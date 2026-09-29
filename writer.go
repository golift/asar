package asar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const (
	integrityBlockSize = 4 << 20
	maxEntrySize       = int64(1<<32 - 1) // Electron rejects a packed file above uint32.
	archiveFileMode    = 0o644
	executableMode     = 0o755
	executablePerm     = 0o111
	archiveDirMode     = 0o750
)

// Entry is one file, directory, or symlink written into a new archive.
// Name is a slash-separated path with no leading slash. A non-empty Link makes
// the entry a symlink and Data is ignored. Dir writes a directory node.
// Unpacked entries are omitted from the archive body.
type Entry struct {
	Name       string
	Data       []byte
	Link       string
	Dir        bool
	Executable bool
	Unpacked   bool
}

// Options controls Pack. The zero value packs every regular file.
type Options struct {
	// Unpack reports whether a slash-separated path should be copied to
	// dest+".unpacked" instead of the archive body. Children of an unpacked
	// directory are unpacked too.
	Unpack func(name string) bool
}

// WriteArchive writes an ASAR image of entries to w.
// Identical packed contents are stored once. Unpacked entries are only recorded
// in the header; the caller supplies any sibling files.
func WriteArchive(writer io.Writer, entries []Entry) error {
	if writer == nil {
		return fmt.Errorf("%w: nil writer", ErrInvalidHeader)
	}

	archive := newBuilder(Options{})

	for _, entry := range entries {
		err := archive.addEntry(entry)
		if err != nil {
			return err
		}
	}

	return archive.writeTo(writer)
}

// Pack writes the directory src to dest as an ASAR archive.
// Symlinks become package-relative links and must stay inside src.
// Unpacked files are copied to dest+".unpacked".
// dest must not be inside src. A symlink to a directory is packed as that
// directory. A previous archive is replaced only after the new archive and
// sibling tree have both been installed.
func Pack(dest, src string, opts Options) error {
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("pack asar: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrInvalidHeader, src)
	}

	// WalkDir does not descend through a symlink used as its root.
	root, err := resolveDir(src)
	if err != nil {
		return err
	}

	err = rejectOutputInsideSource(dest, root)
	if err != nil {
		return err
	}

	builder := newBuilder(opts)

	err = builder.addTree(root)
	if err != nil {
		return err
	}

	return builder.publish(dest)
}

type bodySource struct {
	path string
	data []byte
}

type entryNode struct {
	dir        bool
	unpacked   bool
	link       string
	size       int64
	offset     string
	executable bool
	integrity  *Integrity
	children   map[string]*entryNode
}

type builder struct {
	unpack       func(string) bool
	root         *entryNode
	dirs         map[string]*entryNode
	seen         map[string]struct{}
	hashes       map[string]string
	unpackedDirs map[string]struct{}
	body         []bodySource
	siblings     []siblingFile
	links        []unpackedLink
	offset       int64
}

type unpackedLink struct {
	name   string
	target string
}

type siblingFile struct {
	name   string
	mode   os.FileMode
	source bodySource
}

func newBuilder(opts Options) *builder {
	return &builder{
		unpack:       opts.Unpack,
		root:         &entryNode{dir: true, children: map[string]*entryNode{}},
		dirs:         map[string]*entryNode{},
		seen:         map[string]struct{}{},
		hashes:       map[string]string{},
		unpackedDirs: map[string]struct{}{},
	}
}

func (b *builder) addEntry(entry Entry) error {
	switch {
	case entry.Link != "":
		link, err := cleanLink(entry.Link)
		if err != nil {
			return err
		}

		return b.addLink(entry.Name, link, "", entry.Unpacked)
	case entry.Dir:
		return b.addDir(entry.Name, entry.Unpacked)
	default:
		return b.addContent(entry.Name, bodySource{data: entry.Data}, entryMode(entry.Executable), entry.Unpacked)
	}
}

func (b *builder) addTree(root string) error {
	err := filepath.WalkDir(root, func(diskPath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if diskPath == root {
			return nil
		}

		name, err := slashRel(root, diskPath)
		if err != nil {
			return err
		}

		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("pack asar: %w", err)
		}

		switch {
		case info.Mode()&os.ModeSymlink != 0:
			return b.addDiskLink(root, diskPath, name)
		case info.IsDir():
			return b.addDir(name, b.wantUnpack(name))
		case info.Mode().IsRegular():
			return b.addContent(name, bodySource{path: diskPath}, info.Mode().Perm(), b.wantUnpack(name))
		default:
			return fmt.Errorf("%w: %s is not a regular file", ErrInvalidHeader, name)
		}
	})
	if err != nil {
		return fmt.Errorf("pack asar: %w", err)
	}

	return nil
}

func (b *builder) addDiskLink(root, diskPath, name string) error {
	raw, err := os.Readlink(diskPath)
	if err != nil {
		return fmt.Errorf("pack asar: %w", err)
	}

	rel, err := linkInside(root, diskPath, raw)
	if err != nil {
		return err
	}

	return b.addLink(name, rel, raw, b.wantUnpack(name))
}

func (b *builder) addDir(name string, unpacked bool) error {
	name, err := cleanEntryPath(name)
	if err != nil {
		return err
	}

	if existing, ok := b.dirs[name]; ok {
		if unpacked {
			existing.unpacked = true
			b.unpackedDirs[name] = struct{}{}
		}

		return nil
	}

	if _, dup := b.seen[name]; dup {
		return fmt.Errorf("%w: duplicate entry %q", ErrInvalidHeader, name)
	}

	parent := path.Dir(name)
	if parent == "." {
		parent = ""
	}

	err = b.ensureDir(parent)
	if err != nil {
		return err
	}

	node := &entryNode{dir: true, unpacked: unpacked, children: map[string]*entryNode{}}

	err = b.attach(parent, path.Base(name), node)
	if err != nil {
		return err
	}

	b.dirs[name] = node
	b.seen[name] = struct{}{}

	if unpacked {
		b.unpackedDirs[name] = struct{}{}
	}

	return nil
}

func (b *builder) addLink(name, rel, raw string, unpacked bool) error {
	name, node, err := b.newLeaf(name)
	if err != nil {
		return err
	}

	node.link = rel
	node.unpacked = unpacked

	if unpacked && raw != "" {
		b.links = append(b.links, unpackedLink{name: name, target: raw})
	}

	return nil
}

func (b *builder) addContent(name string, source bodySource, mode os.FileMode, unpacked bool) error {
	sum, size, err := source.integrity()
	if err != nil {
		return err
	}

	if !unpacked && size > maxEntrySize {
		return fmt.Errorf("%w: %s is %d bytes", ErrFileTooLarge, name, size)
	}

	name, node, err := b.newLeaf(name)
	if err != nil {
		return err
	}

	node.size = size
	node.executable = mode&executablePerm != 0
	node.integrity = sum
	node.unpacked = unpacked

	if unpacked {
		b.siblings = append(b.siblings, siblingFile{name: name, mode: mode.Perm(), source: source})
		return nil
	}

	if offset, ok := b.hashes[sum.Hash]; ok {
		node.offset = offset
		return nil
	}

	node.offset = strconv.FormatInt(b.offset, 10)
	b.hashes[sum.Hash] = node.offset
	b.offset += size
	b.body = append(b.body, source)

	return nil
}

func (b *builder) newLeaf(name string) (string, *entryNode, error) {
	name, err := cleanEntryPath(name)
	if err != nil {
		return "", nil, err
	}

	if _, dup := b.seen[name]; dup {
		return "", nil, fmt.Errorf("%w: duplicate entry %q", ErrInvalidHeader, name)
	}

	parent := path.Dir(name)
	if parent == "." {
		parent = ""
	}

	err = b.ensureDir(parent)
	if err != nil {
		return "", nil, err
	}

	node := &entryNode{}

	err = b.attach(parent, path.Base(name), node)
	if err != nil {
		return "", nil, err
	}

	b.seen[name] = struct{}{}

	return name, node, nil
}

func (b *builder) ensureDir(name string) error {
	if name == "" {
		return nil
	}

	if _, ok := b.dirs[name]; ok {
		return nil
	}

	return b.addDir(name, b.wantUnpack(name))
}

func (b *builder) attach(parent, base string, node *entryNode) error {
	err := validateEntryName(base)
	if err != nil {
		return err
	}

	dir := b.root
	if parent != "" {
		dir = b.dirs[parent]
	}

	if _, exists := dir.children[base]; exists {
		return fmt.Errorf("%w: duplicate entry %q", ErrInvalidHeader, base)
	}

	dir.children[base] = node

	return nil
}

func (b *builder) wantUnpack(name string) bool {
	if b.unpack != nil && b.unpack(name) {
		return true
	}

	parent := path.Dir(name)
	for parent != "." && parent != "/" {
		if _, ok := b.unpackedDirs[parent]; ok {
			return true
		}

		parent = path.Dir(parent)
	}

	return false
}

func (b *builder) publish(dest string) error {
	dir := filepath.Dir(dest)
	if dir == "" {
		dir = "."
	}

	err := os.MkdirAll(dir, archiveDirMode)
	if err != nil {
		return fmt.Errorf("pack asar: %w", err)
	}

	archiveName, err := b.stageArchive(dir)
	if err != nil {
		return err
	}

	unpackedName, err := b.stageUnpacked(dir)
	if err != nil {
		_ = os.Remove(archiveName)
		return err
	}

	return commitOutputs(dest, archiveName, unpackedName)
}

func (b *builder) stageArchive(dir string) (string, error) {
	out, err := os.CreateTemp(dir, ".asar-*")
	if err != nil {
		return "", fmt.Errorf("pack asar: %w", err)
	}

	name := out.Name()
	writeErr := b.writeTo(out)
	closeErr := out.Close()

	if writeErr != nil {
		_ = os.Remove(name)
		return "", writeErr
	}

	if closeErr != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("pack asar: %w", closeErr)
	}

	err = os.Chmod(name, archiveFileMode)
	if err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("pack asar: %w", err)
	}

	return name, nil
}

func (b *builder) stageUnpacked(dir string) (string, error) {
	if len(b.siblings) == 0 && len(b.links) == 0 {
		return "", nil
	}

	name, err := os.MkdirTemp(dir, ".asar-unpacked-*")
	if err != nil {
		return "", fmt.Errorf("pack asar: %w", err)
	}

	err = os.Chmod(name, archiveDirMode)
	if err != nil {
		_ = os.RemoveAll(name)
		return "", fmt.Errorf("pack asar: %w", err)
	}

	err = b.writeSiblings(name)
	if err != nil {
		_ = os.RemoveAll(name)
		return "", err
	}

	return name, nil
}

func (b *builder) writeTo(out io.Writer) error {
	raw, err := json.Marshal(b.root.object())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidHeader, err)
	}

	header, err := encodeStringPickle(string(raw))
	if err != nil {
		return err
	}

	size, err := encodeSizePickle(len(header))
	if err != nil {
		return err
	}

	err = writeFull(out, size)
	if err != nil {
		return err
	}

	err = writeFull(out, header)
	if err != nil {
		return err
	}

	for _, source := range b.body {
		err = source.copyTo(out)
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *builder) writeSiblings(root string) error {
	if len(b.siblings) == 0 && len(b.links) == 0 {
		return nil
	}

	for _, sibling := range b.siblings {
		err := sibling.write(root)
		if err != nil {
			return err
		}
	}

	for _, link := range b.links {
		dest := filepath.Join(root, filepath.FromSlash(link.name))

		err := os.MkdirAll(filepath.Dir(dest), archiveDirMode)
		if err != nil {
			return fmt.Errorf("pack asar: %w", err)
		}

		err = os.Symlink(link.target, dest)
		if err != nil {
			return fmt.Errorf("pack asar: %w", err)
		}
	}

	return nil
}

func (n *entryNode) object() any {
	if n.dir {
		files := make(map[string]any, len(n.children))
		for name, child := range n.children {
			files[name] = child.object()
		}

		obj := map[string]any{"files": files}
		if n.unpacked {
			obj["unpacked"] = true
		}

		return obj
	}

	if n.link != "" {
		obj := map[string]any{"link": n.link}
		if n.unpacked {
			obj["unpacked"] = true
		}

		return obj
	}

	obj := map[string]any{
		"size":      n.size,
		"integrity": n.integrity,
	}
	if n.unpacked {
		obj["unpacked"] = true
	} else {
		obj["offset"] = n.offset
	}

	if n.executable {
		obj["executable"] = true
	}

	return obj
}

func (s bodySource) integrity() (*Integrity, int64, error) {
	if s.path == "" {
		return integrityReader(bytes.NewReader(s.data))
	}

	file, err := os.Open(s.path)
	if err != nil {
		return nil, 0, fmt.Errorf("pack asar: %w", err)
	}
	defer file.Close()

	return integrityReader(file)
}

func (s bodySource) copyTo(out io.Writer) error {
	if s.path == "" {
		return writeFull(out, s.data)
	}

	file, err := os.Open(s.path)
	if err != nil {
		return fmt.Errorf("pack asar: %w", err)
	}
	defer file.Close()

	_, err = io.Copy(out, file)
	if err != nil {
		return fmt.Errorf("pack asar: %w", err)
	}

	return nil
}

func (s siblingFile) write(root string) error {
	dest := filepath.Join(root, filepath.FromSlash(s.name))
	if s.source.path != "" {
		file, err := os.Open(s.source.path)
		if err != nil {
			return fmt.Errorf("pack asar: %w", err)
		}
		defer file.Close()

		return writeNew(dest, file, s.mode)
	}

	return writeNew(dest, bytes.NewReader(s.source.data), s.mode)
}

func writeNew(dest string, reader io.Reader, mode os.FileMode) error {
	err := os.MkdirAll(filepath.Dir(dest), archiveDirMode)
	if err != nil {
		return fmt.Errorf("pack asar: %w", err)
	}

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("pack asar: %w", err)
	}

	_, err = io.Copy(out, reader)
	if err == nil {
		err = out.Chmod(mode)
	}

	closeErr := out.Close()

	if err != nil {
		return fmt.Errorf("pack asar: %w", err)
	}

	if closeErr != nil {
		return fmt.Errorf("pack asar: %w", closeErr)
	}

	return nil
}

func integrityReader(input io.Reader) (*Integrity, int64, error) {
	whole := sha256.New()
	blocks := make([]string, 0, 1)
	buf := make([]byte, integrityBlockSize)

	var size int64

	var filled int

	for {
		n, err := input.Read(buf[filled:])
		filled += n
		size += int64(n)

		if filled == integrityBlockSize {
			blocks = append(blocks, sumBlock(whole, buf[:filled]))
			filled = 0
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, 0, fmt.Errorf("hash asar file: %w", err)
		}
	}

	if filled > 0 || len(blocks) == 0 {
		blocks = append(blocks, sumBlock(whole, buf[:filled]))
	}

	return &Integrity{
		Algorithm: "SHA256",
		Hash:      hex.EncodeToString(whole.Sum(nil)),
		BlockSize: integrityBlockSize,
		Blocks:    blocks,
	}, size, nil
}

func sumBlock(whole io.Writer, chunk []byte) string {
	_, _ = whole.Write(chunk)
	sum := sha256.Sum256(chunk)

	return hex.EncodeToString(sum[:])
}

func slashRel(root, diskPath string) (string, error) {
	rel, err := filepath.Rel(root, diskPath)
	if err != nil {
		return "", fmt.Errorf("pack asar: %w", err)
	}

	return filepath.ToSlash(rel), nil
}

func linkInside(root, linkPath, raw string) (string, error) {
	target := raw
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(linkPath), target)
	}

	rootAbs, err := resolveDir(root)
	if err != nil {
		return "", err
	}

	// Resolve the target the same way as root. On macOS /var is a symlink to
	// /private/var, so Abs alone makes an in-tree target look outside.
	targetAbs, err := resolveOutput(target)
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil || rel == "." || outsideRel(rel) {
		return "", fmt.Errorf("%w: %s", ErrLinkOutside, raw)
	}

	return filepath.ToSlash(rel), nil
}

func cleanEntryPath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%w: invalid entry name %q", ErrInvalidHeader, name)
	}

	name = path.Clean(name)
	if name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("%w: invalid entry name %q", ErrInvalidHeader, name)
	}

	for part := range strings.SplitSeq(name, "/") {
		err := validateEntryName(part)
		if err != nil {
			return "", err
		}
	}

	return name, nil
}

func cleanLink(link string) (string, error) {
	link = path.Clean(filepath.ToSlash(link))
	if link == "." || link == ".." || strings.HasPrefix(link, "../") || strings.HasPrefix(link, "/") {
		return "", fmt.Errorf("%w: %s", ErrLinkOutside, link)
	}

	return link, nil
}

func entryMode(executable bool) os.FileMode {
	if executable {
		return executableMode
	}

	return archiveFileMode
}

func writeFull(out io.Writer, data []byte) error {
	n, err := out.Write(data)
	if err != nil {
		return fmt.Errorf("write asar: %w", err)
	}

	if n != len(data) {
		return io.ErrShortWrite
	}

	return nil
}

func rejectOutputInsideSource(dest, src string) error {
	root, err := resolveDir(src)
	if err != nil {
		return err
	}

	for _, candidate := range []string{dest, dest + ".unpacked"} {
		resolved, err := resolveOutput(candidate)
		if err != nil {
			return err
		}

		inside, err := insideDir(root, resolved)
		if err != nil {
			return err
		}

		if inside {
			return fmt.Errorf("%w: %s", ErrOutputInside, candidate)
		}
	}

	return nil
}

func resolveDir(name string) (string, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return "", fmt.Errorf("pack asar: %w", err)
	}

	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("pack asar: %w", err)
	}

	return resolved, nil
}

func resolveOutput(name string) (string, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return "", fmt.Errorf("pack asar: %w", err)
	}

	parent, err := resolveExistingPrefix(filepath.Dir(abs))
	if err != nil {
		return "", err
	}

	return filepath.Join(parent, filepath.Base(abs)), nil
}

func resolveExistingPrefix(name string) (string, error) {
	current := name

	var pending []string

	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for _, p := range slices.Backward(pending) {
				resolved = filepath.Join(resolved, p)
			}

			return resolved, nil
		}

		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("pack asar: %w", err)
		}

		parent := filepath.Dir(current)
		if parent == current {
			return name, nil
		}

		pending = append(pending, filepath.Base(current))
		current = parent
	}
}

func insideDir(root, candidate string) (bool, error) {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false, fmt.Errorf("pack asar: %w", err)
	}

	return rel == "." || !outsideRel(rel), nil
}

func outsideRel(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func commitOutputs(dest, archiveTmp, unpackedTmp string) error {
	unpackedDest := dest + ".unpacked"

	archiveBak, err := moveAside(dest)
	if err != nil {
		discardStaged(archiveTmp, unpackedTmp)
		return err
	}

	unpackedBak, err := moveAside(unpackedDest)
	if err != nil {
		restoreAside(archiveBak, dest)
		discardStaged(archiveTmp, unpackedTmp)

		return err
	}

	err = renamePath(archiveTmp, dest)
	if err != nil {
		restorePair(dest, unpackedDest, archiveBak, unpackedBak)
		discardStaged(archiveTmp, unpackedTmp)

		return err
	}

	err = placeUnpacked(unpackedTmp, unpackedDest)
	if err != nil {
		displaceNewArchive(dest)
		restorePair(dest, unpackedDest, archiveBak, unpackedBak)
		discardStaged("", unpackedTmp)

		return err
	}

	return removeBackups(archiveBak, unpackedBak)
}

func moveAside(name string) (string, error) {
	_, err := os.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}

	if err != nil {
		return "", fmt.Errorf("pack asar: %w", err)
	}

	dir := filepath.Dir(name)

	file, err := os.CreateTemp(dir, ".asar-previous-*")
	if err != nil {
		return "", fmt.Errorf("pack asar: %w", err)
	}

	backup := file.Name()
	closeErr := file.Close()
	removeErr := os.Remove(backup)

	if closeErr != nil || removeErr != nil {
		return "", fmt.Errorf("pack asar: %w", errors.Join(closeErr, removeErr))
	}

	err = os.Rename(name, backup)
	if err != nil {
		return "", fmt.Errorf("pack asar: %w", err)
	}

	return backup, nil
}

func placeUnpacked(tmp, dest string) error {
	if tmp == "" {
		return nil
	}

	return renamePath(tmp, dest)
}

func restorePair(dest, unpackedDest, archiveBak, unpackedBak string) {
	restoreAside(archiveBak, dest)
	restoreAside(unpackedBak, unpackedDest)
}

func restoreAside(backup, dest string) {
	if backup == "" {
		return
	}

	_ = os.Rename(backup, dest)
}

func displaceNewArchive(dest string) {
	_ = os.Remove(dest)
}

func discardStaged(archiveTmp, unpackedTmp string) {
	if archiveTmp != "" {
		_ = os.Remove(archiveTmp)
	}

	_ = removeTree(unpackedTmp)
}

func removeBackups(archiveBak, unpackedBak string) error {
	err := removeTree(unpackedBak)
	if archiveBak == "" {
		return err
	}

	fileErr := os.Remove(archiveBak)
	if fileErr != nil {
		fileErr = fmt.Errorf("pack asar: %w", fileErr)
	}

	if err != nil {
		return err
	}

	return fileErr
}

func renamePath(tmp, dest string) error {
	err := os.Rename(tmp, dest)
	if err != nil {
		return fmt.Errorf("pack asar: %w", err)
	}

	return nil
}

func removeTree(name string) error {
	if name == "" {
		return nil
	}

	err := os.RemoveAll(name)
	if err != nil {
		return fmt.Errorf("pack asar: %w", err)
	}

	return nil
}
