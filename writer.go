package asar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	integrityBlockSize = 4 << 20
	maxEntrySize       = int64(1<<32 - 1) // Electron rejects a single file above uint32.
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
func Pack(dest, src string, opts Options) (err error) {
	info, err := os.Lstat(src)
	if err != nil {
		return fmt.Errorf("pack asar: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrInvalidHeader, src)
	}

	builder := newBuilder(opts)

	err = builder.addTree(src)
	if err != nil {
		return err
	}

	err = builder.writePacked(dest)
	if err != nil {
		_ = os.Remove(dest)
		_ = os.RemoveAll(dest + ".unpacked")

		return err
	}

	return nil
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
		return b.addContent(entry.Name, bodySource{data: entry.Data}, entry.Executable, entry.Unpacked)
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
			return b.addContent(name, bodySource{path: diskPath}, info.Mode()&0o111 != 0, b.wantUnpack(name))
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

func (b *builder) addContent(name string, source bodySource, executable, unpacked bool) error {
	sum, size, err := source.integrity()
	if err != nil {
		return err
	}

	if size > maxEntrySize {
		return fmt.Errorf("%w: %s is %d bytes", ErrFileTooLarge, name, size)
	}

	name, node, err := b.newLeaf(name)
	if err != nil {
		return err
	}

	node.size = size
	node.executable = executable
	node.integrity = sum
	node.unpacked = unpacked

	if unpacked {
		b.siblings = append(b.siblings, siblingFile{name: name, source: source})
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

func (b *builder) writePacked(dest string) error {
	err := os.MkdirAll(filepath.Dir(dest), archiveDirMode)
	if err != nil {
		return fmt.Errorf("pack asar: %w", err)
	}

	out, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("pack asar: %w", err)
	}

	err = b.writeTo(out)
	closeErr := out.Close()

	if err != nil {
		return err
	}

	if closeErr != nil {
		return fmt.Errorf("pack asar: %w", closeErr)
	}

	return b.writeSiblings(dest + ".unpacked")
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

	_, err = out.Write(size)
	if err != nil {
		return fmt.Errorf("write asar: %w", err)
	}

	_, err = out.Write(header)
	if err != nil {
		return fmt.Errorf("write asar: %w", err)
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
		_, err := out.Write(s.data)
		if err != nil {
			return fmt.Errorf("write asar: %w", err)
		}

		return nil
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

		return writeNew(dest, file)
	}

	return writeNew(dest, bytes.NewReader(s.source.data))
}

func writeNew(dest string, reader io.Reader) error {
	err := os.MkdirAll(filepath.Dir(dest), archiveDirMode)
	if err != nil {
		return fmt.Errorf("pack asar: %w", err)
	}

	out, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("pack asar: %w", err)
	}

	_, err = io.Copy(out, reader)
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
	block := sha256.New()
	blocks := make([]string, 0, 1)
	buf := make([]byte, integrityBlockSize)

	var size int64

	var filled int

	for {
		n, err := input.Read(buf[filled:])
		filled += n
		size += int64(n)

		if filled == integrityBlockSize {
			blocks = append(blocks, sumBlock(whole, block, buf[:filled]))
			block.Reset()

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
		blocks = append(blocks, sumBlock(whole, block, buf[:filled]))
	}

	return &Integrity{
		Algorithm: "SHA256",
		Hash:      hex.EncodeToString(whole.Sum(nil)),
		BlockSize: integrityBlockSize,
		Blocks:    blocks,
	}, size, nil
}

func sumBlock(whole, block io.Writer, chunk []byte) string {
	_, _ = whole.Write(chunk)
	_, _ = block.Write(chunk)
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

	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
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
