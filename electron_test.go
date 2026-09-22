//go:build integration

package asar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestElectronPackedArchive(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	mustWrite(t, filepath.Join(src, "README.txt"), "hello asar\n", 0o644)
	mustWrite(t, filepath.Join(src, "dir", "nested.txt"), "nested\n", 0o644)
	mustWrite(t, filepath.Join(src, "dir", "copy.txt"), "same-bytes", 0o644)
	mustWrite(t, filepath.Join(src, "other", "copy.txt"), "same-bytes", 0o644)
	mustWrite(t, filepath.Join(src, "empty.txt"), "", 0o644)
	mustWrite(t, filepath.Join(src, "bin", "tool.sh"), "#!/bin/sh\necho ok\n", 0o755)

	haveLink := true

	err := os.Symlink(filepath.Join("..", "bin", "tool.sh"), filepath.Join(src, "dir", "alias"))
	if err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}

		haveLink = false
	}

	archive := filepath.Join(dir, "app.asar")
	packElectron(t, src, archive)

	reader := openArchive(t, archive)
	defer reader.Close()

	assertPackedIndex(t, reader, haveLink)

	got := filepath.Join(dir, "got")
	extractReader(t, archive, reader, got)

	want := filepath.Join(dir, "want")
	electronExtract(t, archive, want)
	assertSameTree(t, want, got)
}

func assertPackedIndex(t *testing.T, reader *Reader, haveLink bool) {
	t.Helper()

	assertSharedOffset(t, reader)
	assertEmptyFile(t, fileByName(t, reader, "empty.txt"))
	assertExecutable(t, fileByName(t, reader, "bin/tool.sh"))
	assertPackageLink(t, reader, haveLink)
}

func assertSharedOffset(t *testing.T, reader *Reader) {
	t.Helper()

	left := fileByName(t, reader, "dir/copy.txt")
	right := fileByName(t, reader, "other/copy.txt")

	if left.Offset != right.Offset || !left.Packed() || !right.Packed() {
		t.Fatalf("shared offsets: dir=%+v other=%+v", left, right)
	}
}

func assertEmptyFile(t *testing.T, file *File) {
	t.Helper()

	if !file.Packed() || file.Size != 0 || file.Integrity == nil || file.Integrity.Hash != emptySHA256 {
		t.Fatalf("empty.txt = %+v", file)
	}
}

func assertExecutable(t *testing.T, file *File) {
	t.Helper()

	if runtime.GOOS != "windows" && !file.Executable {
		t.Fatalf("%s executable = %v", file.Name, file.Executable)
	}
}

func assertPackageLink(t *testing.T, reader *Reader, haveLink bool) {
	t.Helper()

	if !haveLink {
		return
	}

	link := fileByName(t, reader, "dir/alias")
	if !link.IsLink() || filepath.ToSlash(link.Link) != "bin/tool.sh" {
		t.Fatalf("alias = %+v", link)
	}
}

func TestElectronUnpackedArchive(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	mustWrite(t, filepath.Join(src, "app.js"), "console.log(1)\n", 0o644)
	mustWrite(t, filepath.Join(src, "native", "addon.node"), "not-really-native", 0o644)

	archive := filepath.Join(dir, "mixed.asar")
	packElectron(t, src, archive, "--unpack", "*.node")

	reader := openArchive(t, archive)
	defer reader.Close()

	assertUnpackedIndex(t, archive, reader)

	got := filepath.Join(dir, "got")
	extractReader(t, archive, reader, got)

	want := filepath.Join(dir, "want")
	electronExtract(t, archive, want)
	assertSameTree(t, want, got)
}

func assertUnpackedIndex(t *testing.T, archive string, reader *Reader) {
	t.Helper()

	packed := fileByName(t, reader, "app.js")

	body, err := io.ReadAll(mustOpen(t, packed))
	if err != nil {
		t.Fatal(err)
	}

	if string(body) != "console.log(1)\n" || packed.Integrity == nil || packed.Integrity.Algorithm != "SHA256" {
		t.Fatalf("app.js = %q integrity=%+v", body, packed.Integrity)
	}

	native := fileByName(t, reader, "native/addon.node")
	if !native.Unpacked || native.Packed() || native.Size != int64(len("not-really-native")) {
		t.Fatalf("addon.node = %+v", native)
	}

	_, err = native.Open()
	if err == nil {
		t.Fatal("Open(unpacked) succeeded")
	}

	assertUnpackedSibling(t, archive, native)
}

func assertUnpackedSibling(t *testing.T, archive string, native *File) {
	t.Helper()

	siblingBody, err := os.ReadFile(filepath.Join(archive+".unpacked", "native", "addon.node"))
	if err != nil {
		t.Fatal(err)
	}

	if string(siblingBody) != "not-really-native" {
		t.Fatalf("unpacked sibling = %q", siblingBody)
	}

	if native.Integrity == nil || native.Integrity.Hash != sha256Hex(siblingBody) {
		t.Fatalf("unpacked integrity = %+v", native.Integrity)
	}
}

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func electronASAR(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}

	bin := filepath.Join(filepath.Dir(filename), "integration", "node_modules", ".bin", "asar")
	if runtime.GOOS == "windows" {
		bin += ".cmd"
	}

	_, err := os.Stat(bin)
	if err != nil {
		t.Fatalf("electron asar CLI missing at %s; run npm ci --prefix integration: %v", bin, err)
	}

	return bin
}

func packElectron(t *testing.T, src, archive string, extra ...string) {
	t.Helper()

	args := append([]string{"pack"}, extra...)
	args = append(args, src, archive)
	runASAR(t, args...)
}

func electronExtract(t *testing.T, archive, dest string) {
	t.Helper()

	runASAR(t, "extract", archive, dest)
}

func runASAR(t *testing.T, args ...string) {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), electronASAR(t), args...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("asar %v: %v\n%s", args, err, out)
	}
}

func extractReader(t *testing.T, archive string, reader *Reader, dest string) {
	t.Helper()

	err := os.MkdirAll(dest, 0o755)
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range reader.Files {
		extractEntry(t, archive, dest, file)
	}
}

func extractEntry(t *testing.T, archive, dest string, file *File) {
	t.Helper()

	out := filepath.Join(dest, filepath.FromSlash(file.Name))

	switch {
	case file.IsDir():
		mkdir(t, out)
	case file.IsLink():
		extractLink(t, dest, out, file.Link)
	case file.Unpacked:
		copyFile(t, filepath.Join(archive+".unpacked", filepath.FromSlash(file.Name)), out, 0o644)
	default:
		extractPacked(t, out, file)
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()

	err := os.MkdirAll(path, 0o755)
	if err != nil {
		t.Fatal(err)
	}
}

func extractLink(t *testing.T, dest, out, link string) {
	t.Helper()

	mkdir(t, filepath.Dir(out))

	target := filepath.Join(dest, filepath.FromSlash(link))

	rel, err := filepath.Rel(filepath.Dir(out), target)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Symlink(rel, out)
	if err != nil {
		t.Fatal(err)
	}
}

func extractPacked(t *testing.T, out string, file *File) {
	t.Helper()

	src, err := file.Open()
	if err != nil {
		t.Fatal(err)
	}

	body, err := io.ReadAll(src)
	if err != nil {
		t.Fatal(err)
	}

	mode := os.FileMode(0o644)
	if file.Executable {
		mode = 0o755
	}

	mustWrite(t, out, string(body), mode)
}

func assertSameTree(t *testing.T, want, got string) {
	t.Helper()

	assertTreeSide(t, want, got)
	assertTreeSide(t, got, want)
}

func assertTreeSide(t *testing.T, left, right string) {
	t.Helper()

	err := filepath.WalkDir(left, func(path string, _ os.DirEntry, walkErr error) error {
		if walkErr != nil {
			t.Error(walkErr)
			return nil
		}

		compareTreePath(t, left, right, path)

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func compareTreePath(t *testing.T, left, right, path string) {
	t.Helper()

	rel, err := filepath.Rel(left, path)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}

	other := filepath.Join(right, rel)

	otherInfo, err := os.Lstat(other)
	if err != nil {
		t.Errorf("missing %s: %v", rel, err)
		return
	}

	if windowsLinkFile(info, otherInfo) {
		compareFile(t, path, other, rel, info, otherInfo)
		return
	}

	if info.Mode()&os.ModeSymlink != otherInfo.Mode()&os.ModeSymlink {
		t.Errorf("%s symlink mismatch", rel)
		return
	}

	if info.Mode()&os.ModeSymlink != 0 {
		compareLink(t, path, other, rel)
		return
	}

	if info.IsDir() {
		return
	}

	compareFile(t, path, other, rel, info, otherInfo)
}

// windowsLinkFile reports Electron's Windows extract behavior: extractAll follows
// links and writes the target bytes as a regular file.
func windowsLinkFile(left, right os.FileInfo) bool {
	if runtime.GOOS != "windows" {
		return false
	}

	leftLink := left.Mode()&os.ModeSymlink != 0
	rightLink := right.Mode()&os.ModeSymlink != 0

	return leftLink != rightLink
}

func compareLink(t *testing.T, left, right, rel string) {
	t.Helper()

	leftLink, err := os.Readlink(left)
	if err != nil {
		t.Fatal(err)
	}

	rightLink, err := os.Readlink(right)
	if err != nil {
		t.Fatal(err)
	}

	if leftLink != rightLink {
		t.Errorf("%s link %q != %q", rel, leftLink, rightLink)
	}
}

func compareFile(t *testing.T, left, right, rel string, info, otherInfo os.FileInfo) {
	t.Helper()

	leftBody, err := os.ReadFile(left)
	if err != nil {
		t.Fatal(err)
	}

	rightBody, err := os.ReadFile(right)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(leftBody, rightBody) {
		t.Errorf("%s content mismatch", rel)
	}

	if runtime.GOOS != "windows" && info.Mode()&0o111 != otherInfo.Mode()&0o111 {
		t.Errorf("%s executable bit mismatch: %v vs %v", rel, info.Mode(), otherInfo.Mode())
	}
}

func openArchive(t *testing.T, path string) *Reader {
	t.Helper()

	reader, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	return reader
}

func mustWrite(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()

	err := os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(path, []byte(body), mode)
	if err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, src, dest string, mode os.FileMode) {
	t.Helper()

	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}

	mustWrite(t, dest, string(body), mode)
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)

	return hex.EncodeToString(sum[:])
}
