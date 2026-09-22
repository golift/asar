package asar

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteArchiveRoundTrip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	err := WriteArchive(&buf, []Entry{
		{Name: "dir/a.txt", Data: []byte("same")},
		{Name: "b.txt", Data: []byte("same")},
		{Name: "dir/nested.txt", Data: []byte("yes")},
		{Name: "bin/tool", Data: []byte("run"), Executable: true},
		{Name: "empty.txt", Data: []byte{}},
		{Name: "link", Link: "dir/a.txt"},
		{Name: "native.node", Data: []byte("unpacked-bytes"), Unpacked: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	reader := mustReader(t, buf.Bytes())
	assertSharedFiles(t, reader, "dir/a.txt", "b.txt", "same")
	assertPackedText(t, reader, "dir/nested.txt", "yes")
	assertExecutableTool(t, fileByName(t, reader, "bin/tool"))
	assertEmptyPacked(t, fileByName(t, reader, "empty.txt"))
	assertLinkTarget(t, fileByName(t, reader, "link"), "dir/a.txt")
	assertUnpackedOmitted(t, fileByName(t, reader, "native.node"), buf.Bytes())
	assertParentDirs(t, reader)
}

func assertSharedFiles(t *testing.T, reader *Reader, leftName, rightName, text string) {
	t.Helper()

	left := fileByName(t, reader, leftName)
	right := fileByName(t, reader, rightName)

	if left.Offset != right.Offset || string(readPacked(t, left)) != text || string(readPacked(t, right)) != text {
		t.Fatalf("shared files: %+v %+v", left, right)
	}
}

func assertPackedText(t *testing.T, reader *Reader, name, text string) {
	t.Helper()

	if string(readPacked(t, fileByName(t, reader, name))) != text {
		t.Fatalf("%s mismatch", name)
	}
}

func assertExecutableTool(t *testing.T, tool *File) {
	t.Helper()

	if !tool.Executable || tool.Integrity == nil || tool.Integrity.Algorithm != "SHA256" {
		t.Fatalf("tool = %+v", tool)
	}
}

func assertEmptyPacked(t *testing.T, empty *File) {
	t.Helper()

	if !empty.Packed() || empty.Size != 0 || empty.Integrity == nil || empty.Integrity.Hash != hashOf(t, nil) {
		t.Fatalf("empty = %+v", empty)
	}
}

func assertLinkTarget(t *testing.T, link *File, target string) {
	t.Helper()

	if !link.IsLink() || link.Link != target {
		t.Fatalf("link = %+v", link)
	}
}

func assertUnpackedOmitted(t *testing.T, native *File, archive []byte) {
	t.Helper()

	if !native.Unpacked || native.Packed() || bytes.Contains(archive, []byte("unpacked-bytes")) {
		t.Fatalf("unpacked entry was stored in the archive body: %+v", native)
	}
}

func assertParentDirs(t *testing.T, reader *Reader) {
	t.Helper()

	if !fileByName(t, reader, "dir").IsDir() || !fileByName(t, reader, "bin").IsDir() {
		t.Fatal("missing parent directories")
	}
}

func TestWriteArchiveRejectsEscape(t *testing.T) {
	t.Parallel()

	err := WriteArchive(io.Discard, []Entry{{Name: "../outside", Data: []byte("x")}})
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("name: %v", err)
	}

	err = WriteArchive(io.Discard, []Entry{{Name: "link", Link: "../outside"}})
	if !errors.Is(err, ErrLinkOutside) {
		t.Fatalf("link: %v", err)
	}
}

func TestPackDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	writeDisk(t, filepath.Join(src, "dir", "a.txt"), "same", 0o644)
	writeDisk(t, filepath.Join(src, "b.txt"), "same", 0o644)
	writeDisk(t, filepath.Join(src, "bin", "tool.sh"), "#!/bin/sh\n", 0o755)
	writeDisk(t, filepath.Join(src, "native", "addon.node"), "native", 0o644)

	haveLink := true

	err := os.Symlink(filepath.Join("..", "bin", "tool.sh"), filepath.Join(src, "dir", "alias"))
	if err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}

		haveLink = false
	}

	archive := filepath.Join(dir, "app.asar")

	err = Pack(archive, src, Options{Unpack: func(name string) bool {
		return name == "native/addon.node"
	}})
	if err != nil {
		t.Fatal(err)
	}

	reader, err := Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	assertSharedFiles(t, reader, "dir/a.txt", "b.txt", "same")
	assertPackedExecutable(t, fileByName(t, reader, "bin/tool.sh"))
	assertPackedSibling(t, archive, fileByName(t, reader, "native/addon.node"))
	assertOptionalLink(t, reader, haveLink)
}

func assertPackedExecutable(t *testing.T, tool *File) {
	t.Helper()

	if runtime.GOOS != "windows" && !tool.Executable {
		t.Fatalf("tool executable = %v", tool.Executable)
	}
}

func assertPackedSibling(t *testing.T, archive string, native *File) {
	t.Helper()

	if !native.Unpacked || native.Integrity == nil {
		t.Fatalf("addon = %+v", native)
	}

	body, err := os.ReadFile(filepath.Join(archive+".unpacked", "native", "addon.node"))
	if err != nil {
		t.Fatal(err)
	}

	if string(body) != "native" || native.Integrity.Hash != hashOf(t, body) {
		t.Fatalf("sibling = %q integrity=%+v", body, native.Integrity)
	}
}

func assertOptionalLink(t *testing.T, reader *Reader, haveLink bool) {
	t.Helper()

	if !haveLink {
		return
	}

	assertLinkTarget(t, fileByName(t, reader, "dir/alias"), "bin/tool.sh")
}

func TestPackRejectsLinkOutside(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	writeDisk(t, filepath.Join(src, "keep.txt"), "x", 0o644)

	err := os.Symlink(filepath.Join("..", "outside"), filepath.Join(src, "bad"))
	if err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symlinks are not available")
		}

		t.Fatal(err)
	}

	err = Pack(filepath.Join(dir, "app.asar"), src, Options{})
	if !errors.Is(err, ErrLinkOutside) {
		t.Fatalf("got %v", err)
	}
}

func readPacked(t *testing.T, file *File) []byte {
	t.Helper()

	body, err := io.ReadAll(mustOpen(t, file))
	if err != nil {
		t.Fatal(err)
	}

	return body
}

func writeDisk(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()

	err := os.MkdirAll(filepath.Dir(path), 0o750)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(path, []byte(body), mode)
	if err != nil {
		t.Fatal(err)
	}
}

func hashOf(t *testing.T, body []byte) string {
	t.Helper()

	sum, _, err := integrityReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	return sum.Hash
}
