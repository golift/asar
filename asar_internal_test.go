package asar

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestNestedDirsAndPackedFiles(t *testing.T) {
	t.Parallel()

	archive := makeArchive(t, filesHeader(map[string]any{
		"hello.txt": packed("0", 5, nil),
		"dir": filesHeader(map[string]any{
			"nested.txt": packed("5", 3, nil),
		}),
	}), []byte("hello"), []byte("yes"))

	reader := mustReader(t, archive)

	if len(reader.Files) != 3 {
		t.Fatalf("got %d files, want 3", len(reader.Files))
	}

	dir := reader.Files[0]
	if dir.Name != "dir" || !dir.IsDir() {
		t.Fatalf("first entry should be dir, got %+v", dir)
	}

	nested := fileByName(t, reader, "dir/nested.txt")
	if nested.IsDir() || nested.Unpacked {
		t.Fatalf("nested.txt should be packed, got %+v", nested)
	}

	got, err := io.ReadAll(mustOpen(t, nested))
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != "yes" {
		t.Fatalf("nested.txt = %q", got)
	}

	hello := fileByName(t, reader, "hello.txt")

	got, err = io.ReadAll(mustOpen(t, hello))
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != "hello" {
		t.Fatalf("hello.txt = %q", got)
	}
}

func TestSharedOffsets(t *testing.T) {
	t.Parallel()

	archive := makeArchive(t, filesHeader(map[string]any{
		"a.txt": packed("0", 4, nil),
		"b.txt": packed("0", 4, nil),
	}), []byte("same"))

	reader := mustReader(t, archive)
	aFile := fileByName(t, reader, "a.txt")
	bFile := fileByName(t, reader, "b.txt")

	if aFile.Offset != bFile.Offset {
		t.Fatalf("offsets differ: %d vs %d", aFile.Offset, bFile.Offset)
	}

	aData, _ := io.ReadAll(mustOpen(t, aFile))
	bData, _ := io.ReadAll(mustOpen(t, bFile))

	if string(aData) != "same" || string(bData) != "same" {
		t.Fatalf("a=%q b=%q", aData, bData)
	}
}

func TestSymlinkAndExecutable(t *testing.T) {
	t.Parallel()

	archive := makeArchive(t, filesHeader(map[string]any{
		"bin":  packed("0", 3, map[string]any{"executable": true}),
		"link": map[string]any{"link": "bin"},
	}), []byte("run"))

	reader := mustReader(t, archive)
	bin := fileByName(t, reader, "bin")
	link := fileByName(t, reader, "link")

	if !bin.Executable {
		t.Fatal("bin should be executable")
	}

	if !link.IsLink() || link.Link != "bin" {
		t.Fatalf("link = %+v", link)
	}

	_, err := link.Open()
	if !errors.Is(err, ErrNotPacked) {
		t.Fatalf("Open(link) = %v", err)
	}
}

func TestUnpackedEntry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry map[string]any
		blobs [][]byte
	}{
		{
			name:  "size only",
			entry: map[string]any{"unpacked": true, "size": 10},
		},
		{
			name:  "offset and unpacked",
			entry: packed("0", 4, map[string]any{"unpacked": true}),
			blobs: [][]byte{[]byte("nope")},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			archive := makeArchive(t, filesHeader(map[string]any{"native.node": test.entry}), test.blobs...)
			reader := mustReader(t, archive)
			native := fileByName(t, reader, "native.node")

			if !native.Unpacked || native.Packed() {
				t.Fatalf("unpacked entry = %+v packed=%v", native, native.Packed())
			}

			_, err := native.Open()
			if !errors.Is(err, ErrNotPacked) {
				t.Fatalf("Open(unpacked) = %v", err)
			}
		})
	}
}

func TestIntegrityParsed(t *testing.T) {
	t.Parallel()

	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	archive := makeArchive(t, filesHeader(map[string]any{
		"a.txt": packed("0", 1, map[string]any{
			"integrity": map[string]any{
				"algorithm": "SHA256",
				"hash":      hash,
				"blockSize": 4 * 1024 * 1024,
				"blocks":    []string{hash},
			},
		}),
	}), []byte("x"))

	reader := mustReader(t, archive)
	file := fileByName(t, reader, "a.txt")

	if file.Integrity == nil || file.Integrity.Hash != hash || file.Integrity.Algorithm != "SHA256" {
		t.Fatalf("integrity = %+v", file.Integrity)
	}
}

func TestHeaderPicklePastEOF(t *testing.T) {
	t.Parallel()

	archive := pickleUInt32(1000)

	_, err := NewReader(bytes.NewReader(archive), int64(len(archive)))
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("got %v, want ErrTruncated", err)
	}
}

func TestHeaderPastEOF(t *testing.T) {
	t.Parallel()

	archive := makeArchive(t, filesHeader(map[string]any{
		"big.bin": packed("0", 99999, nil),
	}))

	_, err := NewReader(bytes.NewReader(archive), int64(len(archive)))
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("got %v, want ErrTruncated", err)
	}
}

func TestInvalidEntryNames(t *testing.T) {
	t.Parallel()

	names := []string{"..", ".", "a/b", `a\b`, ""}

	for _, name := range names {
		archive := makeArchive(t, filesHeader(map[string]any{
			name: packed("0", 0, nil),
		}))

		_, err := NewReader(bytes.NewReader(archive), int64(len(archive)))
		if !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("name %q: got %v, want ErrInvalidHeader", name, err)
		}
	}
}

func TestEmptyPackedFile(t *testing.T) {
	t.Parallel()

	archive := makeArchive(t, filesHeader(map[string]any{
		"empty.txt": packed("0", 0, nil),
	}))

	reader := mustReader(t, archive)
	empty := fileByName(t, reader, "empty.txt")

	if !empty.Packed() || empty.IsDir() {
		t.Fatalf("empty packed file = %+v packed=%v dir=%v", empty, empty.Packed(), empty.IsDir())
	}

	got, err := io.ReadAll(mustOpen(t, empty))
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 0 {
		t.Fatalf("got %q", got)
	}
}

func TestOpenPath(t *testing.T) {
	t.Parallel()

	archive := makeArchive(t, filesHeader(map[string]any{
		"hello.txt": packed("0", 5, nil),
	}), []byte("hello"))

	path := filepath.Join(t.TempDir(), "app.asar")

	err := os.WriteFile(path, archive, 0o600)
	if err != nil {
		t.Fatal(err)
	}

	reader, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	file := fileByName(t, reader, "hello.txt")

	got, err := io.ReadAll(mustOpen(t, file))
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestPickleRoundTrip(t *testing.T) {
	t.Parallel()

	for _, text := range []string{"", "x", "abc", "abcd", "abcde", `{"files":{}}`} {
		pickled := pickleString(text)

		got, err := readPickleString(pickled[pickleHeaderSize:])
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}

		if got != text {
			t.Fatalf("got %q want %q", got, text)
		}
	}
}

func TestRootMustHaveFiles(t *testing.T) {
	t.Parallel()

	raw, _ := json.Marshal(map[string]any{"offset": "0", "size": 1})
	headerPickle := pickleString(string(raw))
	archive := append(pickleUInt32(uint32(len(headerPickle))), headerPickle...)

	_, err := NewReader(bytes.NewReader(archive), int64(len(archive)))
	if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("got %v", err)
	}
}

func mustOpen(t *testing.T, file *File) *io.SectionReader {
	t.Helper()

	reader, err := file.Open()
	if err != nil {
		t.Fatal(err)
	}

	return reader
}
