package asar

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"maps"
	"testing"
)

func pickleUInt32(value uint32) []byte {
	buf := make([]byte, sizePickleBytes)
	binary.LittleEndian.PutUint32(buf[0:4], pickleHeaderSize)
	binary.LittleEndian.PutUint32(buf[4:8], value)

	return buf
}

func pickleString(text string) []byte {
	str := []byte(text)
	aligned := alignPickle(len(str))
	payload := pickleHeaderSize + aligned
	buf := make([]byte, pickleHeaderSize+payload)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(payload))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(len(str)))
	copy(buf[pickleHeaderSize*2:], str)

	return buf
}

func makeArchive(t *testing.T, header map[string]any, blobs ...[]byte) []byte {
	t.Helper()

	raw, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}

	headerPickle := pickleString(string(raw))
	out := bytes.NewBuffer(pickleUInt32(uint32(len(headerPickle))))
	_, _ = out.Write(headerPickle)

	for _, blob := range blobs {
		_, _ = out.Write(blob)
	}

	return out.Bytes()
}

func filesHeader(entries map[string]any) map[string]any {
	return map[string]any{"files": entries}
}

func packed(offset string, size int, extra map[string]any) map[string]any {
	entry := map[string]any{"offset": offset, "size": size}
	maps.Copy(entry, extra)

	return entry
}

func mustReader(t *testing.T, archive []byte) *Reader {
	t.Helper()

	reader, err := NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}

	return reader
}

func fileByName(t *testing.T, reader *Reader, name string) *File {
	t.Helper()

	for _, file := range reader.Files {
		if file.Name == name {
			return file
		}
	}

	t.Fatalf("missing entry %q", name)

	return nil
}
