package main

import (
	"testing"
	"time"
)

func TestOverwriteSmallRange(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping overwrite test in short mode")
	}

	file := NewMockFile(10 * ERASE_CHUNK_SIZE)

	for i := 0; i < len(file.data); i++ {
		file.data[i] = 0xFF
	}

	Overwrite(file, 0, ERASE_CHUNK_SIZE)

	for i := 0; i < ERASE_CHUNK_SIZE; i++ {
		if file.data[i] != 0 {
			t.Errorf("Byte at position %d not zeroed: %d", i, file.data[i])
			break
		}
	}

	for i := ERASE_CHUNK_SIZE; i < len(file.data); i++ {
		if file.data[i] != 0xFF {
			t.Errorf("Byte at position %d should be 0xFF: %d", i, file.data[i])
			break
		}
	}
}

func TestOverwriteFromOffset(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping overwrite test in short mode")
	}

	file := NewMockFile(5 * ERASE_CHUNK_SIZE)

	for i := 0; i < len(file.data); i++ {
		file.data[i] = 0xAA
	}

	startOffset := int64(2 * ERASE_CHUNK_SIZE)
	endOffset := uint64(4 * ERASE_CHUNK_SIZE)

	Overwrite(file, startOffset, endOffset)

	for i := 0; i < int(startOffset); i++ {
		if file.data[i] != 0xAA {
			t.Errorf("Byte at position %d should be unchanged: %d", i, file.data[i])
			break
		}
	}

	for i := int(startOffset); i < int(endOffset); i++ {
		if file.data[i] != 0 {
			t.Errorf("Byte at position %d should be zeroed: %d", i, file.data[i])
			break
		}
	}

	for i := int(endOffset); i < len(file.data); i++ {
		if file.data[i] != 0xAA {
			t.Errorf("Byte at position %d should be unchanged: %d", i, file.data[i])
			break
		}
	}
}

func TestOverwritePartialChunk(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping overwrite test in short mode")
	}

	size := ERASE_CHUNK_SIZE + 500000
	file := NewMockFile(size)

	for i := 0; i < len(file.data); i++ {
		file.data[i] = 0xBB
	}

	Overwrite(file, 0, uint64(size))

	for i := 0; i < size; i++ {
		if file.data[i] != 0 {
			t.Errorf("Byte at position %d not zeroed: %d", i, file.data[i])
			break
		}
	}
}

func TestOverwriteZeroLength(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	file := NewMockFile(1000)

	for i := 0; i < len(file.data); i++ {
		file.data[i] = 0xCC
	}

	Overwrite(file, 0, 0)

	for i := 0; i < len(file.data); i++ {
		if file.data[i] != 0xCC {
			t.Errorf("Byte at position %d should be unchanged: %d", i, file.data[i])
			break
		}
	}
}

func TestOverwriteMultipleChunks(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping multi-chunk overwrite test in short mode")
	}

	size := 3 * ERASE_CHUNK_SIZE
	file := NewMockFile(size)

	for i := 0; i < len(file.data); i++ {
		file.data[i] = 0xDD
	}

	Overwrite(file, 0, uint64(size))

	for i := 0; i < size; i++ {
		if file.data[i] != 0 {
			t.Errorf("Byte at position %d not zeroed: %d", i, file.data[i])
			break
		}
	}
}

func TestOverwriteSeekPosition(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	file := NewMockFile(2 * ERASE_CHUNK_SIZE)

	file.Seek(1000, 0)

	startPos := int64(ERASE_CHUNK_SIZE / 2)
	Overwrite(file, startPos, uint64(ERASE_CHUNK_SIZE))

	for i := int(startPos); i < ERASE_CHUNK_SIZE; i++ {
		if file.data[i] != 0 {
			t.Errorf("Byte at position %d should be zeroed: %d", i, file.data[i])
			break
		}
	}
}

func TestOverwriteFilesystemMetadata(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping filesystem metadata overwrite test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	content := []byte("test file content")
	sourcePath := CreateTempSourceFile(t, content)
	Add(file, sourcePath, 0)

	Overwrite(file, 0, uint64(META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE)))

	file.Seek(0, 0)
	buf := make([]byte, META_FILE_SIZE)
	file.Read(buf)

	if buf[4] != 0 {

	}

	file.Seek(int64(META_FILE_SIZE), 0)
	dataBuf := make([]byte, MAX_FILE_SIZE)
	file.Read(dataBuf)

	allZeros := true
	for _, b := range dataBuf {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if !allZeros {
		t.Error("Data region should be completely zeroed after overwrite")
	}
}

func TestOverwriteAndReinitialize(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping overwrite and reinitialize test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	content := []byte("original content")
	sourcePath := CreateTempSourceFile(t, content)
	Add(file, sourcePath, 0)

	Overwrite(file, 0, uint64(META_FILE_SIZE+(10*MAX_FILE_SIZE)))

	InitMeta(file, "file")

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	for i := 0; i < TOTAL_FILES; i++ {
		if meta.Files[i].Name != "" {
			t.Errorf("Slot %d should be empty after overwrite and reinit", i)
		}
	}

	newContent := []byte("new content after overwrite")
	newSourcePath := CreateTempSourceFile(t, newContent)
	Add(file, newSourcePath, 0)

	VerifyFileConsistency(t, file, 0, newContent)
}

func TestOverwriteProgress(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping progress test in short mode")
	}

	size := 3 * ERASE_CHUNK_SIZE
	file := NewMockFile(size)

	for i := 0; i < len(file.data); i++ {
		file.data[i] = byte(i % 256)
	}

	Overwrite(file, 0, uint64(size))

	for i := 0; i < size; i++ {
		if file.data[i] != 0 {
			t.Errorf("Pattern not overwritten at position %d", i)
			break
		}
	}
}

func TestOverwriteBoundaryConditions(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping boundary conditions test in short mode")
	}

	tests := []struct {
		name  string
		size  int
		start int64
		end   uint64
	}{
		{
			name:  "Single byte",
			size:  100,
			start: 0,
			end:   1,
		},
		{
			name:  "Chunk boundary",
			size:  ERASE_CHUNK_SIZE * 2,
			start: 0,
			end:   uint64(ERASE_CHUNK_SIZE),
		},
		{
			name:  "Chunk + 1",
			size:  ERASE_CHUNK_SIZE * 2,
			start: 0,
			end:   uint64(ERASE_CHUNK_SIZE + 1),
		},
		{
			name:  "Chunk - 1",
			size:  ERASE_CHUNK_SIZE * 2,
			start: 0,
			end:   uint64(ERASE_CHUNK_SIZE - 1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := NewMockFile(tt.size)

			for i := 0; i < len(file.data); i++ {
				file.data[i] = 0xFF
			}

			Overwrite(file, tt.start, tt.end)

			for i := int(tt.start); i < int(tt.end) && i < len(file.data); i++ {
				if file.data[i] != 0 {
					t.Errorf("Position %d should be zeroed", i)
					break
				}
			}

			for i := int(tt.end); i < len(file.data); i++ {
				if file.data[i] != 0xFF {
					t.Errorf("Position %d should be unchanged", i)
					break
				}
			}
		})
	}
}

func BenchmarkOverwrite1MB(b *testing.B) {
	size := ERASE_CHUNK_SIZE
	file := NewMockFile(size)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		file.Seek(0, 0)
		Overwrite(file, 0, uint64(size))
	}
}

func BenchmarkOverwrite10MB(b *testing.B) {
	size := 10 * ERASE_CHUNK_SIZE
	file := NewMockFile(size)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		file.Seek(0, 0)
		Overwrite(file, 0, uint64(size))
	}
}
