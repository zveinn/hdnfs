package hdnfs

import (
	"bytes"
	"fmt"
	"testing"
)

func TestSync(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	// Create source and destination files
	srcFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer srcFile.Close()

	dstFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer dstFile.Close()

	// Initialize source
	InitMeta(srcFile, "file")

	// Add files to source
	testFiles := []struct {
		content []byte
		name    string
		index   int
	}{
		{[]byte("File 1 content"), "file1.txt", 0},
		{[]byte("File 2 content longer"), "file2.txt", 1},
		{[]byte("File 3"), "file3.txt", 5},
		{GenerateRandomBytes(1000), "binary.bin", 10},
	}

	for _, tf := range testFiles {
		sourcePath := CreateTempSourceFile(t, tf.content)
		Add(srcFile, sourcePath, tf.name, tf.index)
	}

	// Sync to destination
	Sync(srcFile, dstFile)

	// Verify destination metadata
	dstMeta := ReadMeta(dstFile)
	srcMeta := ReadMeta(srcFile)

	// Compare metadata
	for i := 0; i < TOTAL_FILES; i++ {
		if srcMeta.Files[i].Name != dstMeta.Files[i].Name {
			t.Errorf("Index %d: name mismatch - src: %s, dst: %s", i, srcMeta.Files[i].Name, dstMeta.Files[i].Name)
		}
		if srcMeta.Files[i].Size != dstMeta.Files[i].Size {
			t.Errorf("Index %d: size mismatch - src: %d, dst: %d", i, srcMeta.Files[i].Size, dstMeta.Files[i].Size)
		}
	}

	// Verify file contents
	for _, tf := range testFiles {
		VerifyFileConsistency(t, dstFile, tf.index, tf.content)
	}
}

func TestSyncEmptyFilesystem(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer srcFile.Close()

	dstFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer dstFile.Close()

	// Initialize source as empty
	InitMeta(srcFile, "file")

	// Sync
	Sync(srcFile, dstFile)

	// Verify destination is also empty
	dstMeta := ReadMeta(dstFile)
	for i := 0; i < TOTAL_FILES; i++ {
		if dstMeta.Files[i].Name != "" {
			t.Errorf("Index %d should be empty after syncing empty filesystem", i)
		}
	}
}

func TestSyncOverwrite(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer srcFile.Close()

	dstFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer dstFile.Close()

	// Initialize both
	InitMeta(srcFile, "file")
	InitMeta(dstFile, "file")

	// Add files to destination first
	oldContent := []byte("old content in destination")
	oldSourcePath := CreateTempSourceFile(t, oldContent)
	Add(dstFile, oldSourcePath, "old_file.txt", 0)

	// Add different files to source
	newContent := []byte("new content from source")
	newSourcePath := CreateTempSourceFile(t, newContent)
	Add(srcFile, newSourcePath, "new_file.txt", 0)

	// Sync should overwrite
	Sync(srcFile, dstFile)

	// Verify destination has new content
	dstMeta := ReadMeta(dstFile)
	if dstMeta.Files[0].Name != "new_file.txt" {
		t.Errorf("Expected new_file.txt, got %s", dstMeta.Files[0].Name)
	}

	VerifyFileConsistency(t, dstFile, 0, newContent)
}

func TestSyncPartialFilesystem(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer srcFile.Close()

	dstFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer dstFile.Close()

	InitMeta(srcFile, "file")

	// Add files at various indices with gaps
	indices := []int{0, 5, 10, 50, 100, 500, 999}
	for _, idx := range indices {
		content := []byte(fmt.Sprintf("Content at index %d", idx))
		sourcePath := CreateTempSourceFile(t, content)
		Add(srcFile, sourcePath, fmt.Sprintf("file_%d.txt", idx), idx)
	}

	// Sync
	Sync(srcFile, dstFile)

	// Verify all files are present at correct indices
	for _, idx := range indices {
		expectedContent := []byte(fmt.Sprintf("Content at index %d", idx))
		VerifyFileConsistency(t, dstFile, idx, expectedContent)
	}

	// Verify empty slots are still empty
	dstMeta := ReadMeta(dstFile)
	for i := 0; i < TOTAL_FILES; i++ {
		isUsedIndex := false
		for _, idx := range indices {
			if i == idx {
				isUsedIndex = true
				break
			}
		}

		if !isUsedIndex && dstMeta.Files[i].Name != "" {
			t.Errorf("Index %d should be empty but has name: %s", i, dstMeta.Files[i].Name)
		}
	}
}

func TestSyncLargeFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large file sync test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer srcFile.Close()

	dstFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer dstFile.Close()

	InitMeta(srcFile, "file")

	// Add files with maximum allowed size
	maxSize := 40000 // Leave room for encryption overhead
	for i := 0; i < 10; i++ {
		content := GenerateRandomBytes(maxSize)
		sourcePath := CreateTempSourceFile(t, content)
		Add(srcFile, sourcePath, fmt.Sprintf("large_%d.bin", i), i)
	}

	// Sync
	Sync(srcFile, dstFile)

	// Verify all large files synced correctly
	srcMeta := ReadMeta(srcFile)
	dstMeta := ReadMeta(dstFile)

	for i := 0; i < 10; i++ {
		if srcMeta.Files[i].Size != dstMeta.Files[i].Size {
			t.Errorf("File %d size mismatch: src=%d, dst=%d", i, srcMeta.Files[i].Size, dstMeta.Files[i].Size)
		}
	}
}

func TestSyncMultipleTimes(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer srcFile.Close()

	dstFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer dstFile.Close()

	InitMeta(srcFile, "file")

	// Sync 1: Add some files and sync
	content1 := []byte("Sync 1 content")
	sourcePath1 := CreateTempSourceFile(t, content1)
	Add(srcFile, sourcePath1, "file1.txt", 0)
	Sync(srcFile, dstFile)

	// Sync 2: Add more files and sync
	content2 := []byte("Sync 2 content")
	sourcePath2 := CreateTempSourceFile(t, content2)
	Add(srcFile, sourcePath2, "file2.txt", 1)
	Sync(srcFile, dstFile)

	// Sync 3: Delete a file and sync
	Del(srcFile, 0)
	Sync(srcFile, dstFile)

	// Verify final state
	srcMeta := ReadMeta(srcFile)
	dstMeta := ReadMeta(dstFile)

	// File 0 should be deleted
	if dstMeta.Files[0].Name != "" {
		t.Error("File 0 should be deleted after sync")
	}

	// File 1 should still exist
	if dstMeta.Files[1].Name != "file2.txt" {
		t.Errorf("File 1 should be file2.txt, got %s", dstMeta.Files[1].Name)
	}

	// Verify they match
	for i := 0; i < TOTAL_FILES; i++ {
		if srcMeta.Files[i].Name != dstMeta.Files[i].Name {
			t.Errorf("After multiple syncs, index %d name mismatch", i)
		}
	}
}

func TestReadBlock(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Add a file
	content := []byte("Test content for ReadBlock")
	sourcePath := CreateTempSourceFile(t, content)
	Add(file, sourcePath, "test.txt", 5)

	// Read the block
	block := ReadBlock(file, 5)

	// Verify block size
	if len(block) != MAX_FILE_SIZE {
		t.Errorf("Block size should be %d, got %d", MAX_FILE_SIZE, len(block))
	}

	// Verify block contains encrypted data
	// First part should be non-zero (encrypted data)
	allZeros := true
	for i := 0; i < 100; i++ {
		if block[i] != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		t.Error("Block should contain encrypted data")
	}
}

func TestWriteBlock(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Create a block
	block := make([]byte, MAX_FILE_SIZE)
	testData := []byte("Test data in block")
	copy(block, testData)

	// Write block
	WriteBlock(file, block, "test_block.txt", 7)

	// Read it back
	file.Seek(int64(META_FILE_SIZE+(7*MAX_FILE_SIZE)), 0)
	readBlock := make([]byte, MAX_FILE_SIZE)
	file.Read(readBlock)

	// Verify
	if !bytes.Equal(block, readBlock) {
		t.Error("Written block doesn't match read block")
	}
}

func TestSyncWithBinaryData(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer srcFile.Close()

	dstFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer dstFile.Close()

	InitMeta(srcFile, "file")

	// Create binary data with all byte values
	binaryData := make([]byte, 256)
	for i := 0; i < 256; i++ {
		binaryData[i] = byte(i)
	}

	sourcePath := CreateTempSourceFile(t, binaryData)
	Add(srcFile, sourcePath, "binary.bin", 0)

	// Sync
	Sync(srcFile, dstFile)

	// Verify binary data is intact
	VerifyFileConsistency(t, dstFile, 0, binaryData)
}

func TestSyncFullFilesystem(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping full filesystem sync test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer srcFile.Close()

	dstFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer dstFile.Close()

	InitMeta(srcFile, "file")

	// Fill source filesystem
	FillAllSlots(t, srcFile)

	// Sync
	Sync(srcFile, dstFile)

	// Verify all files synced
	srcMeta := ReadMeta(srcFile)
	dstMeta := ReadMeta(dstFile)

	for i := 0; i < TOTAL_FILES; i++ {
		if srcMeta.Files[i].Name != dstMeta.Files[i].Name {
			t.Errorf("Index %d name mismatch after full sync", i)
		}
		if srcMeta.Files[i].Size != dstMeta.Files[i].Size {
			t.Errorf("Index %d size mismatch after full sync", i)
		}
	}

	// Verify metadata count
	srcCount := CountUsedSlots(srcMeta)
	dstCount := CountUsedSlots(dstMeta)

	if srcCount != dstCount {
		t.Errorf("Used slot count mismatch: src=%d, dst=%d", srcCount, dstCount)
	}

	if srcCount != TOTAL_FILES {
		t.Errorf("Expected %d files, got %d", TOTAL_FILES, srcCount)
	}
}

func TestSyncPreservesEmptySlots(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer srcFile.Close()

	dstFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer dstFile.Close()

	InitMeta(srcFile, "file")

	// Add files with gaps
	content := []byte("test content")
	sourcePath := CreateTempSourceFile(t, content)
	Add(srcFile, sourcePath, "file1.txt", 0)
	Add(srcFile, sourcePath, "file2.txt", 10)
	Add(srcFile, sourcePath, "file3.txt", 20)

	// Sync
	Sync(srcFile, dstFile)

	// Verify gaps are preserved (slots 1-9, 11-19 should be empty)
	dstMeta := ReadMeta(dstFile)

	for i := 1; i < 10; i++ {
		if dstMeta.Files[i].Name != "" {
			t.Errorf("Slot %d should be empty", i)
		}
	}

	for i := 11; i < 20; i++ {
		if dstMeta.Files[i].Name != "" {
			t.Errorf("Slot %d should be empty", i)
		}
	}
}

func BenchmarkSync(b *testing.B) {
	SetupTestKey(&testing.T{})

	srcFile := CreateTempTestFile(&testing.T{}, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer srcFile.Close()

	InitMeta(srcFile, "file")

	// Add 10 files
	for i := 0; i < 10; i++ {
		content := GenerateRandomBytes(1000)
		sourcePath := CreateTempSourceFile(&testing.T{}, content)
		Add(srcFile, sourcePath, fmt.Sprintf("file%d.txt", i), i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dstFile := CreateTempTestFile(&testing.T{}, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
		Sync(srcFile, dstFile)
		dstFile.Close()
	}
}

func BenchmarkReadBlock(b *testing.B) {
	SetupTestKey(&testing.T{})

	file := CreateTempTestFile(&testing.T{}, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	content := GenerateRandomBytes(1000)
	sourcePath := CreateTempSourceFile(&testing.T{}, content)
	Add(file, sourcePath, "test.txt", 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ReadBlock(file, 0)
	}
}

func BenchmarkWriteBlock(b *testing.B) {
	SetupTestKey(&testing.T{})

	file := CreateTempTestFile(&testing.T{}, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	block := make([]byte, MAX_FILE_SIZE)
	copy(block, GenerateRandomBytes(1000))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		WriteBlock(file, block, "test.txt", 0)
	}
}
