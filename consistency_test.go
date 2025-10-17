package hdnfs

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
)

// TestMetadataConsistency tests that metadata remains consistent across operations
func TestMetadataConsistencyBasic(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Initial state
	meta1 := VerifyMetadataIntegrity(t, file)
	if CountUsedSlots(meta1) != 0 {
		t.Error("Initial metadata should have no files")
	}

	// Add file
	content := []byte("test content")
	sourcePath := CreateTempSourceFile(t, content)
	Add(file, sourcePath, "test.txt", 0)

	// Verify consistency after add
	meta2 := VerifyMetadataIntegrity(t, file)
	if CountUsedSlots(meta2) != 1 {
		t.Errorf("Expected 1 file, got %d", CountUsedSlots(meta2))
	}
	if meta2.Files[0].Name != "test.txt" {
		t.Errorf("File name mismatch: %s", meta2.Files[0].Name)
	}

	// Delete file
	Del(file, 0)

	// Verify consistency after delete
	meta3 := VerifyMetadataIntegrity(t, file)
	if CountUsedSlots(meta3) != 0 {
		t.Errorf("Expected 0 files after delete, got %d", CountUsedSlots(meta3))
	}
	if meta3.Files[0].Name != "" {
		t.Error("File should be deleted from metadata")
	}
}

func TestMetadataConsistencyMultipleOperations(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Perform sequence of operations
	operations := []struct {
		op      string
		index   int
		name    string
		content []byte
	}{
		{"add", 0, "file0.txt", []byte("content 0")},
		{"add", 1, "file1.txt", []byte("content 1")},
		{"add", 2, "file2.txt", []byte("content 2")},
		{"del", 1, "", nil},
		{"add", 3, "file3.txt", []byte("content 3")},
		{"del", 0, "", nil},
		{"add", 0, "file0_new.txt", []byte("new content 0")},
	}

	for i, op := range operations {
		switch op.op {
		case "add":
			sourcePath := CreateTempSourceFile(t, op.content)
			Add(file, sourcePath, op.name, op.index)
		case "del":
			Del(file, op.index)
		}

		// Verify metadata integrity after each operation
		meta := VerifyMetadataIntegrity(t, file)
		if meta == nil {
			t.Fatalf("Metadata corrupted after operation %d: %+v", i, op)
		}
	}

	// Final state verification
	meta := ReadMeta(file)

	// File 0 should be "file0_new.txt"
	if meta.Files[0].Name != "file0_new.txt" {
		t.Errorf("File 0 final state incorrect: %s", meta.Files[0].Name)
	}

	// File 1 should be deleted
	if meta.Files[1].Name != "" {
		t.Errorf("File 1 should be deleted: %s", meta.Files[1].Name)
	}

	// File 2 should still be "file2.txt"
	if meta.Files[2].Name != "file2.txt" {
		t.Errorf("File 2 should be file2.txt: %s", meta.Files[2].Name)
	}

	// File 3 should be "file3.txt"
	if meta.Files[3].Name != "file3.txt" {
		t.Errorf("File 3 should be file3.txt: %s", meta.Files[3].Name)
	}
}

func TestMetadataConsistencyAfterPowerFailure(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Add files
	for i := 0; i < 10; i++ {
		content := []byte(fmt.Sprintf("content %d", i))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("file%d.txt", i), i)
	}

	// Simulate "power failure" by closing and reopening
	filePath := file.Name()
	file.Close()

	file, err := os.OpenFile(filePath, os.O_RDWR, 0777)
	if err != nil {
		t.Fatalf("Failed to reopen file: %v", err)
	}
	defer file.Close()

	// Verify metadata is still intact
	meta := VerifyMetadataIntegrity(t, file)
	if CountUsedSlots(meta) != 10 {
		t.Errorf("Expected 10 files after reopen, got %d", CountUsedSlots(meta))
	}

	// Verify file contents are still correct
	for i := 0; i < 10; i++ {
		expectedContent := []byte(fmt.Sprintf("content %d", i))
		VerifyFileConsistency(t, file, i, expectedContent)
	}
}

func TestMetadataConsistencyWithMaxFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping max files consistency test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Fill all slots
	FillAllSlots(t, file)

	// Verify metadata
	meta := VerifyMetadataIntegrity(t, file)
	if CountUsedSlots(meta) != TOTAL_FILES {
		t.Errorf("Expected %d files, got %d", TOTAL_FILES, CountUsedSlots(meta))
	}

	// Verify all slots have valid entries
	for i := 0; i < TOTAL_FILES; i++ {
		if meta.Files[i].Name == "" {
			t.Errorf("Slot %d should not be empty", i)
		}
		if meta.Files[i].Size == 0 {
			t.Errorf("Slot %d should have non-zero size", i)
		}
	}
}

func TestFileConsistencyAfterEncryption(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	tests := []struct {
		name    string
		content []byte
	}{
		{"text file", []byte("This is a text file")},
		{"binary file", GenerateRandomBytes(1000)},
		{"empty file", []byte{}},
		{"large file", GenerateRandomBytes(40000)},
		{"unicode file", []byte("Hello 世界 🌍 Привет")},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sourcePath := CreateTempSourceFile(t, tt.content)
			Add(file, sourcePath, fmt.Sprintf("%s.dat", tt.name), i)

			// Verify file consistency
			VerifyFileConsistency(t, file, i, tt.content)
		})
	}
}

func TestFileConsistencyAcrossSync(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer srcFile.Close()

	dstFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer dstFile.Close()

	InitMeta(srcFile, "file")

	// Add files with checksums
	numFiles := 20
	checksums := make(map[int][32]byte)

	for i := 0; i < numFiles; i++ {
		content := GenerateRandomBytes(10000 + (i * 100))
		checksum := sha256.Sum256(content)
		checksums[i] = checksum

		sourcePath := CreateTempSourceFile(t, content)
		Add(srcFile, sourcePath, fmt.Sprintf("file%d.bin", i), i)
	}

	// Sync
	Sync(srcFile, dstFile)

	// Verify file consistency on destination
	for i := 0; i < numFiles; i++ {
		// Read file from destination
		seekPos := META_FILE_SIZE + (i * MAX_FILE_SIZE)
		dstFile.Seek(int64(seekPos), 0)

		meta := ReadMeta(dstFile)
		buff := make([]byte, meta.Files[i].Size)
		dstFile.Read(buff)

		decrypted := Decrypt(buff, GetEncKey())
		checksum := sha256.Sum256(decrypted)

		if checksum != checksums[i] {
			t.Errorf("File %d checksum mismatch after sync", i)
		}
	}
}

func TestFileConsistencyWithOverwrite(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	index := 5

	// Add initial file
	content1 := []byte("Initial content")
	checksum1 := sha256.Sum256(content1)
	sourcePath1 := CreateTempSourceFile(t, content1)
	Add(file, sourcePath1, "file.txt", index)

	// Verify initial
	VerifyFileConsistency(t, file, index, content1)

	// Overwrite with different content
	content2 := []byte("Overwritten content - much different")
	checksum2 := sha256.Sum256(content2)
	sourcePath2 := CreateTempSourceFile(t, content2)
	Add(file, sourcePath2, "file_new.txt", index)

	// Verify overwritten
	VerifyFileConsistency(t, file, index, content2)

	// Ensure old content is gone
	seekPos := META_FILE_SIZE + (index * MAX_FILE_SIZE)
	file.Seek(int64(seekPos), 0)

	meta := ReadMeta(file)
	buff := make([]byte, meta.Files[index].Size)
	file.Read(buff)

	decrypted := Decrypt(buff, GetEncKey())
	checksum := sha256.Sum256(decrypted)

	if checksum == checksum1 {
		t.Error("Old content still present after overwrite")
	}

	if checksum != checksum2 {
		t.Error("New content not correct after overwrite")
	}
}

func TestFileConsistencyAfterDelete(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Add file
	content := []byte("Content to be deleted")
	sourcePath := CreateTempSourceFile(t, content)
	Add(file, sourcePath, "todelete.txt", 3)

	// Delete file
	Del(file, 3)

	// Verify file data is zeroed
	seekPos := META_FILE_SIZE + (3 * MAX_FILE_SIZE)
	file.Seek(int64(seekPos), 0)

	buff := make([]byte, MAX_FILE_SIZE)
	file.Read(buff)

	// Check if all zeros
	for i, b := range buff {
		if b != 0 {
			t.Errorf("Byte at position %d not zeroed after delete: %d", i, b)
			break
		}
	}

	// Verify metadata is cleared
	meta := ReadMeta(file)
	if meta.Files[3].Name != "" {
		t.Error("Metadata not cleared after delete")
	}
}

func TestFileConsistencyWithFragmentation(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Add files at non-contiguous positions
	positions := []int{0, 5, 10, 50, 100, 500, 999}
	contents := make(map[int][]byte)

	for _, pos := range positions {
		content := GenerateRandomBytes(5000 + pos)
		contents[pos] = content
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("file_%d.bin", pos), pos)
	}

	// Verify all files independently
	for _, pos := range positions {
		VerifyFileConsistency(t, file, pos, contents[pos])
	}

	// Verify gaps are empty
	meta := ReadMeta(file)
	for i := 0; i < TOTAL_FILES; i++ {
		isUsed := false
		for _, pos := range positions {
			if i == pos {
				isUsed = true
				break
			}
		}

		if !isUsed && meta.Files[i].Name != "" {
			t.Errorf("Position %d should be empty", i)
		}
	}
}

func TestMetadataConsistencyUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Perform many operations
	for iteration := 0; iteration < 100; iteration++ {
		// Add 10 files
		for i := 0; i < 10; i++ {
			content := GenerateRandomBytes(1000 + (iteration * 10) + i)
			sourcePath := CreateTempSourceFile(t, content)
			index := (iteration*10 + i) % 100
			Add(file, sourcePath, fmt.Sprintf("load_%d_%d.bin", iteration, i), index)
		}

		// Delete 5 files
		for i := 0; i < 5; i++ {
			index := (iteration*10 + i*2) % 100
			Del(file, index)
		}

		// Verify integrity every 10 iterations
		if iteration%10 == 0 {
			meta := VerifyMetadataIntegrity(t, file)
			if meta == nil {
				t.Fatalf("Metadata corrupted at iteration %d", iteration)
			}
		}
	}

	// Final integrity check
	meta := VerifyMetadataIntegrity(t, file)
	t.Logf("Final state: %d files in use", CountUsedSlots(meta))
}

func TestConsistencyAcrossReopen(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	tmpFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	filePath := tmpFile.Name()

	InitMeta(tmpFile, "file")

	// Add files
	fileData := make(map[int][]byte)
	for i := 0; i < 10; i++ {
		content := GenerateRandomBytes(5000 + i*100)
		fileData[i] = content
		sourcePath := CreateTempSourceFile(t, content)
		Add(tmpFile, sourcePath, fmt.Sprintf("reopen_%d.bin", i), i)
	}

	tmpFile.Close()

	// Reopen
	reopenedFile, err := os.OpenFile(filePath, os.O_RDWR, 0777)
	if err != nil {
		t.Fatalf("Failed to reopen: %v", err)
	}
	defer reopenedFile.Close()

	// Verify all files
	for i := 0; i < 10; i++ {
		VerifyFileConsistency(t, reopenedFile, i, fileData[i])
	}

	// Verify metadata
	meta := VerifyMetadataIntegrity(t, reopenedFile)
	if CountUsedSlots(meta) != 10 {
		t.Errorf("Expected 10 files after reopen, got %d", CountUsedSlots(meta))
	}
}

func TestConsistencyWithCorruptedMetadata(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Add files
	content := []byte("test content")
	sourcePath := CreateTempSourceFile(t, content)
	Add(file, sourcePath, "test.txt", 0)

	// Manually corrupt metadata (write random data)
	file.Seek(100, 0) // Write in middle of metadata
	corruptData := GenerateRandomBytes(100)
	file.Write(corruptData)

	// Try to read metadata
	// This should fail or return corrupted data
	// In a production system, we'd want checksums to detect this
	file.Seek(0, 0)
	_ = ReadMeta(file)

	// Metadata might be corrupted - this is expected
	// The test documents that we have no corruption detection
	t.Log("Note: No corruption detection implemented in current version")
}

func TestFileConsistencyBoundaryConditions(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	tests := []struct {
		name  string
		index int
	}{
		{"First slot", 0},
		{"Last slot", TOTAL_FILES - 1},
		{"Middle slot", TOTAL_FILES / 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := GenerateRandomBytes(10000)
			sourcePath := CreateTempSourceFile(t, content)
			Add(file, sourcePath, fmt.Sprintf("boundary_%d.bin", tt.index), tt.index)

			// Verify
			VerifyFileConsistency(t, file, tt.index, content)

			// Verify metadata
			meta := ReadMeta(file)
			if meta.Files[tt.index].Name == "" {
				t.Errorf("File at %s not added", tt.name)
			}
		})
	}
}

func BenchmarkMetadataConsistencyCheck(b *testing.B) {
	SetupTestKey(&testing.T{})

	file := CreateTempTestFile(&testing.T{}, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Add some files
	for i := 0; i < 50; i++ {
		content := GenerateRandomBytes(5000)
		sourcePath := CreateTempSourceFile(&testing.T{}, content)
		Add(file, sourcePath, fmt.Sprintf("bench_%d.bin", i), i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyMetadataIntegrity(&testing.T{}, file)
	}
}

func BenchmarkFileConsistencyCheck(b *testing.B) {
	SetupTestKey(&testing.T{})

	file := CreateTempTestFile(&testing.T{}, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	content := GenerateRandomBytes(10000)
	sourcePath := CreateTempSourceFile(&testing.T{}, content)
	Add(file, sourcePath, "bench.bin", 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyFileConsistency(&testing.T{}, file, 0, content)
	}
}
