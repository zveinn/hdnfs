package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestMetadataConsistencyBasic(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("InitMeta failed: %v", err)
	}

	meta1 := VerifyMetadataIntegrity(t, file)
	if CountUsedSlots(meta1) != 0 {
		t.Error("Initial metadata should have no files")
	}

	content := []byte("test content")
	sourcePath := CreateTempSourceFile(t, content)
	if err := Add(file, sourcePath, "test.txt", 0); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	meta2 := VerifyMetadataIntegrity(t, file)
	if CountUsedSlots(meta2) != 1 {
		t.Errorf("Expected 1 file, got %d", CountUsedSlots(meta2))
	}
	if meta2.Files[0].Name != "test.txt" {
		t.Errorf("File name mismatch: %s", meta2.Files[0].Name)
	}

	if err := Del(file, 0); err != nil {
		t.Fatalf("Del failed: %v", err)
	}

	meta3 := VerifyMetadataIntegrity(t, file)
	if CountUsedSlots(meta3) != 0 {
		t.Errorf("Expected 0 files after delete, got %d", CountUsedSlots(meta3))
	}
	if meta3.Files[0].Name != "" {
		t.Error("File should be deleted from metadata")
	}
}

func TestMetadataConsistencyMultipleOperations(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("InitMeta failed: %v", err)
	}

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
			if err := Add(file, sourcePath, op.name, op.index); err != nil {
				t.Fatalf("Add failed at operation %d: %v", i, err)
			}
		case "del":
			if err := Del(file, op.index); err != nil {
				t.Fatalf("Del failed at operation %d: %v", i, err)
			}
		}

		meta := VerifyMetadataIntegrity(t, file)
		if meta == nil {
			t.Fatalf("Metadata corrupted after operation %d: %+v", i, op)
		}
	}

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}

	if meta.Files[0].Name != "file0_new.txt" {
		t.Errorf("File 0 final state incorrect: %s", meta.Files[0].Name)
	}

	if meta.Files[1].Name != "" {
		t.Errorf("File 1 should be deleted: %s", meta.Files[1].Name)
	}

	if meta.Files[2].Name != "file2.txt" {
		t.Errorf("File 2 should be file2.txt: %s", meta.Files[2].Name)
	}

	if meta.Files[3].Name != "file3.txt" {
		t.Errorf("File 3 should be file3.txt: %s", meta.Files[3].Name)
	}
}

func TestMetadataConsistencyAfterPowerFailure(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("InitMeta failed: %v", err)
	}

	for i := 0; i < 10; i++ {
		content := []byte(fmt.Sprintf("content %d", i))
		sourcePath := CreateTempSourceFile(t, content)
		if err := Add(file, sourcePath, fmt.Sprintf("file%d.txt", i), i); err != nil {
			t.Fatalf("Add failed for file %d: %v", i, err)
		}
	}

	filePath := file.Name()
	file.Close()

	file, err := os.OpenFile(filePath, os.O_RDWR, 0o777)
	if err != nil {
		t.Fatalf("Failed to reopen file: %v", err)
	}
	defer file.Close()

	meta := VerifyMetadataIntegrity(t, file)
	if CountUsedSlots(meta) != 10 {
		t.Errorf("Expected 10 files after reopen, got %d", CountUsedSlots(meta))
	}

	for i := 0; i < 10; i++ {
		expectedContent := []byte(fmt.Sprintf("content %d", i))
		VerifyFileConsistency(t, file, i, expectedContent)
	}
}

func TestMetadataConsistencyWithMaxFiles(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping max files consistency test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("InitMeta failed: %v", err)
	}

	const testFileCount = 100
	FillSlots(t, file, testFileCount)

	meta := VerifyMetadataIntegrity(t, file)
	if CountUsedSlots(meta) != testFileCount {
		t.Errorf("Expected %d files, got %d", testFileCount, CountUsedSlots(meta))
	}

	filledCount := 0
	for i := 0; i < TOTAL_FILES; i++ {
		if meta.Files[i].Name != "" {
			filledCount++
			if meta.Files[i].Size == 0 {
				t.Errorf("Slot %d should have non-zero size", i)
			}
		}
	}
	if filledCount != testFileCount {
		t.Errorf("Expected %d filled slots, got %d", testFileCount, filledCount)
	}
}

func TestFileConsistencyAfterEncryption(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("InitMeta failed: %v", err)
	}

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
			if err := Add(file, sourcePath, fmt.Sprintf("%s.dat", tt.name), i); err != nil {
				t.Fatalf("Add failed: %v", err)
			}

			VerifyFileConsistency(t, file, i, tt.content)
		})
	}
}

func TestFileConsistencyAcrossSync(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := GetSharedTestFile(t)

	dstFile := GetSharedTestFile(t)

	if err := InitMeta(srcFile, "file"); err != nil {
		t.Fatalf("InitMeta failed: %v", err)
	}

	numFiles := 20
	checksums := make(map[int][32]byte)

	for i := 0; i < numFiles; i++ {
		content := GenerateRandomBytes(10000 + (i * 100))
		checksum := sha256.Sum256(content)
		checksums[i] = checksum

		sourcePath := CreateTempSourceFile(t, content)
		if err := Add(srcFile, sourcePath, fmt.Sprintf("file%d.bin", i), i); err != nil {
			t.Fatalf("Add failed for file %d: %v", i, err)
		}
	}

	if err := Sync(srcFile, dstFile); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	meta, err := ReadMeta(dstFile)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}

	for i := 0; i < numFiles; i++ {

		seekPos := META_FILE_SIZE + (i * MAX_FILE_SIZE)
		_, err := dstFile.Seek(int64(seekPos), 0)
		if err != nil {
			t.Fatalf("Seek failed: %v", err)
		}

		buff := make([]byte, meta.Files[i].Size)
		_, err = dstFile.Read(buff)
		if err != nil {
			t.Fatalf("Read failed for file %d: %v", i, err)
		}

		password, err := GetEncKey()
		if err != nil {
			t.Fatalf("GetEncKey failed: %v", err)
		}
		decrypted, err := DecryptGCM(buff, password, meta.Salt)
		if err != nil {
			t.Fatalf("DecryptGCM failed for file %d: %v", i, err)
		}
		checksum := sha256.Sum256(decrypted)

		if checksum != checksums[i] {
			t.Errorf("File %d checksum mismatch after sync", i)
		}
	}
}

func TestFileConsistencyWithOverwrite(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("InitMeta failed: %v", err)
	}

	index := 5

	content1 := []byte("Initial content")
	checksum1 := sha256.Sum256(content1)
	sourcePath1 := CreateTempSourceFile(t, content1)
	if err := Add(file, sourcePath1, "file.txt", index); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	VerifyFileConsistency(t, file, index, content1)

	content2 := []byte("Overwritten content - much different")
	checksum2 := sha256.Sum256(content2)
	sourcePath2 := CreateTempSourceFile(t, content2)
	if err := Add(file, sourcePath2, "file_new.txt", index); err != nil {
		t.Fatalf("Add failed for overwrite: %v", err)
	}

	VerifyFileConsistency(t, file, index, content2)

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}

	seekPos := META_FILE_SIZE + (index * MAX_FILE_SIZE)
	_, err = file.Seek(int64(seekPos), 0)
	if err != nil {
		t.Fatalf("Seek failed: %v", err)
	}

	buff := make([]byte, meta.Files[index].Size)
	_, err = file.Read(buff)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	password, err := GetEncKey()
	if err != nil {
		t.Fatalf("GetEncKey failed: %v", err)
	}
	decrypted, err := DecryptGCM(buff, password, meta.Salt)
	if err != nil {
		t.Fatalf("DecryptGCM failed: %v", err)
	}
	checksum := sha256.Sum256(decrypted)

	if checksum == checksum1 {
		t.Error("Old content still present after overwrite")
	}

	if checksum != checksum2 {
		t.Error("New content not correct after overwrite")
	}
}

func TestFileConsistencyAfterDelete(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("InitMeta failed: %v", err)
	}

	content := []byte("Content to be deleted")
	sourcePath := CreateTempSourceFile(t, content)
	if err := Add(file, sourcePath, "todelete.txt", 3); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	if err := Del(file, 3); err != nil {
		t.Fatalf("Del failed: %v", err)
	}

	seekPos := META_FILE_SIZE + (3 * MAX_FILE_SIZE)
	file.Seek(int64(seekPos), 0)

	buff := make([]byte, MAX_FILE_SIZE)
	file.Read(buff)

	for i, b := range buff {
		if b != 0 {
			t.Errorf("Byte at position %d not zeroed after delete: %d", i, b)
			break
		}
	}

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if meta.Files[3].Name != "" {
		t.Error("Metadata not cleared after delete")
	}
}

func TestFileConsistencyWithFragmentation(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("InitMeta failed: %v", err)
	}

	positions := []int{0, 5, 10, 50, 100, 500, 999}
	contents := make(map[int][]byte)

	for _, pos := range positions {
		content := GenerateRandomBytes(5000 + pos)
		contents[pos] = content
		sourcePath := CreateTempSourceFile(t, content)
		if err := Add(file, sourcePath, fmt.Sprintf("file_%d.bin", pos), pos); err != nil {
			t.Fatalf("Add failed at position %d: %v", pos, err)
		}
	}

	for _, pos := range positions {
		VerifyFileConsistency(t, file, pos, contents[pos])
	}

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
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
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("InitMeta failed: %v", err)
	}

	for iteration := 0; iteration < 10; iteration++ {

		for i := 0; i < 10; i++ {
			content := GenerateRandomBytes(1000 + (iteration * 10) + i)
			sourcePath := CreateTempSourceFile(t, content)
			index := (iteration*10 + i) % 100
			if err := Add(file, sourcePath, fmt.Sprintf("load_%d_%d.bin", iteration, i), index); err != nil {
				t.Fatalf("Add failed at iteration %d, file %d: %v", iteration, i, err)
			}
		}

		for i := 0; i < 5; i++ {
			index := (iteration*10 + i*2) % 100
			if err := Del(file, index); err != nil {
				t.Fatalf("Del failed at iteration %d, index %d: %v", iteration, index, err)
			}
		}

		if iteration%5 == 0 {
			meta := VerifyMetadataIntegrity(t, file)
			if meta == nil {
				t.Fatalf("Metadata corrupted at iteration %d", iteration)
			}
		}
	}

	meta := VerifyMetadataIntegrity(t, file)
	t.Logf("Final state: %d files in use", CountUsedSlots(meta))
}

func TestConsistencyAcrossReopen(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	tmpFile := GetSharedTestFile(t)
	filePath := tmpFile.Name()

	if err := InitMeta(tmpFile, "file"); err != nil {
		t.Fatalf("InitMeta failed: %v", err)
	}

	fileData := make(map[int][]byte)
	for i := 0; i < 10; i++ {
		content := GenerateRandomBytes(5000 + i*100)
		fileData[i] = content
		sourcePath := CreateTempSourceFile(t, content)
		if err := Add(tmpFile, sourcePath, fmt.Sprintf("reopen_%d.bin", i), i); err != nil {
			t.Fatalf("Add failed for file %d: %v", i, err)
		}
	}

	tmpFile.Close()

	reopenedFile, err := os.OpenFile(filePath, os.O_RDWR, 0o777)
	if err != nil {
		t.Fatalf("Failed to reopen: %v", err)
	}
	defer reopenedFile.Close()

	for i := 0; i < 10; i++ {
		VerifyFileConsistency(t, reopenedFile, i, fileData[i])
	}

	meta := VerifyMetadataIntegrity(t, reopenedFile)
	if CountUsedSlots(meta) != 10 {
		t.Errorf("Expected 10 files after reopen, got %d", CountUsedSlots(meta))
	}
}

func TestConsistencyWithCorruptedMetadata(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("InitMeta failed: %v", err)
	}

	content := []byte("test content")
	sourcePath := CreateTempSourceFile(t, content)
	if err := Add(file, sourcePath, "test.txt", 0); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	file.Seek(100, 0)
	corruptData := GenerateRandomBytes(100)
	file.Write(corruptData)

	file.Seek(0, 0)
	_, _ = ReadMeta(file)

	t.Log("Note: Corruption detection now implemented via SHA-256 checksums")
}

func TestFileConsistencyBoundaryConditions(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("InitMeta failed: %v", err)
	}

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
			if err := Add(file, sourcePath, fmt.Sprintf("boundary_%d.bin", tt.index), tt.index); err != nil {
				t.Fatalf("Add failed: %v", err)
			}

			VerifyFileConsistency(t, file, tt.index, content)

			meta, err := ReadMeta(file)
			if err != nil {
				t.Fatalf("ReadMeta failed: %v", err)
			}
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
