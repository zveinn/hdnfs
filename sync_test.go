package main

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestSync(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := GetSharedTestFile(t)

	dstFile := GetSharedTestFile(t)

	InitMeta(srcFile, "file")

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

	Sync(srcFile, dstFile)

	dstMeta, err := ReadMeta(dstFile)

	if err != nil {

		t.Fatalf("ReadMeta failed: %v", err)

	}
	srcMeta, err := ReadMeta(srcFile)

	if err != nil {

		t.Fatalf("ReadMeta failed: %v", err)

	}

	for i := 0; i < TOTAL_FILES; i++ {
		if srcMeta.Files[i].Name != dstMeta.Files[i].Name {
			t.Errorf("Index %d: name mismatch - src: %s, dst: %s", i, srcMeta.Files[i].Name, dstMeta.Files[i].Name)
		}
		if srcMeta.Files[i].Size != dstMeta.Files[i].Size {
			t.Errorf("Index %d: size mismatch - src: %d, dst: %d", i, srcMeta.Files[i].Size, dstMeta.Files[i].Size)
		}
	}

	for _, tf := range testFiles {
		VerifyFileConsistency(t, dstFile, tf.index, tf.content)
	}
}

func TestSyncEmptyFilesystem(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := GetSharedTestFile(t)

	dstFile := GetSharedTestFile(t)

	InitMeta(srcFile, "file")

	Sync(srcFile, dstFile)

	dstMeta, err := ReadMeta(dstFile)

	if err != nil {

		t.Fatalf("ReadMeta failed: %v", err)

	}
	for i := 0; i < TOTAL_FILES; i++ {
		if dstMeta.Files[i].Name != "" {
			t.Errorf("Index %d should be empty after syncing empty filesystem", i)
		}
	}
}

func TestSyncOverwrite(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := GetSharedTestFile(t)

	dstFile := GetSharedTestFile(t)

	InitMeta(srcFile, "file")
	InitMeta(dstFile, "file")

	oldContent := []byte("old content in destination")
	oldSourcePath := CreateTempSourceFile(t, oldContent)
	Add(dstFile, oldSourcePath, "old_file.txt", 0)

	newContent := []byte("new content from source")
	newSourcePath := CreateTempSourceFile(t, newContent)
	Add(srcFile, newSourcePath, "new_file.txt", 0)

	Sync(srcFile, dstFile)

	dstMeta, err := ReadMeta(dstFile)

	if err != nil {

		t.Fatalf("ReadMeta failed: %v", err)

	}
	if dstMeta.Files[0].Name != "new_file.txt" {
		t.Errorf("Expected new_file.txt, got %s", dstMeta.Files[0].Name)
	}

	VerifyFileConsistency(t, dstFile, 0, newContent)
}

func TestSyncPartialFilesystem(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := GetSharedTestFile(t)

	dstFile := GetSharedTestFile(t)

	InitMeta(srcFile, "file")

	indices := []int{0, 5, 10, 50, 100, 500, 999}
	for _, idx := range indices {
		content := []byte(fmt.Sprintf("Content at index %d", idx))
		sourcePath := CreateTempSourceFile(t, content)
		Add(srcFile, sourcePath, fmt.Sprintf("file_%d.txt", idx), idx)
	}

	Sync(srcFile, dstFile)

	for _, idx := range indices {
		expectedContent := []byte(fmt.Sprintf("Content at index %d", idx))
		VerifyFileConsistency(t, dstFile, idx, expectedContent)
	}

	dstMeta, err := ReadMeta(dstFile)

	if err != nil {

		t.Fatalf("ReadMeta failed: %v", err)

	}
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
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping large file sync test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := GetSharedTestFile(t)

	dstFile := GetSharedTestFile(t)

	InitMeta(srcFile, "file")

	maxSize := 40000
	for i := 0; i < 10; i++ {
		content := GenerateRandomBytes(maxSize)
		sourcePath := CreateTempSourceFile(t, content)
		Add(srcFile, sourcePath, fmt.Sprintf("large_%d.bin", i), i)
	}

	Sync(srcFile, dstFile)

	srcMeta, err := ReadMeta(srcFile)

	if err != nil {

		t.Fatalf("ReadMeta failed: %v", err)

	}
	dstMeta, err := ReadMeta(dstFile)

	if err != nil {

		t.Fatalf("ReadMeta failed: %v", err)

	}

	for i := 0; i < 10; i++ {
		if srcMeta.Files[i].Size != dstMeta.Files[i].Size {
			t.Errorf("File %d size mismatch: src=%d, dst=%d", i, srcMeta.Files[i].Size, dstMeta.Files[i].Size)
		}
	}
}

func TestSyncMultipleTimes(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := GetSharedTestFile(t)

	dstFile := GetSharedTestFile(t)

	InitMeta(srcFile, "file")

	content1 := []byte("Sync 1 content")
	sourcePath1 := CreateTempSourceFile(t, content1)
	Add(srcFile, sourcePath1, "file1.txt", 0)
	Sync(srcFile, dstFile)

	content2 := []byte("Sync 2 content")
	sourcePath2 := CreateTempSourceFile(t, content2)
	Add(srcFile, sourcePath2, "file2.txt", 1)
	Sync(srcFile, dstFile)

	Del(srcFile, 0)
	Sync(srcFile, dstFile)

	srcMeta, err := ReadMeta(srcFile)

	if err != nil {

		t.Fatalf("ReadMeta failed: %v", err)

	}
	dstMeta, err := ReadMeta(dstFile)

	if err != nil {

		t.Fatalf("ReadMeta failed: %v", err)

	}

	if dstMeta.Files[0].Name != "" {
		t.Error("File 0 should be deleted after sync")
	}

	if dstMeta.Files[1].Name != "file2.txt" {
		t.Errorf("File 1 should be file2.txt, got %s", dstMeta.Files[1].Name)
	}

	for i := 0; i < TOTAL_FILES; i++ {
		if srcMeta.Files[i].Name != dstMeta.Files[i].Name {
			t.Errorf("After multiple syncs, index %d name mismatch", i)
		}
	}
}

func TestReadBlock(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	content := []byte("Test content for ReadBlock")
	sourcePath := CreateTempSourceFile(t, content)
	Add(file, sourcePath, "test.txt", 5)

	block, err := ReadBlock(file, 5)
	if err != nil {
		t.Fatalf("ReadBlock failed: %v", err)
	}

	if len(block) != MAX_FILE_SIZE {
		t.Errorf("Block size should be %d, got %d", MAX_FILE_SIZE, len(block))
	}

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
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	block := make([]byte, MAX_FILE_SIZE)
	testData := []byte("Test data in block")
	copy(block, testData)

	WriteBlock(file, block, "test_block.txt", 7)

	file.Seek(int64(META_FILE_SIZE+(7*MAX_FILE_SIZE)), 0)
	readBlock := make([]byte, MAX_FILE_SIZE)
	file.Read(readBlock)

	if !bytes.Equal(block, readBlock) {
		t.Error("Written block doesn't match read block")
	}
}

func TestSyncWithBinaryData(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := GetSharedTestFile(t)

	dstFile := GetSharedTestFile(t)

	InitMeta(srcFile, "file")

	binaryData := make([]byte, 256)
	for i := 0; i < 256; i++ {
		binaryData[i] = byte(i)
	}

	sourcePath := CreateTempSourceFile(t, binaryData)
	Add(srcFile, sourcePath, "binary.bin", 0)

	Sync(srcFile, dstFile)

	VerifyFileConsistency(t, dstFile, 0, binaryData)
}

func TestSyncFullFilesystem(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping full filesystem sync test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := GetSharedTestFile(t)

	dstFile := GetSharedTestFile(t)

	InitMeta(srcFile, "file")

	const testFileCount = 100
	FillSlots(t, srcFile, testFileCount)

	Sync(srcFile, dstFile)

	srcMeta, err := ReadMeta(srcFile)

	if err != nil {

		t.Fatalf("ReadMeta failed: %v", err)

	}
	dstMeta, err := ReadMeta(dstFile)

	if err != nil {

		t.Fatalf("ReadMeta failed: %v", err)

	}

	for i := 0; i < testFileCount; i++ {
		if srcMeta.Files[i].Name != dstMeta.Files[i].Name {
			t.Errorf("Index %d name mismatch after full sync", i)
		}
		if srcMeta.Files[i].Size != dstMeta.Files[i].Size {
			t.Errorf("Index %d size mismatch after full sync", i)
		}
	}

	srcCount := CountUsedSlots(srcMeta)
	dstCount := CountUsedSlots(dstMeta)

	if srcCount != dstCount {
		t.Errorf("Used slot count mismatch: src=%d, dst=%d", srcCount, dstCount)
	}

	if srcCount != testFileCount {
		t.Errorf("Expected %d files, got %d", testFileCount, srcCount)
	}
}

func TestSyncPreservesEmptySlots(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	srcFile := GetSharedTestFile(t)

	dstFile := GetSharedTestFile(t)

	InitMeta(srcFile, "file")

	content := []byte("test content")
	sourcePath := CreateTempSourceFile(t, content)
	Add(srcFile, sourcePath, "file1.txt", 0)
	Add(srcFile, sourcePath, "file2.txt", 10)
	Add(srcFile, sourcePath, "file3.txt", 20)

	Sync(srcFile, dstFile)

	dstMeta, err := ReadMeta(dstFile)

	if err != nil {

		t.Fatalf("ReadMeta failed: %v", err)

	}

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
