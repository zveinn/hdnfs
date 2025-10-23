package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAdd(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	tests := []struct {
		name     string
		content  []byte
		filename string
		index    int
	}{
		{
			name:     "Small file",
			content:  []byte("Hello, World!"),
			filename: "hello.txt",
			index:    OUT_OF_BOUNDS_INDEX,
		},
		{
			name:     "Medium file",
			content:  GenerateRandomBytes(1024),
			filename: "medium.bin",
			index:    OUT_OF_BOUNDS_INDEX,
		},
		{
			name:     "Large file near limit",
			content:  GenerateRandomBytes(40000),
			filename: "large.bin",
			index:    OUT_OF_BOUNDS_INDEX,
		},
		{
			name:     "File at specific index",
			content:  []byte("specific index"),
			filename: "specific.txt",
			index:    10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			sourcePath := CreateTempSourceFileWithName(t, tt.content, tt.filename)

			Add(file, sourcePath, tt.index)

			file.Seek(0, 0)
			meta, err := ReadMeta(file)
			if err != nil {
				t.Fatalf("ReadMeta failed: %v", err)
			}

			var foundIndex int = -1
			if tt.index != OUT_OF_BOUNDS_INDEX {
				foundIndex = tt.index
			} else {
				for i, f := range meta.Files {
					if f.Name == tt.filename {
						foundIndex = i
						break
					}
				}
			}

			if foundIndex == -1 {
				t.Fatalf("File not found in metadata: %s", tt.filename)
			}

			if meta.Files[foundIndex].Name != tt.filename {
				t.Errorf("Name mismatch: expected %s, got %s", tt.filename, meta.Files[foundIndex].Name)
			}

			VerifyFileConsistency(t, file, foundIndex, tt.content)
		})
	}
}

func TestAddOverwrite(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	content1 := []byte("Initial content")
	sourcePath1 := CreateTempSourceFileWithName(t, content1, "initial.txt")
	Add(file, sourcePath1, 0)

	VerifyFileConsistency(t, file, 0, content1)

	content2 := []byte("Overwritten content - much longer than before!")
	sourcePath2 := CreateTempSourceFileWithName(t, content2, "overwritten.txt")
	Add(file, sourcePath2, 0)

	VerifyFileConsistency(t, file, 0, content2)

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if meta.Files[0].Name != "overwritten.txt" {
		t.Errorf("Name not updated: %s", meta.Files[0].Name)
	}
}

func TestAddFileTooLarge(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	largeContent := GenerateRandomBytes(MAX_FILE_SIZE)
	sourcePath := CreateTempSourceFile(t, largeContent)

	Add(file, sourcePath, OUT_OF_BOUNDS_INDEX)

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	// Verify no files were added (all slots should be empty)
	for i, f := range meta.Files {
		if f.Name != "" {
			t.Errorf("File should not have been added, but found file at slot %d: %s", i, f.Name)
		}
	}
}

func TestAddFilenameTooLong(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	content := []byte("test content")

	// Create a file with a name that exceeds MAX_FILE_NAME_SIZE
	longName := string(bytes.Repeat([]byte("a"), MAX_FILE_NAME_SIZE+1)) + ".txt"
	sourcePath := CreateTempSourceFileWithName(t, content, longName)

	err := Add(file, sourcePath, OUT_OF_BOUNDS_INDEX)
	if err == nil {
		t.Error("Expected error when adding file with too long name, got nil")
	}

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if CountUsedSlots(meta) != 0 {
		t.Error("File with long name should not have been added")
	}
}

func TestAddWhenFull(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping full filesystem test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	const testFileCount = 100
	FillSlots(t, file, testFileCount)

	content := []byte("one too many")
	sourcePath := CreateTempSourceFile(t, content)

	Add(file, sourcePath, OUT_OF_BOUNDS_INDEX)

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}

	// Check that the file was added in slot 100 (the first empty slot after filling 100)
	if meta.Files[testFileCount].Name == "" {
		t.Error("File should have been added in slot 100 (first empty slot beyond the filled range)")
	}
	if meta.Files[testFileCount].Size == 0 {
		t.Error("File at slot 100 should have non-zero size")
	}
}

func TestGet(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	originalContent := []byte("This is test content for Get function")
	sourcePath := CreateTempSourceFile(t, originalContent)
	Add(file, sourcePath, 5)

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "output.txt")

	Get(file, 5, outputPath)

	retrievedContent, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read retrieved file: %v", err)
	}

	if !bytes.Equal(retrievedContent, originalContent) {
		t.Errorf("Retrieved content doesn't match original")
		t.Errorf("Expected: %s", string(originalContent))
		t.Errorf("Got: %s", string(retrievedContent))
	}
}

func TestGetMultipleFiles(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	tmpDir := t.TempDir()

	testFiles := []struct {
		content  []byte
		name     string
		index    int
		outName  string
	}{
		{[]byte("File 1"), "file1.txt", 0, "out1.txt"},
		{[]byte("File 2 content"), "file2.txt", 1, "out2.txt"},
		{[]byte("File 3 larger content here"), "file3.txt", 2, "out3.txt"},
	}

	for _, tf := range testFiles {
		sourcePath := CreateTempSourceFile(t, tf.content)
		Add(file, sourcePath, tf.index)
	}

	for _, tf := range testFiles {
		outputPath := filepath.Join(tmpDir, tf.outName)
		Get(file, tf.index, outputPath)

		retrieved, err := os.ReadFile(outputPath)
		if err != nil {
			t.Errorf("Failed to read %s: %v", tf.outName, err)
			continue
		}

		if !bytes.Equal(retrieved, tf.content) {
			t.Errorf("File %s content mismatch", tf.name)
		}
	}
}

func TestDel(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	content := []byte("File to be deleted")
	sourcePath := CreateTempSourceFileWithName(t, content, "todelete.txt")
	Add(file, sourcePath, 3)

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if meta.Files[3].Name != "todelete.txt" {
		t.Fatal("File was not added")
	}

	Del(file, 3)

	meta, err = ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if meta.Files[3].Name != "" {
		t.Errorf("File name not cleared: %s", meta.Files[3].Name)
	}
	if meta.Files[3].Size != 0 {
		t.Errorf("File size not cleared: %d", meta.Files[3].Size)
	}

	seekPos := META_FILE_SIZE + (3 * MAX_FILE_SIZE)
	file.Seek(int64(seekPos), 0)
	buf := make([]byte, MAX_FILE_SIZE)
	file.Read(buf)

	allZeros := true
	for _, b := range buf {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if !allZeros {
		t.Error("File data was not zeroed after deletion")
	}
}

func TestDelMultipleFiles(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	for i := 0; i < 10; i++ {
		content := []byte(fmt.Sprintf("File %d", i))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, i)
	}

	for i := 0; i < 10; i += 2 {
		Del(file, i)
	}

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	for i := 0; i < 10; i++ {
		if i%2 == 0 {

			if meta.Files[i].Name != "" {
				t.Errorf("File at index %d should be deleted", i)
			}
		} else {

			if meta.Files[i].Name == "" {
				t.Errorf("File at index %d should not be deleted", i)
			}
		}
	}
}

func TestDelInvalidIndex(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	Del(file, TOTAL_FILES+100)

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if meta == nil {
		t.Error("Filesystem corrupted after invalid delete")
	}
}

func TestAddDeleteAddCycle(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	index := 5

	for cycle := 0; cycle < 5; cycle++ {

		content := []byte(fmt.Sprintf("Cycle %d content", cycle))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, index)

		VerifyFileConsistency(t, file, index, content)

		Del(file, index)

		meta, err := ReadMeta(file)
		if err != nil {
			t.Fatalf("ReadMeta failed: %v", err)
		}
		if meta.Files[index].Name != "" {
			t.Errorf("Cycle %d: file not deleted", cycle)
		}
	}
}

func TestAddWithEmptyFile(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	emptyContent := []byte{}
	sourcePath := CreateTempSourceFileWithName(t, emptyContent, "empty.txt")
	Add(file, sourcePath, 0)

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if meta.Files[0].Name != "empty.txt" {
		t.Error("Empty file was not added")
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "empty_out.txt")
	Get(file, 0, outputPath)

	retrieved, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read empty file: %v", err)
	}

	if len(retrieved) != 0 {
		t.Errorf("Empty file should have no content, got %d bytes", len(retrieved))
	}
}

func TestAddBinaryFile(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	binaryContent := make([]byte, 256)
	for i := 0; i < 256; i++ {
		binaryContent[i] = byte(i)
	}

	sourcePath := CreateTempSourceFile(t, binaryContent)
	Add(file, sourcePath, 0)

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "binary_out.bin")
	Get(file, 0, outputPath)

	retrieved, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read binary file: %v", err)
	}

	if !bytes.Equal(retrieved, binaryContent) {
		t.Error("Binary file content corrupted")
		for i := 0; i < len(binaryContent) && i < len(retrieved); i++ {
			if binaryContent[i] != retrieved[i] {
				t.Errorf("First mismatch at byte %d: expected %02x, got %02x", i, binaryContent[i], retrieved[i])
				break
			}
		}
	}
}

func BenchmarkAdd(b *testing.B) {
	SetupTestKey(&testing.T{})
	file := CreateTempTestFile(&testing.T{}, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	content := GenerateRandomBytes(1024)
	sourcePath := CreateTempSourceFile(&testing.T{}, content)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index := i % TOTAL_FILES
		Add(file, sourcePath, index)
	}
}

func BenchmarkGet(b *testing.B) {
	SetupTestKey(&testing.T{})
	file := CreateTempTestFile(&testing.T{}, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	content := GenerateRandomBytes(1024)
	sourcePath := CreateTempSourceFile(&testing.T{}, content)
	Add(file, sourcePath, 0)

	tmpDir := "/tmp"
	outputPath := filepath.Join(tmpDir, "bench_out.txt")
	defer os.Remove(outputPath)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Get(file, 0, outputPath)
	}
}

func BenchmarkDel(b *testing.B) {
	SetupTestKey(&testing.T{})
	file := CreateTempTestFile(&testing.T{}, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	content := []byte("benchmark")
	sourcePath := CreateTempSourceFile(&testing.T{}, content)
	for i := 0; i < 100; i++ {
		Add(file, sourcePath, i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index := i % 100
		Del(file, index)

		Add(file, sourcePath, index)
	}
}
