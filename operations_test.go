package hdnfs

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestAdd(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

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
			content:  GenerateRandomBytes(40000), // Leave room for encryption overhead
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
			// Create source file
			sourcePath := CreateTempSourceFile(t, tt.content)

			// Add to filesystem
			Add(file, sourcePath, tt.filename, tt.index)

			// Read metadata to verify
			file.Seek(0, 0)
			meta, err := ReadMeta(file)
			if err != nil {
				t.Fatalf("ReadMeta failed: %v", err)
			}

			// Find the file
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

			// Verify metadata entry
			if meta.Files[foundIndex].Name != tt.filename {
				t.Errorf("Name mismatch: expected %s, got %s", tt.filename, meta.Files[foundIndex].Name)
			}

			// Verify file content
			VerifyFileConsistency(t, file, foundIndex, tt.content)
		})
	}
}

func TestAddOverwrite(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Add initial file
	content1 := []byte("Initial content")
	sourcePath1 := CreateTempSourceFile(t, content1)
	Add(file, sourcePath1, "file.txt", 0)

	// Verify initial file
	VerifyFileConsistency(t, file, 0, content1)

	// Overwrite with new content
	content2 := []byte("Overwritten content - much longer than before!")
	sourcePath2 := CreateTempSourceFile(t, content2)
	Add(file, sourcePath2, "overwritten.txt", 0)

	// Verify overwritten file
	VerifyFileConsistency(t, file, 0, content2)

	// Verify metadata
	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if meta.Files[0].Name != "overwritten.txt" {
		t.Errorf("Name not updated: %s", meta.Files[0].Name)
	}
}

func TestAddFileTooLarge(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Create file that's too large (after encryption, will exceed MAX_FILE_SIZE)
	// AES-CFB adds 16 bytes for IV
	largeContent := GenerateRandomBytes(MAX_FILE_SIZE) // This will be > MAX_FILE_SIZE after encryption
	sourcePath := CreateTempSourceFile(t, largeContent)

	// This should fail (PrintError is called)
	Add(file, sourcePath, "toolarge.bin", OUT_OF_BOUNDS_INDEX)

	// Verify file was NOT added
	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	for _, f := range meta.Files {
		if f.Name == "toolarge.bin" {
			t.Error("File should not have been added")
		}
	}
}

func TestAddFilenameTooLong(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	content := []byte("test content")
	sourcePath := CreateTempSourceFile(t, content)

	// Create filename longer than MAX_FILE_NAME_SIZE
	longName := string(bytes.Repeat([]byte("a"), MAX_FILE_NAME_SIZE+1))

	// This should fail
	Add(file, sourcePath, longName, OUT_OF_BOUNDS_INDEX)

	// Verify file was NOT added
	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if CountUsedSlots(meta) != 0 {
		t.Error("File with long name should not have been added")
	}
}

func TestAddWhenFull(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping full filesystem test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Fill all slots
	FillAllSlots(t, file)

	// Try to add one more file
	content := []byte("one too many")
	sourcePath := CreateTempSourceFile(t, content)
	Add(file, sourcePath, "overflow.txt", OUT_OF_BOUNDS_INDEX)

	// Verify it was not added (should print error about no slots available)
	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	for _, f := range meta.Files {
		if f.Name == "overflow.txt" {
			t.Error("File should not have been added when filesystem is full")
		}
	}
}

func TestGet(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Add a file
	originalContent := []byte("This is test content for Get function")
	sourcePath := CreateTempSourceFile(t, originalContent)
	Add(file, sourcePath, "testget.txt", 5)

	// Get the file
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "output.txt")

	Get(file, 5, outputPath)

	// Verify output file exists and matches original
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
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	tmpDir := t.TempDir()

	// Add multiple files
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
		Add(file, sourcePath, tf.name, tf.index)
	}

	// Retrieve all files
	for _, tf := range testFiles {
		outputPath := filepath.Join(tmpDir, tf.outName)
		Get(file, tf.index, outputPath)

		// Verify
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
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Add a file
	content := []byte("File to be deleted")
	sourcePath := CreateTempSourceFile(t, content)
	Add(file, sourcePath, "todelete.txt", 3)

	// Verify it exists
	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if meta.Files[3].Name != "todelete.txt" {
		t.Fatal("File was not added")
	}

	// Delete the file
	Del(file, 3)

	// Verify metadata is cleared
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

	// Verify file data is zeroed
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
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Add multiple files
	for i := 0; i < 10; i++ {
		content := []byte(fmt.Sprintf("File %d", i))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("file%d.txt", i), i)
	}

	// Delete every other file
	for i := 0; i < 10; i += 2 {
		Del(file, i)
	}

	// Verify correct files are deleted
	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	for i := 0; i < 10; i++ {
		if i%2 == 0 {
			// Should be deleted
			if meta.Files[i].Name != "" {
				t.Errorf("File at index %d should be deleted", i)
			}
		} else {
			// Should still exist
			if meta.Files[i].Name == "" {
				t.Errorf("File at index %d should not be deleted", i)
			}
		}
	}
}

func TestDelInvalidIndex(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Try to delete out of bounds index
	// This should call PrintError but not crash
	Del(file, TOTAL_FILES+100)

	// Verify filesystem is still intact
	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if meta == nil {
		t.Error("Filesystem corrupted after invalid delete")
	}
}

func TestAddDeleteAddCycle(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	index := 5

	for cycle := 0; cycle < 5; cycle++ {
		// Add file
		content := []byte(fmt.Sprintf("Cycle %d content", cycle))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("cycle%d.txt", cycle), index)

		// Verify added
		VerifyFileConsistency(t, file, index, content)

		// Delete file
		Del(file, index)

		// Verify deleted
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
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Add empty file
	emptyContent := []byte{}
	sourcePath := CreateTempSourceFile(t, emptyContent)
	Add(file, sourcePath, "empty.txt", 0)

	// Verify it was added
	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if meta.Files[0].Name != "empty.txt" {
		t.Error("Empty file was not added")
	}

	// Verify we can retrieve it
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
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Create binary content with all byte values
	binaryContent := make([]byte, 256)
	for i := 0; i < 256; i++ {
		binaryContent[i] = byte(i)
	}

	sourcePath := CreateTempSourceFile(t, binaryContent)
	Add(file, sourcePath, "binary.bin", 0)

	// Retrieve and verify
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
		Add(file, sourcePath, fmt.Sprintf("bench%d.txt", i), index)
	}
}

func BenchmarkGet(b *testing.B) {
	SetupTestKey(&testing.T{})
	file := CreateTempTestFile(&testing.T{}, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	content := GenerateRandomBytes(1024)
	sourcePath := CreateTempSourceFile(&testing.T{}, content)
	Add(file, sourcePath, "bench.txt", 0)

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

	// Pre-fill with files
	content := []byte("benchmark")
	sourcePath := CreateTempSourceFile(&testing.T{}, content)
	for i := 0; i < 100; i++ {
		Add(file, sourcePath, fmt.Sprintf("file%d.txt", i), i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index := i % 100
		Del(file, index)
		// Re-add to keep filesystem populated
		Add(file, sourcePath, fmt.Sprintf("file%d.txt", i), index)
	}
}
