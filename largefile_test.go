package hdnfs

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestLargeFilesystem tests filesystem with large storage capacity
func TestLargeFilesystem1GB(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping 1GB filesystem test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	// Calculate size for 1GB data capacity (metadata + data)
	// Note: Current MAX_FILE_SIZE is 50KB, so we can't actually store 1GB in 1000 files
	// This test validates the filesystem structure with large allocations

	size := int64(1 * 1024 * 1024 * 1024) // 1GB
	file := CreateTempTestFile(t, size)
	defer file.Close()

	// Initialize metadata
	InitMeta(file, "file")

	t.Log("Initialized 1GB filesystem")

	// Verify we can read metadata
	meta := VerifyMetadataIntegrity(t, file)
	if meta == nil {
		t.Fatal("Failed to verify metadata on 1GB filesystem")
	}

	// Add files throughout the address space
	testIndices := []int{0, 100, 500, 900, 999}
	for _, idx := range testIndices {
		content := []byte(fmt.Sprintf("Test content at index %d in 1GB filesystem", idx))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("file_%d.txt", idx), idx)

		t.Logf("Added file at index %d", idx)
	}

	// Verify all files
	for _, idx := range testIndices {
		content := []byte(fmt.Sprintf("Test content at index %d in 1GB filesystem", idx))
		VerifyFileConsistency(t, file, idx, content)
	}

	t.Log("All files verified successfully on 1GB filesystem")
}

func TestLargeFilesystem5GB(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping 5GB filesystem test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	// 5GB filesystem
	size := int64(5 * 1024 * 1024 * 1024) // 5GB
	file := CreateTempTestFile(t, size)
	defer file.Close()

	t.Log("Created 5GB filesystem")

	// Initialize
	InitMeta(file, "file")

	t.Log("Initialized 5GB filesystem")

	// Verify metadata integrity
	meta := VerifyMetadataIntegrity(t, file)
	if meta == nil {
		t.Fatal("Failed to verify metadata on 5GB filesystem")
	}

	// Add files at various positions
	testIndices := []int{0, 250, 500, 750, 999}
	for _, idx := range testIndices {
		content := GenerateRandomBytes(10000) // 10KB files
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("large_%d.bin", idx), idx)

		t.Logf("Added 10KB file at index %d", idx)
	}

	// Verify all files
	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	for _, idx := range testIndices {
		if meta.Files[idx].Name == "" {
			t.Errorf("File at index %d was not added", idx)
		}
	}

	t.Log("All files verified on 5GB filesystem")
}

func TestLargeFileAddressSpace(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large address space test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	// Test that we can correctly calculate and access positions in large files
	size := int64(2 * 1024 * 1024 * 1024) // 2GB

	file := CreateTempTestFile(t, size)
	defer file.Close()

	InitMeta(file, "file")

	// Test access at boundaries
	tests := []struct {
		index    int
		position int64
	}{
		{0, META_FILE_SIZE},
		{1, META_FILE_SIZE + MAX_FILE_SIZE},
		{100, META_FILE_SIZE + (100 * MAX_FILE_SIZE)},
		{500, META_FILE_SIZE + (500 * MAX_FILE_SIZE)},
		{999, META_FILE_SIZE + (999 * MAX_FILE_SIZE)},
	}

	for _, tt := range tests {
		// Seek to expected position
		pos, err := file.Seek(tt.position, 0)
		if err != nil {
			t.Errorf("Failed to seek to position %d: %v", tt.position, err)
		}

		if pos != tt.position {
			t.Errorf("Seek position mismatch for index %d: expected %d, got %d", tt.index, tt.position, pos)
		}

		// Write marker
		marker := []byte(fmt.Sprintf("INDEX_%d", tt.index))
		_, err = file.Write(marker)
		if err != nil {
			t.Errorf("Failed to write at index %d: %v", tt.index, err)
		}

		// Read back
		file.Seek(tt.position, 0)
		readMarker := make([]byte, len(marker))
		_, err = file.Read(readMarker)
		if err != nil {
			t.Errorf("Failed to read at index %d: %v", tt.index, err)
		}

		if string(readMarker) != string(marker) {
			t.Errorf("Marker mismatch at index %d: expected %s, got %s", tt.index, marker, readMarker)
		}
	}

	t.Log("Large address space test passed")
}

func TestManyLargeFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping many large files test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	size := int64(META_FILE_SIZE + (TOTAL_FILES * MAX_FILE_SIZE))
	file := CreateTempTestFile(t, size)
	defer file.Close()

	InitMeta(file, "file")

	// Add 100 files of maximum size
	maxContentSize := 40000 // Leave room for encryption
	numFiles := 100

	t.Logf("Adding %d files of %d bytes each", numFiles, maxContentSize)

	for i := 0; i < numFiles; i++ {
		content := GenerateRandomBytes(maxContentSize)
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("large_%d.bin", i), i)

		if i%10 == 0 {
			t.Logf("Progress: %d/%d files added", i, numFiles)
		}
	}

	t.Log("All files added, verifying...")

	// Verify metadata
	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	for i := 0; i < numFiles; i++ {
		if meta.Files[i].Name == "" {
			t.Errorf("File %d was not added", i)
		}
		if meta.Files[i].Size == 0 {
			t.Errorf("File %d has zero size", i)
		}
	}

	t.Log("Many large files test passed")
}

func TestLargeFileIntegrity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large file integrity test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	size := int64(1 * 1024 * 1024 * 1024) // 1GB
	file := CreateTempTestFile(t, size)
	defer file.Close()

	InitMeta(file, "file")

	// Create files with known checksums
	numFiles := 50
	checksums := make(map[int][32]byte)

	for i := 0; i < numFiles; i++ {
		content := GenerateRandomBytes(20000)
		checksum := sha256.Sum256(content)
		checksums[i] = checksum

		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("integrity_%d.bin", i), i)
	}

	t.Log("Files added with checksums")

	// Retrieve and verify checksums
	tmpDir := t.TempDir()
	for i := 0; i < numFiles; i++ {
		outputPath := filepath.Join(tmpDir, fmt.Sprintf("out_%d.bin", i))
		Get(file, i, outputPath)

		// Calculate checksum of retrieved file
		retrievedContent, err := os.ReadFile(outputPath)
		if err != nil {
			t.Errorf("Failed to read retrieved file %d: %v", i, err)
			continue
		}

		retrievedChecksum := sha256.Sum256(retrievedContent)
		if retrievedChecksum != checksums[i] {
			t.Errorf("Checksum mismatch for file %d", i)
		}
	}

	t.Log("All checksums verified")
}

func TestLargeFilesystemSync(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large filesystem sync test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	size := int64(2 * 1024 * 1024 * 1024) // 2GB

	srcFile := CreateTempTestFile(t, size)
	defer srcFile.Close()

	dstFile := CreateTempTestFile(t, size)
	defer dstFile.Close()

	InitMeta(srcFile, "file")

	t.Log("Adding files to source...")

	// Add files
	numFiles := 50
	for i := 0; i < numFiles; i++ {
		content := GenerateRandomBytes(30000)
		sourcePath := CreateTempSourceFile(t, content)
		Add(srcFile, sourcePath, fmt.Sprintf("sync_%d.bin", i), i)
	}

	t.Log("Syncing large filesystem...")

	// Sync
	Sync(srcFile, dstFile)

	t.Log("Verifying sync...")

	// Verify sync
	srcMeta, err := ReadMeta(srcFile)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	dstMeta, err := ReadMeta(dstFile)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}

	for i := 0; i < numFiles; i++ {
		if srcMeta.Files[i].Name != dstMeta.Files[i].Name {
			t.Errorf("File %d name mismatch after sync", i)
		}
		if srcMeta.Files[i].Size != dstMeta.Files[i].Size {
			t.Errorf("File %d size mismatch after sync", i)
		}
	}

	t.Log("Large filesystem sync successful")
}

func TestLargeFilesystemFragmentation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping fragmentation test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	size := int64(1 * 1024 * 1024 * 1024) // 1GB
	file := CreateTempTestFile(t, size)
	defer file.Close()

	InitMeta(file, "file")

	// Fill filesystem
	for i := 0; i < 200; i++ {
		content := GenerateRandomBytes(10000)
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("frag_%d.bin", i), i)
	}

	t.Log("Filled filesystem with 200 files")

	// Delete every other file
	for i := 0; i < 200; i += 2 {
		Del(file, i)
	}

	t.Log("Deleted every other file (100 deletions)")

	// Verify fragmentation
	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	usedCount := 0
	for i := 0; i < 200; i++ {
		if meta.Files[i].Name != "" {
			usedCount++
		}
	}

	if usedCount != 100 {
		t.Errorf("Expected 100 files after deletions, got %d", usedCount)
	}

	// Add files back into gaps
	gapsCount := 0
	for i := 0; i < 200; i++ {
		if meta.Files[i].Name == "" {
			content := GenerateRandomBytes(10000)
			sourcePath := CreateTempSourceFile(t, content)
			Add(file, sourcePath, fmt.Sprintf("gap_%d.bin", i), OUT_OF_BOUNDS_INDEX)
			gapsCount++

			if gapsCount >= 50 {
				break
			}
		}
	}

	t.Logf("Filled %d gaps", gapsCount)

	// Verify gaps were filled
	meta, err = ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	finalCount := CountUsedSlots(meta)

	if finalCount != 150 {
		t.Errorf("Expected 150 files after refilling gaps, got %d", finalCount)
	}

	t.Log("Fragmentation test passed")
}

func TestLargeFileStressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	size := int64(1 * 1024 * 1024 * 1024) // 1GB
	file := CreateTempTestFile(t, size)
	defer file.Close()

	InitMeta(file, "file")

	// Perform many operations
	operations := 500

	t.Logf("Running %d random operations", operations)

	for i := 0; i < operations; i++ {
		op := i % 3
		index := i % 300

		switch op {
		case 0: // Add
			content := GenerateRandomBytes(5000 + (i % 10000))
			sourcePath := CreateTempSourceFile(t, content)
			Add(file, sourcePath, fmt.Sprintf("stress_%d.bin", i), index)

		case 1: // Delete
			Del(file, index)

		case 2: // Read metadata
			meta, err := ReadMeta(file)
			if err != nil {
				t.Fatalf("ReadMeta failed: %v", err)
			}
			if meta == nil {
				t.Fatal("Metadata became corrupted during stress test")
			}
		}

		if i%50 == 0 {
			t.Logf("Progress: %d/%d operations", i, operations)
			// Verify integrity periodically
			VerifyMetadataIntegrity(t, file)
		}
	}

	t.Log("Stress test completed")

	// Final integrity check
	meta := VerifyMetadataIntegrity(t, file)
	t.Logf("Final state: %d files in filesystem", CountUsedSlots(meta))
}

func TestLargeFileSeekPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping seek performance test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	size := int64(5 * 1024 * 1024 * 1024) // 5GB
	file := CreateTempTestFile(t, size)
	defer file.Close()

	InitMeta(file, "file")

	// Test seeking to various positions in large file
	positions := []int{0, 100, 250, 500, 750, 999}

	for _, idx := range positions {
		expectedPos := int64(META_FILE_SIZE + (idx * MAX_FILE_SIZE))

		pos, err := file.Seek(expectedPos, 0)
		if err != nil {
			t.Errorf("Seek to index %d failed: %v", idx, err)
		}

		if pos != expectedPos {
			t.Errorf("Seek position mismatch at index %d: expected %d, got %d", idx, expectedPos, pos)
		}
	}

	t.Log("Seek performance test passed")
}

func BenchmarkLargeFilesystemAdd(b *testing.B) {
	SetupTestKey(&testing.T{})

	size := int64(1 * 1024 * 1024 * 1024) // 1GB
	file := CreateTempTestFile(&testing.T{}, size)
	defer file.Close()

	InitMeta(file, "file")

	content := GenerateRandomBytes(10000)
	sourcePath := CreateTempSourceFile(&testing.T{}, content)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index := i % 100
		Add(file, sourcePath, fmt.Sprintf("bench_%d.bin", i), index)
	}
}

func BenchmarkLargeFilesystemRead(b *testing.B) {
	SetupTestKey(&testing.T{})

	size := int64(1 * 1024 * 1024 * 1024) // 1GB
	file := CreateTempTestFile(&testing.T{}, size)
	defer file.Close()

	InitMeta(file, "file")

	// Add some files
	for i := 0; i < 10; i++ {
		content := GenerateRandomBytes(10000)
		sourcePath := CreateTempSourceFile(&testing.T{}, content)
		Add(file, sourcePath, fmt.Sprintf("bench_%d.bin", i), i)
	}

	tmpDir := "/tmp"
	outputPath := filepath.Join(tmpDir, "bench_out.bin")
	defer os.Remove(outputPath)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index := i % 10
		Get(file, index, outputPath)
	}
}
