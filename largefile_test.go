package hdnfs

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSmallFilesystemBasic(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	size := int64(500 * 1024)
	file := CreateTempTestFile(t, size)
	defer file.Close()

	InitMeta(file, "file")

	testIndices := []int{0, 3, 5, 8}
	for _, idx := range testIndices {
		content := []byte(fmt.Sprintf("Test content at index %d", idx))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("file_%d.txt", idx), idx)
	}

	for _, idx := range testIndices {
		content := []byte(fmt.Sprintf("Test content at index %d", idx))
		VerifyFileConsistency(t, file, idx, content)
	}

	t.Log("Small filesystem basic test passed")
}

func TestSmallFilesystemAddressSpace(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	size := int64(1024 * 1024)
	file := CreateTempTestFile(t, size)
	defer file.Close()

	InitMeta(file, "file")

	tests := []struct {
		index    int
		position int64
	}{
		{0, META_FILE_SIZE},
		{1, META_FILE_SIZE + MAX_FILE_SIZE},
		{5, META_FILE_SIZE + (5 * MAX_FILE_SIZE)},
		{10, META_FILE_SIZE + (10 * MAX_FILE_SIZE)},
	}

	for _, tt := range tests {

		pos, err := file.Seek(tt.position, 0)
		if err != nil {
			t.Errorf("Failed to seek to position %d: %v", tt.position, err)
		}

		if pos != tt.position {
			t.Errorf("Seek position mismatch for index %d: expected %d, got %d", tt.index, tt.position, pos)
		}

		marker := []byte(fmt.Sprintf("INDEX_%d", tt.index))
		_, err = file.Write(marker)
		if err != nil {
			t.Errorf("Failed to write at index %d: %v", tt.index, err)
		}

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

	t.Log("Small filesystem address space test passed")
}

func TestSmallFilesystemIntegrity(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	size := int64(1024 * 1024)
	file := CreateTempTestFile(t, size)
	defer file.Close()

	InitMeta(file, "file")

	numFiles := 10
	checksums := make(map[int][32]byte)

	for i := 0; i < numFiles; i++ {
		content := GenerateRandomBytes(1000)
		checksum := sha256.Sum256(content)
		checksums[i] = checksum

		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("integrity_%d.bin", i), i)
	}

	t.Log("Small files added with checksums")

	tmpDir := t.TempDir()
	for i := 0; i < numFiles; i++ {
		outputPath := filepath.Join(tmpDir, fmt.Sprintf("out_%d.bin", i))
		Get(file, i, outputPath)

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

	t.Log("All checksums verified for small files")
}

func TestSmallFilesystemSync(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	size := int64(800 * 1024)

	srcFile := CreateTempTestFile(t, size)
	defer srcFile.Close()

	dstFile := CreateTempTestFile(t, size)
	defer dstFile.Close()

	InitMeta(srcFile, "file")

	numFiles := 8
	for i := 0; i < numFiles; i++ {
		content := GenerateRandomBytes(2000)
		sourcePath := CreateTempSourceFile(t, content)
		Add(srcFile, sourcePath, fmt.Sprintf("sync_%d.bin", i), i)
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

	for i := 0; i < numFiles; i++ {
		if srcMeta.Files[i].Name != dstMeta.Files[i].Name {
			t.Errorf("File %d name mismatch after sync", i)
		}
		if srcMeta.Files[i].Size != dstMeta.Files[i].Size {
			t.Errorf("File %d size mismatch after sync", i)
		}
	}

	t.Log("Small filesystem sync successful")
}

func TestSmallFilesystemFragmentation(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	size := int64(1024 * 1024)
	file := CreateTempTestFile(t, size)
	defer file.Close()

	InitMeta(file, "file")

	numFiles := 15
	for i := 0; i < numFiles; i++ {
		content := GenerateRandomBytes(500)
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("frag_%d.bin", i), i)
	}

	for i := 0; i < numFiles; i += 2 {
		Del(file, i)
	}

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	usedCount := 0
	for i := 0; i < numFiles; i++ {
		if meta.Files[i].Name != "" {
			usedCount++
		}
	}

	expectedCount := numFiles / 2
	if usedCount != expectedCount {
		t.Errorf("Expected %d files after deletions, got %d", expectedCount, usedCount)
	}

	gapsCount := 0
	for i := 0; i < numFiles; i++ {
		if meta.Files[i].Name == "" {
			content := GenerateRandomBytes(500)
			sourcePath := CreateTempSourceFile(t, content)
			Add(file, sourcePath, fmt.Sprintf("gap_%d.bin", i), OUT_OF_BOUNDS_INDEX)
			gapsCount++

			if gapsCount >= 4 {
				break
			}
		}
	}

	t.Logf("Filled %d gaps in small filesystem", gapsCount)

	meta, err = ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	finalCount := CountUsedSlots(meta)

	expectedFinal := expectedCount + gapsCount
	if finalCount != expectedFinal {
		t.Errorf("Expected %d files after refilling gaps, got %d", expectedFinal, finalCount)
	}

	t.Log("Small filesystem fragmentation test passed")
}

func TestSmallFilesystemSeekPerformance(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	size := int64(1024 * 1024)
	file := CreateTempTestFile(t, size)
	defer file.Close()

	InitMeta(file, "file")

	positions := []int{0, 3, 7, 12, 18}

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

	t.Log("Small filesystem seek test passed")
}

func TestLargeFileConsistency(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping large file consistency test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	size := int64(META_FILE_SIZE + (TOTAL_FILES * MAX_FILE_SIZE))
	file := CreateTempTestFile(t, size)
	defer file.Close()

	InitMeta(file, "file")

	t.Log("Testing large file consistency...")

	maxContentSize := 40000

	checksums := make(map[int][32]byte)

	testIndices := []int{0, 500, 999}

	for i, idx := range testIndices {
		content := GenerateRandomBytes(maxContentSize)
		checksum := sha256.Sum256(content)
		checksums[idx] = checksum

		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("largefile_%d.bin", i), idx)

		t.Logf("Added large file at index %d (%d bytes)", idx, maxContentSize)
	}

	t.Log("Large files added, verifying consistency...")

	tmpDir := t.TempDir()
	for _, idx := range testIndices {
		outputPath := filepath.Join(tmpDir, fmt.Sprintf("large_out_%d.bin", idx))
		Get(file, idx, outputPath)

		retrievedContent, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("Failed to read retrieved large file at index %d: %v", idx, err)
		}

		retrievedChecksum := sha256.Sum256(retrievedContent)
		if retrievedChecksum != checksums[idx] {
			t.Errorf("Checksum mismatch for large file at index %d", idx)
		}

		if len(retrievedContent) != maxContentSize {
			t.Errorf("Size mismatch for large file at index %d: expected %d, got %d",
				idx, maxContentSize, len(retrievedContent))
		}

		t.Logf("Large file at index %d verified successfully", idx)
	}

	newContent := GenerateRandomBytes(maxContentSize)
	newChecksum := sha256.Sum256(newContent)
	newSourcePath := CreateTempSourceFile(t, newContent)

	overwriteIdx := testIndices[1]
	Add(file, newSourcePath, "largefile_overwrite.bin", overwriteIdx)

	t.Logf("Overwrote large file at index %d", overwriteIdx)

	outputPath := filepath.Join(tmpDir, "large_overwrite.bin")
	Get(file, overwriteIdx, outputPath)

	retrievedContent, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read overwritten large file: %v", err)
	}

	retrievedChecksum := sha256.Sum256(retrievedContent)
	if retrievedChecksum != newChecksum {
		t.Errorf("Checksum mismatch for overwritten large file")
	}

	for _, idx := range []int{testIndices[0], testIndices[2]} {
		outputPath := filepath.Join(tmpDir, fmt.Sprintf("verify_%d.bin", idx))
		Get(file, idx, outputPath)

		retrievedContent, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("Failed to read file at index %d after overwrite: %v", idx, err)
		}

		retrievedChecksum := sha256.Sum256(retrievedContent)
		if retrievedChecksum != checksums[idx] {
			t.Errorf("Checksum changed for unmodified file at index %d", idx)
		}
	}

	t.Log("Large file consistency test passed - all large files verified successfully")
}

func BenchmarkSmallFilesystemAdd(b *testing.B) {
	SetupTestKey(&testing.T{})

	size := int64(1024 * 1024)
	file := CreateTempTestFile(&testing.T{}, size)
	defer file.Close()

	InitMeta(file, "file")

	content := GenerateRandomBytes(1000)
	sourcePath := CreateTempSourceFile(&testing.T{}, content)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index := i % 15
		Add(file, sourcePath, fmt.Sprintf("bench_%d.bin", i), index)
	}
}

func BenchmarkSmallFilesystemRead(b *testing.B) {
	SetupTestKey(&testing.T{})

	size := int64(1024 * 1024)
	file := CreateTempTestFile(&testing.T{}, size)
	defer file.Close()

	InitMeta(file, "file")

	for i := 0; i < 10; i++ {
		content := GenerateRandomBytes(1000)
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
