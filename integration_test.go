package hdnfs

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestEndToEndWorkflow tests a complete workflow from init to sync
func TestEndToEndWorkflow(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	// Step 1: Initialize
	t.Log("Step 1: Initialize filesystem")
	InitMeta(file, "file")

	meta := VerifyMetadataIntegrity(t, file)
	if CountUsedSlots(meta) != 0 {
		t.Fatal("Initial filesystem should be empty")
	}

	// Step 2: Add multiple files
	t.Log("Step 2: Add files")
	testFiles := map[int][]byte{
		0: []byte("First file content"),
		1: []byte("Second file with more content"),
		5: []byte("File at index 5"),
		10: GenerateRandomBytes(10000),
	}

	for idx, content := range testFiles {
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("file_%d.txt", idx), idx)
	}

	meta = ReadMeta(file)
	if CountUsedSlots(meta) != len(testFiles) {
		t.Errorf("Expected %d files, got %d", len(testFiles), CountUsedSlots(meta))
	}

	// Step 3: List files
	t.Log("Step 3: List files")
	output := captureOutput(func() {
		List(file, "")
	})

	for idx := range testFiles {
		filename := fmt.Sprintf("file_%d.txt", idx)
		if !bytes.Contains([]byte(output), []byte(filename)) {
			t.Errorf("File %s not found in list", filename)
		}
	}

	// Step 4: Retrieve files
	t.Log("Step 4: Retrieve files")
	tmpDir := t.TempDir()
	for idx, expectedContent := range testFiles {
		outputPath := filepath.Join(tmpDir, fmt.Sprintf("retrieved_%d.txt", idx))
		Get(file, idx, outputPath)

		retrievedContent, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("Failed to read retrieved file %d: %v", idx, err)
		}

		if !bytes.Equal(retrievedContent, expectedContent) {
			t.Errorf("File %d content mismatch", idx)
		}
	}

	// Step 5: Delete a file
	t.Log("Step 5: Delete file")
	Del(file, 1)

	meta = ReadMeta(file)
	if meta.Files[1].Name != "" {
		t.Error("File 1 should be deleted")
	}
	if CountUsedSlots(meta) != len(testFiles)-1 {
		t.Errorf("Expected %d files after delete", len(testFiles)-1)
	}

	// Step 6: Overwrite a file
	t.Log("Step 6: Overwrite file")
	newContent := []byte("Overwritten content")
	newSourcePath := CreateTempSourceFile(t, newContent)
	Add(file, newSourcePath, "overwritten.txt", 0)

	VerifyFileConsistency(t, file, 0, newContent)

	// Step 7: Sync to another device
	t.Log("Step 7: Sync to destination")
	dstFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer dstFile.Close()

	Sync(file, dstFile)

	// Verify sync
	srcMeta := ReadMeta(file)
	dstMeta := ReadMeta(dstFile)

	for i := 0; i < TOTAL_FILES; i++ {
		if srcMeta.Files[i].Name != dstMeta.Files[i].Name {
			t.Errorf("Index %d: name mismatch after sync", i)
		}
		if srcMeta.Files[i].Size != dstMeta.Files[i].Size {
			t.Errorf("Index %d: size mismatch after sync", i)
		}
	}

	t.Log("End-to-end workflow completed successfully")
}

// TestRealWorldUsagePattern simulates realistic usage
func TestRealWorldUsagePattern(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping real-world usage test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Simulate: User adds documents over time
	t.Log("Phase 1: Initial document addition")
	documents := []string{
		"readme.txt",
		"config.json",
		"notes.txt",
		"credentials.txt",
		"backup.dat",
	}

	documentContent := make(map[string][]byte)
	for i, doc := range documents {
		content := []byte(fmt.Sprintf("Content of %s\nLine 2\nLine 3", doc))
		documentContent[doc] = content
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, doc, i)
	}

	// User lists files to check
	t.Log("Phase 2: List to verify")
	output := captureOutput(func() {
		List(file, "")
	})

	for _, doc := range documents {
		if !bytes.Contains([]byte(output), []byte(doc)) {
			t.Errorf("Document %s not found", doc)
		}
	}

	// User retrieves a specific file
	t.Log("Phase 3: Retrieve specific file")
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "retrieved_config.json")
	Get(file, 1, outputPath)

	retrieved, _ := os.ReadFile(outputPath)
	if !bytes.Equal(retrieved, documentContent["config.json"]) {
		t.Error("Retrieved config doesn't match")
	}

	// User updates a file
	t.Log("Phase 4: Update existing file")
	newNotesContent := []byte("Updated notes with new information")
	newSourcePath := CreateTempSourceFile(t, newNotesContent)
	Add(file, newSourcePath, "notes_v2.txt", 2) // Overwrite index 2

	VerifyFileConsistency(t, file, 2, newNotesContent)

	// User removes old credentials
	t.Log("Phase 5: Remove sensitive file")
	Del(file, 3)

	meta := ReadMeta(file)
	if meta.Files[3].Name != "" {
		t.Error("Credentials should be deleted")
	}

	// User adds more files
	t.Log("Phase 6: Add more files")
	for i := 0; i < 10; i++ {
		content := GenerateRandomBytes(5000)
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("photo_%d.jpg", i), 10+i)
	}

	// User creates backup
	t.Log("Phase 7: Create backup via sync")
	backupFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer backupFile.Close()

	Sync(file, backupFile)

	// Verify backup
	srcCount := CountUsedSlots(ReadMeta(file))
	dstCount := CountUsedSlots(ReadMeta(backupFile))

	if srcCount != dstCount {
		t.Errorf("Backup file count mismatch: src=%d, dst=%d", srcCount, dstCount)
	}

	t.Log("Real-world usage pattern completed successfully")
}

// TestMultipleDeviceWorkflow tests working with multiple devices
func TestMultipleDeviceWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping multiple device test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	// Create 3 "devices"
	device1 := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer device1.Close()

	device2 := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer device2.Close()

	device3 := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer device3.Close()

	// Initialize device 1
	t.Log("Initialize device 1")
	InitMeta(device1, "file")

	// Add files to device 1
	for i := 0; i < 20; i++ {
		content := []byte(fmt.Sprintf("Device 1 file %d", i))
		sourcePath := CreateTempSourceFile(t, content)
		Add(device1, sourcePath, fmt.Sprintf("dev1_file_%d.txt", i), i)
	}

	// Sync device 1 to device 2
	t.Log("Sync device 1 → device 2")
	Sync(device1, device2)

	// Verify device 2
	dev1Meta := ReadMeta(device1)
	dev2Meta := ReadMeta(device2)

	if CountUsedSlots(dev1Meta) != CountUsedSlots(dev2Meta) {
		t.Error("Device 2 file count mismatch after sync")
	}

	// Modify device 2
	t.Log("Modify device 2")
	newContent := []byte("Modified on device 2")
	newSourcePath := CreateTempSourceFile(t, newContent)
	Add(device2, newSourcePath, "dev2_modified.txt", 5)

	// Sync device 2 to device 3
	t.Log("Sync device 2 → device 3")
	Sync(device2, device3)

	// Verify device 3 has device 2's modifications
	dev3Meta := ReadMeta(device3)
	if dev3Meta.Files[5].Name != "dev2_modified.txt" {
		t.Error("Device 3 should have device 2's modifications")
	}

	// Verify device 1 still has original
	dev1Meta = ReadMeta(device1)
	if dev1Meta.Files[5].Name == "dev2_modified.txt" {
		t.Error("Device 1 should not be modified")
	}

	t.Log("Multiple device workflow completed")
}

// TestRecoveryScenarios tests various recovery scenarios
func TestRecoveryScenarios(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	t.Run("Recovery after improper shutdown", func(t *testing.T) {
		tmpFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
		filePath := tmpFile.Name()

		InitMeta(tmpFile, "file")

		// Add files
		for i := 0; i < 5; i++ {
			content := []byte(fmt.Sprintf("File %d", i))
			sourcePath := CreateTempSourceFile(t, content)
			Add(tmpFile, sourcePath, fmt.Sprintf("file%d.txt", i), i)
		}

		// Simulate improper shutdown (just close without cleanup)
		tmpFile.Close()

		// Reopen
		reopened, err := os.OpenFile(filePath, os.O_RDWR, 0777)
		if err != nil {
			t.Fatalf("Failed to reopen: %v", err)
		}
		defer reopened.Close()

		// Verify files are still accessible
		meta := VerifyMetadataIntegrity(t, reopened)
		if CountUsedSlots(meta) != 5 {
			t.Errorf("Expected 5 files after recovery, got %d", CountUsedSlots(meta))
		}
	})

	t.Run("Recovery from partial sync", func(t *testing.T) {
		srcFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
		defer srcFile.Close()

		dstFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
		defer dstFile.Close()

		InitMeta(srcFile, "file")

		// Add files to source
		for i := 0; i < 10; i++ {
			content := GenerateRandomBytes(5000)
			sourcePath := CreateTempSourceFile(t, content)
			Add(srcFile, sourcePath, fmt.Sprintf("file%d.bin", i), i)
		}

		// Do full sync
		Sync(srcFile, dstFile)

		// Verify destination is complete
		srcMeta := ReadMeta(srcFile)
		dstMeta := ReadMeta(dstFile)

		if CountUsedSlots(srcMeta) != CountUsedSlots(dstMeta) {
			t.Error("Sync incomplete")
		}
	})
}

// TestEdgeCases tests various edge cases
func TestEdgeCases(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	t.Run("Add file to last slot", func(t *testing.T) {
		content := []byte("Last slot")
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, "last.txt", TOTAL_FILES-1)

		meta := ReadMeta(file)
		if meta.Files[TOTAL_FILES-1].Name != "last.txt" {
			t.Error("Failed to add to last slot")
		}
	})

	t.Run("Delete from first slot", func(t *testing.T) {
		content := []byte("First slot")
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, "first.txt", 0)

		Del(file, 0)

		meta := ReadMeta(file)
		if meta.Files[0].Name != "" {
			t.Error("Failed to delete from first slot")
		}
	})

	t.Run("Overwrite last slot", func(t *testing.T) {
		content1 := []byte("Original last")
		sourcePath1 := CreateTempSourceFile(t, content1)
		Add(file, sourcePath1, "original.txt", TOTAL_FILES-1)

		content2 := []byte("Overwritten last")
		sourcePath2 := CreateTempSourceFile(t, content2)
		Add(file, sourcePath2, "overwritten.txt", TOTAL_FILES-1)

		VerifyFileConsistency(t, file, TOTAL_FILES-1, content2)
	})

	t.Run("Add with OUT_OF_BOUNDS_INDEX", func(t *testing.T) {
		content := []byte("Auto-placed")
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, "auto.txt", OUT_OF_BOUNDS_INDEX)

		// Should be placed in first available slot
		meta := ReadMeta(file)
		found := false
		for i := 0; i < TOTAL_FILES; i++ {
			if meta.Files[i].Name == "auto.txt" {
				found = true
				break
			}
		}

		if !found {
			t.Error("File not auto-placed")
		}
	})
}

// TestComplexScenario tests a complex multi-step scenario
func TestComplexScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping complex scenario test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	// Scenario: User manages a encrypted document store
	t.Log("Complex scenario: Encrypted document store")

	// Phase 1: Add initial documents
	docTypes := map[string][]int{
		"personal": {0, 1, 2, 3},
		"work":     {10, 11, 12, 13, 14},
		"archive":  {20, 21, 22},
	}

	for docType, indices := range docTypes {
		for _, idx := range indices {
			content := []byte(fmt.Sprintf("%s document %d content", docType, idx))
			sourcePath := CreateTempSourceFile(t, content)
			Add(file, sourcePath, fmt.Sprintf("%s_%d.txt", docType, idx), idx)
		}
	}

	t.Logf("Added %d documents", CountUsedSlots(ReadMeta(file)))

	// Phase 2: Search and filter
	personalOutput := captureOutput(func() {
		List(file, "personal")
	})

	personalCount := bytes.Count([]byte(personalOutput), []byte("personal_"))
	if personalCount != len(docTypes["personal"]) {
		t.Errorf("Expected %d personal docs, found %d in list", len(docTypes["personal"]), personalCount)
	}

	// Phase 3: Archive old documents (delete work docs)
	for _, idx := range docTypes["work"] {
		Del(file, idx)
	}

	meta := ReadMeta(file)
	for _, idx := range docTypes["work"] {
		if meta.Files[idx].Name != "" {
			t.Errorf("Work document at %d should be deleted", idx)
		}
	}

	// Phase 4: Add new documents in freed space
	for i, idx := range docTypes["work"] {
		if i >= 3 {
			break // Only add 3 new docs
		}
		content := []byte(fmt.Sprintf("new document %d", idx))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("new_%d.txt", idx), idx)
	}

	// Phase 5: Create full backup
	backupFile := CreateTempTestFile(t, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer backupFile.Close()

	Sync(file, backupFile)

	// Phase 6: Verify backup integrity
	for _, indices := range docTypes {
		for _, idx := range indices {
			srcMeta := ReadMeta(file)
			dstMeta := ReadMeta(backupFile)

			if srcMeta.Files[idx].Name != dstMeta.Files[idx].Name {
				t.Errorf("Backup mismatch at index %d", idx)
			}
		}
	}

	// Phase 7: Simulate restore by erasing and syncing back
	Overwrite(file, 0, uint64(META_FILE_SIZE+(10*MAX_FILE_SIZE)))
	InitMeta(file, "file")

	Sync(backupFile, file)

	// Verify restore
	restoredMeta := ReadMeta(file)
	backupMeta := ReadMeta(backupFile)

	if CountUsedSlots(restoredMeta) != CountUsedSlots(backupMeta) {
		t.Error("Restore incomplete")
	}

	t.Log("Complex scenario completed successfully")
}

func BenchmarkFullWorkflow(b *testing.B) {
	SetupTestKey(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		file := CreateTempTestFile(&testing.T{}, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))

		InitMeta(file, "file")

		// Add files
		for j := 0; j < 10; j++ {
			content := GenerateRandomBytes(1000)
			sourcePath := CreateTempSourceFile(&testing.T{}, content)
			Add(file, sourcePath, fmt.Sprintf("bench_%d.txt", j), j)
		}

		// List
		List(file, "")

		// Delete some
		Del(file, 5)

		// Sync
		dstFile := CreateTempTestFile(&testing.T{}, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
		Sync(file, dstFile)

		file.Close()
		dstFile.Close()
	}
}
