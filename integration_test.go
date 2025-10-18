package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEndToEndWorkflow(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	t.Log("Step 1: Initialize filesystem")
	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("InitMeta failed: %v", err)
	}

	meta := VerifyMetadataIntegrity(t, file)
	if CountUsedSlots(meta) != 0 {
		t.Fatal("Initial filesystem should be empty")
	}

	t.Log("Step 2: Add files")
	testFiles := map[int][]byte{
		0: []byte("First file content"),
		1: []byte("Second file with more content"),
		5: []byte("File at index 5"),
		10: GenerateRandomBytes(10000),
	}

	for idx, content := range testFiles {
		sourcePath := CreateTempSourceFile(t, content)
		if err := Add(file, sourcePath, fmt.Sprintf("file_%d.txt", idx), idx); err != nil {
			t.Fatalf("Add failed for file %d: %v", idx, err)
		}
	}

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if CountUsedSlots(meta) != len(testFiles) {
		t.Errorf("Expected %d files, got %d", len(testFiles), CountUsedSlots(meta))
	}

	t.Log("Step 3: List files")
	output := captureOutput(func() {
		if err := List(file, ""); err != nil {
			t.Errorf("List failed: %v", err)
		}
	})

	for idx := range testFiles {
		filename := fmt.Sprintf("file_%d.txt", idx)
		if !bytes.Contains([]byte(output), []byte(filename)) {
			t.Errorf("File %s not found in list", filename)
		}
	}

	t.Log("Step 4: Retrieve files")
	tmpDir := t.TempDir()
	for idx, expectedContent := range testFiles {
		outputPath := filepath.Join(tmpDir, fmt.Sprintf("retrieved_%d.txt", idx))
		if err := Get(file, idx, outputPath); err != nil {
			t.Fatalf("Get failed for file %d: %v", idx, err)
		}

		retrievedContent, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("Failed to read retrieved file %d: %v", idx, err)
		}

		if !bytes.Equal(retrievedContent, expectedContent) {
			t.Errorf("File %d content mismatch", idx)
		}
	}

	t.Log("Step 5: Delete file")
	if err := Del(file, 1); err != nil {
		t.Fatalf("Del failed: %v", err)
	}

	meta, err = ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if meta.Files[1].Name != "" {
		t.Error("File 1 should be deleted")
	}
	if CountUsedSlots(meta) != len(testFiles)-1 {
		t.Errorf("Expected %d files after delete", len(testFiles)-1)
	}

	t.Log("Step 6: Overwrite file")
	newContent := []byte("Overwritten content")
	newSourcePath := CreateTempSourceFile(t, newContent)
	if err := Add(file, newSourcePath, "overwritten.txt", 0); err != nil {
		t.Fatalf("Add failed for overwrite: %v", err)
	}

	VerifyFileConsistency(t, file, 0, newContent)

	t.Log("Step 7: Sync to destination")
	dstFile := GetSharedTestFile(t)

	if err := Sync(file, dstFile); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	srcMeta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed for source: %v", err)
	}
	dstMeta, err := ReadMeta(dstFile)
	if err != nil {
		t.Fatalf("ReadMeta failed for destination: %v", err)
	}

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

func TestRealWorldUsagePattern(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping real-world usage test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

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

	t.Log("Phase 2: List to verify")
	output := captureOutput(func() {
		List(file, "")
	})

	for _, doc := range documents {
		if !bytes.Contains([]byte(output), []byte(doc)) {
			t.Errorf("Document %s not found", doc)
		}
	}

	t.Log("Phase 3: Retrieve specific file")
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "retrieved_config.json")
	Get(file, 1, outputPath)

	retrieved, _ := os.ReadFile(outputPath)
	if !bytes.Equal(retrieved, documentContent["config.json"]) {
		t.Error("Retrieved config doesn't match")
	}

	t.Log("Phase 4: Update existing file")
	newNotesContent := []byte("Updated notes with new information")
	newSourcePath := CreateTempSourceFile(t, newNotesContent)
	Add(file, newSourcePath, "notes_v2.txt", 2)

	VerifyFileConsistency(t, file, 2, newNotesContent)

	t.Log("Phase 5: Remove sensitive file")
	Del(file, 3)

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if meta.Files[3].Name != "" {
		t.Error("Credentials should be deleted")
	}

	t.Log("Phase 6: Add more files")
	for i := 0; i < 10; i++ {
		content := GenerateRandomBytes(5000)
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("photo_%d.jpg", i), 10+i)
	}

	t.Log("Phase 7: Create backup via sync")
	backupFile := GetSharedTestFile(t)

	Sync(file, backupFile)

	srcMeta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed for source: %v", err)
	}
	backupMeta, err := ReadMeta(backupFile)
	if err != nil {
		t.Fatalf("ReadMeta failed for backup: %v", err)
	}
	srcCount := CountUsedSlots(srcMeta)
	dstCount := CountUsedSlots(backupMeta)

	if srcCount != dstCount {
		t.Errorf("Backup file count mismatch: src=%d, dst=%d", srcCount, dstCount)
	}

	t.Log("Real-world usage pattern completed successfully")
}

func TestMultipleDeviceWorkflow(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping multiple device test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	device1 := GetSharedTestFile(t)

	device2 := GetSharedTestFile(t)

	device3 := GetSharedTestFile(t)

	t.Log("Initialize device 1")
	InitMeta(device1, "file")

	for i := 0; i < 20; i++ {
		content := []byte(fmt.Sprintf("Device 1 file %d", i))
		sourcePath := CreateTempSourceFile(t, content)
		Add(device1, sourcePath, fmt.Sprintf("dev1_file_%d.txt", i), i)
	}

	t.Log("Sync device 1 → device 2")
	Sync(device1, device2)

	dev1Meta, err := ReadMeta(device1)
	if err != nil {
		t.Fatalf("ReadMeta failed for device1: %v", err)
	}
	dev2Meta, err := ReadMeta(device2)
	if err != nil {
		t.Fatalf("ReadMeta failed for device2: %v", err)
	}

	if CountUsedSlots(dev1Meta) != CountUsedSlots(dev2Meta) {
		t.Error("Device 2 file count mismatch after sync")
	}

	t.Log("Modify device 2")
	newContent := []byte("Modified on device 2")
	newSourcePath := CreateTempSourceFile(t, newContent)
	Add(device2, newSourcePath, "dev2_modified.txt", 5)

	t.Log("Sync device 2 → device 3")
	Sync(device2, device3)

	dev3Meta, err := ReadMeta(device3)
	if err != nil {
		t.Fatalf("ReadMeta failed for device3: %v", err)
	}
	if dev3Meta.Files[5].Name != "dev2_modified.txt" {
		t.Error("Device 3 should have device 2's modifications")
	}

	dev1Meta, err = ReadMeta(device1)
	if err != nil {
		t.Fatalf("ReadMeta failed for device1: %v", err)
	}
	if dev1Meta.Files[5].Name == "dev2_modified.txt" {
		t.Error("Device 1 should not be modified")
	}

	t.Log("Multiple device workflow completed")
}

func TestRecoveryScenarios(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	t.Run("Recovery after improper shutdown", func(t *testing.T) {
		tmpFile := GetSharedTestFile(t)
		filePath := tmpFile.Name()

		InitMeta(tmpFile, "file")

		for i := 0; i < 5; i++ {
			content := []byte(fmt.Sprintf("File %d", i))
			sourcePath := CreateTempSourceFile(t, content)
			Add(tmpFile, sourcePath, fmt.Sprintf("file%d.txt", i), i)
		}

		tmpFile.Close()

		reopened, err := os.OpenFile(filePath, os.O_RDWR, 0777)
		if err != nil {
			t.Fatalf("Failed to reopen: %v", err)
		}
		defer reopened.Close()

		meta := VerifyMetadataIntegrity(t, reopened)
		if CountUsedSlots(meta) != 5 {
			t.Errorf("Expected 5 files after recovery, got %d", CountUsedSlots(meta))
		}
	})

	t.Run("Recovery from partial sync", func(t *testing.T) {
		srcFile := GetSharedTestFile(t)

		dstFile := GetSharedTestFile(t)

		InitMeta(srcFile, "file")

		for i := 0; i < 10; i++ {
			content := GenerateRandomBytes(5000)
			sourcePath := CreateTempSourceFile(t, content)
			Add(srcFile, sourcePath, fmt.Sprintf("file%d.bin", i), i)
		}

		Sync(srcFile, dstFile)

		srcMeta, err := ReadMeta(srcFile)
		if err != nil {
			t.Fatalf("ReadMeta failed for source: %v", err)
		}
		dstMeta, err := ReadMeta(dstFile)
		if err != nil {
			t.Fatalf("ReadMeta failed for destination: %v", err)
		}

		if CountUsedSlots(srcMeta) != CountUsedSlots(dstMeta) {
			t.Error("Sync incomplete")
		}
	})
}

func TestEdgeCases(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	t.Run("Add file to last slot", func(t *testing.T) {
		content := []byte("Last slot")
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, "last.txt", TOTAL_FILES-1)

		meta, err := ReadMeta(file)
		if err != nil {
			t.Fatalf("ReadMeta failed: %v", err)
		}
		if meta.Files[TOTAL_FILES-1].Name != "last.txt" {
			t.Error("Failed to add to last slot")
		}
	})

	t.Run("Delete from first slot", func(t *testing.T) {
		content := []byte("First slot")
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, "first.txt", 0)

		Del(file, 0)

		meta, err := ReadMeta(file)
		if err != nil {
			t.Fatalf("ReadMeta failed: %v", err)
		}
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

		meta, err := ReadMeta(file)
		if err != nil {
			t.Fatalf("ReadMeta failed: %v", err)
		}
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

func TestComplexScenario(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping complex scenario test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	t.Log("Complex scenario: Encrypted document store")

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

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	t.Logf("Added %d documents", CountUsedSlots(meta))

	personalOutput := captureOutput(func() {
		List(file, "personal")
	})

	personalCount := bytes.Count([]byte(personalOutput), []byte("personal_"))
	if personalCount != len(docTypes["personal"]) {
		t.Errorf("Expected %d personal docs, found %d in list", len(docTypes["personal"]), personalCount)
	}

	for _, idx := range docTypes["work"] {
		Del(file, idx)
	}

	meta, err = ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	for _, idx := range docTypes["work"] {
		if meta.Files[idx].Name != "" {
			t.Errorf("Work document at %d should be deleted", idx)
		}
	}

	for i, idx := range docTypes["work"] {
		if i >= 3 {
			break
		}
		content := []byte(fmt.Sprintf("new document %d", idx))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("new_%d.txt", idx), idx)
	}

	backupFile := GetSharedTestFile(t)

	Sync(file, backupFile)

	for _, indices := range docTypes {
		for _, idx := range indices {
			srcMeta, err := ReadMeta(file)
			if err != nil {
				t.Fatalf("ReadMeta failed for source: %v", err)
			}
			dstMeta, err := ReadMeta(backupFile)
			if err != nil {
				t.Fatalf("ReadMeta failed for backup: %v", err)
			}

			if srcMeta.Files[idx].Name != dstMeta.Files[idx].Name {
				t.Errorf("Backup mismatch at index %d", idx)
			}
		}
	}

	Overwrite(file, 0, uint64(META_FILE_SIZE+(10*MAX_FILE_SIZE)))
	InitMeta(file, "file")

	Sync(backupFile, file)

	restoredMeta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed for restored file: %v", err)
	}
	backupMeta, err := ReadMeta(backupFile)
	if err != nil {
		t.Fatalf("ReadMeta failed for backup file: %v", err)
	}

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

		for j := 0; j < 10; j++ {
			content := GenerateRandomBytes(1000)
			sourcePath := CreateTempSourceFile(&testing.T{}, content)
			Add(file, sourcePath, fmt.Sprintf("bench_%d.txt", j), j)
		}

		List(file, "")

		Del(file, 5)

		dstFile := CreateTempTestFile(&testing.T{}, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
		Sync(file, dstFile)

		file.Close()
		dstFile.Close()
	}
}
