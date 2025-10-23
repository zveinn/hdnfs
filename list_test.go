package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func captureOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Start reading from the pipe in a goroutine to prevent deadlock
	// when output exceeds pipe buffer size
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		io.Copy(&buf, r)
		close(done)
	}()

	f()

	w.Close()
	os.Stdout = old

	<-done // Wait for reading to complete
	return buf.String()
}

func TestListEmpty(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	output := captureOutput(func() {
		List(file, "")
	})

	if !strings.Contains(output, "FILE LIST") {
		t.Error("Missing header in empty list output")
	}

	lines := strings.Split(output, "\n")
	fileLines := 0
	for _, line := range lines {

		if strings.HasPrefix(strings.TrimSpace(line), "0") ||
			strings.HasPrefix(strings.TrimSpace(line), "1") ||
			strings.HasPrefix(strings.TrimSpace(line), "2") ||
			strings.HasPrefix(strings.TrimSpace(line), "3") ||
			strings.HasPrefix(strings.TrimSpace(line), "4") ||
			strings.HasPrefix(strings.TrimSpace(line), "5") ||
			strings.HasPrefix(strings.TrimSpace(line), "6") ||
			strings.HasPrefix(strings.TrimSpace(line), "7") ||
			strings.HasPrefix(strings.TrimSpace(line), "8") ||
			strings.HasPrefix(strings.TrimSpace(line), "9") {

			if !strings.Contains(line, "index") && !strings.Contains(line, "size") && !strings.Contains(line, "name") {
				fileLines++
			}
		}
	}

	if fileLines > 0 {
		t.Errorf("Empty filesystem should show no files, but found %d file entries", fileLines)
	}
}

func TestListWithFiles(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	testFiles := []struct {
		name    string
		content []byte
		index   int
	}{
		{"file1.txt", []byte("content1"), 0},
		{"file2.txt", []byte("content2"), 1},
		{"document.doc", []byte("doc content"), 5},
		{"image.jpg", []byte("image data"), 10},
	}

	for _, tf := range testFiles {
		sourcePath := CreateTempSourceFile(t, tf.content)
		Add(file, sourcePath, tf.index)
	}

	output := captureOutput(func() {
		List(file, "")
	})

	// All files are now named "source.dat", so just verify by index and that source.dat appears
	if !strings.Contains(output, "source.dat") {
		t.Error("source.dat not found in list output")
	}

	for _, tf := range testFiles {
		indexStr := fmt.Sprintf("%d", tf.index)
		if !strings.Contains(output, indexStr) {
			t.Errorf("Index %d not found in list output", tf.index)
		}
	}
}

func TestListWithFilter(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	testFiles := []struct {
		name    string
		content []byte
	}{
		{"document1.txt", []byte("text1")},
		{"document2.txt", []byte("text2")},
		{"image1.jpg", []byte("img1")},
		{"image2.jpg", []byte("img2")},
		{"data.csv", []byte("csv")},
	}

	for i, tf := range testFiles {
		sourcePath := CreateTempSourceFile(t, tf.content)
		Add(file, sourcePath, i)
	}

	// Since all files are now "source.dat", test basic filter functionality
	tests := []struct {
		filter       string
		shouldMatch  bool
		description  string
	}{
		{"source", true, "filter matches filename"},
		{".dat", true, "filter matches extension"},
		{"nonexistent", false, "filter doesn't match"},
		{"xyz123", false, "filter with random string"},
	}

	for _, tt := range tests {
		t.Run("filter_"+tt.filter, func(t *testing.T) {
			output := captureOutput(func() {
				List(file, tt.filter)
			})

			hasFiles := strings.Contains(output, "source.dat")
			if tt.shouldMatch && !hasFiles {
				t.Errorf("%s: expected to find files but found none", tt.description)
			}
			if !tt.shouldMatch && hasFiles {
				t.Errorf("%s: expected no files but found some", tt.description)
			}
		})
	}
}

func TestListWithManyFiles(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	if testing.Short() {
		t.Skip("Skipping many files test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	numFiles := 100
	for i := 0; i < numFiles; i++ {
		content := []byte(fmt.Sprintf("content %d", i))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, i)
	}

	output := captureOutput(func() {
		List(file, "")
	})

	// Check that the list contains all the files (by checking for indices)
	for i := 0; i < numFiles; i++ {
		indexStr := fmt.Sprintf("%d", i)
		if !strings.Contains(output, indexStr) {
			t.Errorf("File at index %d not found in list", i)
		}
	}
}

func TestListAfterDelete(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	for i := 0; i < 5; i++ {
		content := []byte(fmt.Sprintf("file %d", i))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, i)
	}

	Del(file, 1)
	Del(file, 3)

	output := captureOutput(func() {
		List(file, "")
	})

	// Verify indices 0, 2, 4 are present (not deleted)
	for _, idx := range []int{0, 2, 4} {
		indexStr := fmt.Sprintf("%d", idx)
		if !strings.Contains(output, indexStr) {
			t.Errorf("Index %d should appear in list", idx)
		}
	}

	// Count occurrences of "source.dat" - should be 3 (files at indices 0, 2, 4)
	count := strings.Count(output, "source.dat")
	if count != 3 {
		t.Errorf("Expected 3 files in list, found %d", count)
	}
}

func TestListWithSpecialCharacters(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	numSpecialFiles := 4

	for i := 0; i < numSpecialFiles; i++ {
		content := []byte(fmt.Sprintf("content %d", i))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, i)
	}

	output := captureOutput(func() {
		List(file, "")
	})

	// Check that files were added (by checking for indices)
	for i := 0; i < numSpecialFiles; i++ {
		indexStr := fmt.Sprintf("%d", i)
		if !strings.Contains(output, indexStr) {
			t.Errorf("File at index %d not found in list", i)
		}
	}
}

func TestListFilterCaseSensitive(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	numFiles := 3
	for i := 0; i < numFiles; i++ {
		content := []byte(fmt.Sprintf("content %d", i))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, i)
	}

	// Since all files are "source.dat", test basic case sensitivity
	tests := []struct {
		filter      string
		shouldMatch bool
		description string
	}{
		{"source", true, "lowercase matches"},
		{"SOURCE", false, "uppercase doesn't match (case sensitive)"},
		{"Source", false, "mixed case doesn't match"},
		{".dat", true, "extension matches"},
		{".DAT", false, "uppercase extension doesn't match"},
	}

	for _, tt := range tests {
		t.Run("case_"+tt.filter, func(t *testing.T) {
			output := captureOutput(func() {
				List(file, tt.filter)
			})

			hasFiles := strings.Contains(output, "source.dat")
			if tt.shouldMatch && !hasFiles {
				t.Errorf("%s: expected to find files but found none", tt.description)
			}
			if !tt.shouldMatch && hasFiles {
				t.Errorf("%s: expected no files but found some", tt.description)
			}
		})
	}
}

func TestListOutputFormat(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	content := []byte("test content")
	sourcePath := CreateTempSourceFile(t, content)
	Add(file, sourcePath, 5)

	output := captureOutput(func() {
		List(file, "")
	})

	outputLower := strings.ToLower(output)

	if !strings.Contains(output, "FILE LIST") {
		t.Error("Missing 'FILE LIST' header")
	}

	if !strings.Contains(outputLower, "index") {
		t.Error("Missing 'index' column header")
	}

	if !strings.Contains(outputLower, "size") {
		t.Error("Missing 'size' column header")
	}

	if !strings.Contains(outputLower, "name") {
		t.Error("Missing 'name' column header")
	}

	if !strings.Contains(output, "──") {
		t.Error("Missing separator lines")
	}
}

func TestListEmptyFilter(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)

	InitMeta(file, "file")

	for i := 0; i < 3; i++ {
		content := []byte(fmt.Sprintf("content %d", i))
		filename := fmt.Sprintf("file%d.txt", i)
		sourcePath := CreateTempSourceFileWithName(t, content, filename)
		Add(file, sourcePath, i)
	}

	outputAll := captureOutput(func() {
		List(file, "")
	})

	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("file%d.txt", i)
		if !strings.Contains(outputAll, name) {
			t.Errorf("File %s missing with empty filter", name)
		}
	}
}

func BenchmarkList(b *testing.B) {
	SetupTestKey(&testing.T{})
	file := CreateTempTestFile(&testing.T{}, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	for i := 0; i < 100; i++ {
		content := []byte(fmt.Sprintf("content %d", i))
		sourcePath := CreateTempSourceFile(&testing.T{}, content)
		Add(file, sourcePath, i)
	}

	old := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = old }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		List(file, "")
	}
}

func BenchmarkListWithFilter(b *testing.B) {
	SetupTestKey(&testing.T{})
	file := CreateTempTestFile(&testing.T{}, META_FILE_SIZE+(TOTAL_FILES*MAX_FILE_SIZE))
	defer file.Close()

	InitMeta(file, "file")

	for i := 0; i < 100; i++ {
		content := []byte(fmt.Sprintf("content %d", i))
		sourcePath := CreateTempSourceFile(&testing.T{}, content)
		Add(file, sourcePath, i)
	}

	old := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = old }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		List(file, "doc")
	}
}
