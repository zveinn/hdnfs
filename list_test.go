package hdnfs

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// captureOutput captures stdout output from a function
func captureOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestListEmpty(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)
 // Cleanup handled by GetSharedTestFile

	InitMeta(file, "file")

	// Capture output
	output := captureOutput(func() {
		List(file, "")
	})

	// Should show header but no files
	if !strings.Contains(output, "FILE LIST") {
		t.Error("Missing header in empty list output")
	}

	// Should not contain any file entries (just header and borders)
	lines := strings.Split(output, "\n")
	fileLines := 0
	for _, line := range lines {
		// Count lines that look like file entries (start with space and have digits)
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
			// Could be header or file entry
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
 // Cleanup handled by GetSharedTestFile

	InitMeta(file, "file")

	// Add test files
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
		Add(file, sourcePath, tf.name, tf.index)
	}

	// Capture list output
	output := captureOutput(func() {
		List(file, "")
	})

	// Verify all files appear in output
	for _, tf := range testFiles {
		if !strings.Contains(output, tf.name) {
			t.Errorf("File %s not found in list output", tf.name)
		}
	}

	// Verify indices are shown
	for _, tf := range testFiles {
		indexStr := fmt.Sprintf(" %d ", tf.index)
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
 // Cleanup handled by GetSharedTestFile

	InitMeta(file, "file")

	// Add files with different extensions
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
		Add(file, sourcePath, tf.name, i)
	}

	tests := []struct {
		filter   string
		expected []string
		excluded []string
	}{
		{
			filter:   "txt",
			expected: []string{"document1.txt", "document2.txt"},
			excluded: []string{"image1.jpg", "image2.jpg", "data.csv"},
		},
		{
			filter:   "jpg",
			expected: []string{"image1.jpg", "image2.jpg"},
			excluded: []string{"document1.txt", "document2.txt", "data.csv"},
		},
		{
			filter:   "document",
			expected: []string{"document1.txt", "document2.txt"},
			excluded: []string{"image1.jpg", "image2.jpg", "data.csv"},
		},
		{
			filter:   "image",
			expected: []string{"image1.jpg", "image2.jpg"},
			excluded: []string{"document1.txt", "document2.txt", "data.csv"},
		},
		{
			filter:   "data",
			expected: []string{"data.csv"},
			excluded: []string{"document1.txt", "document2.txt", "image1.jpg", "image2.jpg"},
		},
		{
			filter:   "nonexistent",
			expected: []string{},
			excluded: []string{"document1.txt", "document2.txt", "image1.jpg", "image2.jpg", "data.csv"},
		},
	}

	for _, tt := range tests {
		t.Run("filter_"+tt.filter, func(t *testing.T) {
			output := captureOutput(func() {
				List(file, tt.filter)
			})

			// Check expected files are present
			for _, exp := range tt.expected {
				if !strings.Contains(output, exp) {
					t.Errorf("Expected file %s not found in filtered output", exp)
				}
			}

			// Check excluded files are not present
			for _, exc := range tt.excluded {
				if strings.Contains(output, exc) {
					t.Errorf("Excluded file %s found in filtered output", exc)
				}
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
 // Cleanup handled by GetSharedTestFile

	InitMeta(file, "file")

	// Add 100 files
	numFiles := 100
	for i := 0; i < numFiles; i++ {
		content := []byte(fmt.Sprintf("content %d", i))
		sourcePath := CreateTempSourceFile(t, content)
		name := fmt.Sprintf("file_%03d.txt", i)
		Add(file, sourcePath, name, i)
	}

	// List all
	output := captureOutput(func() {
		List(file, "")
	})

	// Verify all files are listed
	for i := 0; i < numFiles; i++ {
		name := fmt.Sprintf("file_%03d.txt", i)
		if !strings.Contains(output, name) {
			t.Errorf("File %s not found in list", name)
		}
	}
}

func TestListAfterDelete(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)
 // Cleanup handled by GetSharedTestFile

	InitMeta(file, "file")

	// Add files
	for i := 0; i < 5; i++ {
		content := []byte(fmt.Sprintf("file %d", i))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("file%d.txt", i), i)
	}

	// Delete some files
	Del(file, 1)
	Del(file, 3)

	// List should not show deleted files
	output := captureOutput(func() {
		List(file, "")
	})

	if strings.Contains(output, "file1.txt") {
		t.Error("Deleted file1.txt should not appear in list")
	}
	if strings.Contains(output, "file3.txt") {
		t.Error("Deleted file3.txt should not appear in list")
	}

	// Should still show non-deleted files
	if !strings.Contains(output, "file0.txt") {
		t.Error("file0.txt should appear in list")
	}
	if !strings.Contains(output, "file2.txt") {
		t.Error("file2.txt should appear in list")
	}
	if !strings.Contains(output, "file4.txt") {
		t.Error("file4.txt should appear in list")
	}
}

func TestListWithSpecialCharacters(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)
 // Cleanup handled by GetSharedTestFile

	InitMeta(file, "file")

	// Add files with special characters
	specialFiles := []string{
		"file with spaces.txt",
		"file-with-dashes.txt",
		"file_with_underscores.txt",
		"file.multiple.dots.txt",
	}

	for i, name := range specialFiles {
		content := []byte(fmt.Sprintf("content %d", i))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, name, i)
	}

	output := captureOutput(func() {
		List(file, "")
	})

	for _, name := range specialFiles {
		if !strings.Contains(output, name) {
			t.Errorf("Special filename %s not found in list", name)
		}
	}
}

func TestListFilterCaseSensitive(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)
 // Cleanup handled by GetSharedTestFile

	InitMeta(file, "file")

	// Add files with different cases
	files := []string{"File.txt", "file.txt", "FILE.txt"}
	for i, name := range files {
		content := []byte(fmt.Sprintf("content %d", i))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, name, i)
	}

	// Test case-sensitive filter
	tests := []struct {
		filter   string
		expected []string
		excluded []string
	}{
		{
			filter:   "File",
			expected: []string{"File.txt"},
			excluded: []string{"file.txt", "FILE.txt"},
		},
		{
			filter:   "file",
			expected: []string{"file.txt"},
			excluded: []string{"File.txt", "FILE.txt"},
		},
		{
			filter:   "FILE",
			expected: []string{"FILE.txt"},
			excluded: []string{"File.txt", "file.txt"},
		},
	}

	for _, tt := range tests {
		t.Run("case_"+tt.filter, func(t *testing.T) {
			output := captureOutput(func() {
				List(file, tt.filter)
			})

			for _, exp := range tt.expected {
				if !strings.Contains(output, exp) {
					t.Errorf("Expected %s in output", exp)
				}
			}

			for _, exc := range tt.excluded {
				if strings.Contains(output, exc) {
					t.Errorf("Should not contain %s in output", exc)
				}
			}
		})
	}
}

func TestListOutputFormat(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)
 // Cleanup handled by GetSharedTestFile

	InitMeta(file, "file")

	// Add a file
	content := []byte("test content")
	sourcePath := CreateTempSourceFile(t, content)
	Add(file, sourcePath, "test.txt", 5)

	output := captureOutput(func() {
		List(file, "")
	})

	// Check for expected formatting elements
	if !strings.Contains(output, "FILE LIST") {
		t.Error("Missing 'FILE LIST' header")
	}

	if !strings.Contains(output, "index") {
		t.Error("Missing 'index' column header")
	}

	if !strings.Contains(output, "size") {
		t.Error("Missing 'size' column header")
	}

	if !strings.Contains(output, "name") {
		t.Error("Missing 'name' column header")
	}

	// Check for separator lines
	if !strings.Contains(output, "---") {
		t.Error("Missing separator lines")
	}
}

func TestListEmptyFilter(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)
 // Cleanup handled by GetSharedTestFile

	InitMeta(file, "file")

	// Add files
	for i := 0; i < 3; i++ {
		content := []byte(fmt.Sprintf("content %d", i))
		sourcePath := CreateTempSourceFile(t, content)
		Add(file, sourcePath, fmt.Sprintf("file%d.txt", i), i)
	}

	// Empty filter should show all files
	outputAll := captureOutput(func() {
		List(file, "")
	})

	// All files should be present
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

	// Add 100 files
	for i := 0; i < 100; i++ {
		content := []byte(fmt.Sprintf("content %d", i))
		sourcePath := CreateTempSourceFile(&testing.T{}, content)
		Add(file, sourcePath, fmt.Sprintf("file%d.txt", i), i)
	}

	// Redirect stdout to /dev/null for benchmark
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

	// Add 100 files with different patterns
	for i := 0; i < 100; i++ {
		content := []byte(fmt.Sprintf("content %d", i))
		sourcePath := CreateTempSourceFile(&testing.T{}, content)
		ext := "txt"
		if i%2 == 0 {
			ext = "doc"
		}
		Add(file, sourcePath, fmt.Sprintf("file%d.%s", i, ext), i)
	}

	// Redirect stdout to /dev/null for benchmark
	old := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = old }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		List(file, "doc")
	}
}
