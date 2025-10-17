package hdnfs

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// MockFile implements the F interface for testing
type MockFile struct {
	data     []byte
	position int64
	closed   bool
}

// NewMockFile creates a new mock file with specified size
func NewMockFile(size int) *MockFile {
	return &MockFile{
		data:     make([]byte, size),
		position: 0,
		closed:   false,
	}
}

// NewMockFileWithData creates a mock file with existing data
func NewMockFileWithData(data []byte) *MockFile {
	return &MockFile{
		data:     data,
		position: 0,
		closed:   false,
	}
}

func (m *MockFile) Write(p []byte) (n int, err error) {
	if m.closed {
		return 0, os.ErrClosed
	}

	// Expand buffer if needed
	needed := int(m.position) + len(p)
	if needed > len(m.data) {
		newData := make([]byte, needed)
		copy(newData, m.data)
		m.data = newData
	}

	n = copy(m.data[m.position:], p)
	m.position += int64(n)
	return n, nil
}

func (m *MockFile) Read(p []byte) (n int, err error) {
	if m.closed {
		return 0, os.ErrClosed
	}

	if m.position >= int64(len(m.data)) {
		return 0, io.EOF
	}

	n = copy(p, m.data[m.position:])
	m.position += int64(n)

	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (m *MockFile) Seek(offset int64, whence int) (int64, error) {
	if m.closed {
		return 0, os.ErrClosed
	}

	var newPos int64
	switch whence {
	case 0: // io.SeekStart
		newPos = offset
	case 1: // io.SeekCurrent
		newPos = m.position + offset
	case 2: // io.SeekEnd
		newPos = int64(len(m.data)) + offset
	default:
		return 0, fmt.Errorf("invalid whence: %d", whence)
	}

	if newPos < 0 {
		return 0, fmt.Errorf("negative position: %d", newPos)
	}

	m.position = newPos
	return m.position, nil
}

func (m *MockFile) Name() string {
	return "mock_file"
}

func (m *MockFile) Sync() error {
	if m.closed {
		return os.ErrClosed
	}
	return nil
}

func (m *MockFile) Close() error {
	m.closed = true
	return nil
}

// GetData returns the internal data buffer
func (m *MockFile) GetData() []byte {
	return m.data
}

// CreateTempTestFile creates a real temporary file for testing
func CreateTempTestFile(t *testing.T, size int64) *os.File {
	t.Helper()
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_device.dat")

	file, err := os.Create(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	// Pre-allocate space
	if size > 0 {
		if err := file.Truncate(size); err != nil {
			file.Close()
			t.Fatalf("Failed to truncate file: %v", err)
		}
	}

	// Reset to beginning
	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		t.Fatalf("Failed to seek: %v", err)
	}

	return file
}

// CreateTempSourceFile creates a temporary source file with content
func CreateTempSourceFile(t *testing.T, content []byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "source.dat")

	if err := os.WriteFile(tmpFile, content, 0o644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	return tmpFile
}

// GenerateRandomBytes generates random bytes for testing
func GenerateRandomBytes(size int) []byte {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		panic(fmt.Sprintf("Failed to generate random bytes: %v", err))
	}
	return data
}

// SetupTestKey sets up a test encryption key
func SetupTestKey(t *testing.T) {
	t.Helper()
	testKey := "test-password-for-testing" // Test password
	os.Setenv(HDNFS_ENV, testKey)
}

// CleanupTestKey clears the test encryption key
func CleanupTestKey(t *testing.T) {
	t.Helper()
	os.Unsetenv(HDNFS_ENV)
}

// CompareFiles compares two files byte by byte
func CompareFiles(t *testing.T, file1, file2 string) bool {
	t.Helper()

	data1, err := os.ReadFile(file1)
	if err != nil {
		t.Errorf("Failed to read file1: %v", err)
		return false
	}

	data2, err := os.ReadFile(file2)
	if err != nil {
		t.Errorf("Failed to read file2: %v", err)
		return false
	}

	return bytes.Equal(data1, data2)
}

// VerifyMetadataIntegrity verifies that metadata can be read and is consistent
func VerifyMetadataIntegrity(t *testing.T, file F) *Meta {
	t.Helper()

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("Failed to read metadata: %v", err)
	}
	if meta == nil {
		t.Fatal("Metadata is nil")
	}

	// Verify structure integrity
	if len(meta.Files) != TOTAL_FILES {
		t.Errorf("Invalid metadata: expected %d file slots, got %d", TOTAL_FILES, len(meta.Files))
	}

	// Verify file entries are valid
	for i, f := range meta.Files {
		if len(f.Name) > MAX_FILE_NAME_SIZE {
			t.Errorf("File at index %d has name too long: %d bytes", i, len(f.Name))
		}
		if f.Size < 0 || f.Size > MAX_FILE_SIZE {
			t.Errorf("File at index %d has invalid size: %d", i, f.Size)
		}
	}

	return meta
}

// VerifyFileConsistency verifies that a file stored at an index matches expected content
func VerifyFileConsistency(t *testing.T, file F, index int, expectedContent []byte) {
	t.Helper()

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("Failed to read metadata: %v", err)
	}
	if meta == nil {
		t.Fatal("Metadata is nil")
	}

	if index < 0 || index >= TOTAL_FILES {
		t.Fatalf("Index out of bounds: %d", index)
	}

	fileEntry := meta.Files[index]
	if fileEntry.Name == "" {
		t.Fatalf("No file at index %d", index)
	}

	// Read the encrypted file data
	seekPos := META_FILE_SIZE + (index * MAX_FILE_SIZE)
	_, err = file.Seek(int64(seekPos), 0)
	if err != nil {
		t.Fatalf("Failed to seek: %v", err)
	}

	buff := make([]byte, fileEntry.Size)
	_, err = file.Read(buff)
	if err != nil {
		t.Fatalf("Failed to read file data: %v", err)
	}

	// Decrypt
	password, err := GetEncKey()
	if err != nil {
		t.Fatalf("Failed to get encryption key: %v", err)
	}
	decrypted, err := DecryptGCM(buff, password, meta.Salt)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Compare
	if !bytes.Equal(decrypted, expectedContent) {
		t.Errorf("File content mismatch at index %d", index)
		t.Errorf("Expected %d bytes, got %d bytes", len(expectedContent), len(decrypted))
		if len(expectedContent) < 100 && len(decrypted) < 100 {
			t.Errorf("Expected: %v", expectedContent)
			t.Errorf("Got: %v", decrypted)
		}
	}
}

// CountUsedSlots counts how many file slots are in use
func CountUsedSlots(meta *Meta) int {
	count := 0
	for _, f := range meta.Files {
		if f.Name != "" {
			count++
		}
	}
	return count
}

// FindEmptySlot finds the first empty slot index
func FindEmptySlot(meta *Meta) int {
	for i, f := range meta.Files {
		if f.Name == "" {
			return i
		}
	}
	return -1
}

// FillAllSlots fills all slots with dummy files for testing
// FillSlots fills a specific number of slots (for testing with reduced load)
func FillSlots(t *testing.T, file F, count int) {
	t.Helper()

	if count > TOTAL_FILES {
		count = TOTAL_FILES
	}

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("Failed to read metadata: %v", err)
	}
	if meta == nil {
		t.Fatal("Metadata is nil")
	}

	password, err := GetEncKey()
	if err != nil {
		t.Fatalf("Failed to get encryption key: %v", err)
	}

	filled := 0
	for i := 0; i < TOTAL_FILES && filled < count; i++ {
		if meta.Files[i].Name == "" {
			dummyData := []byte(fmt.Sprintf("dummy_%d", i))
			encrypted, err := EncryptGCM(dummyData, password, meta.Salt)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			seekPos := META_FILE_SIZE + (i * MAX_FILE_SIZE)
			_, err = file.Seek(int64(seekPos), 0)
			if err != nil {
				t.Fatalf("Failed to seek: %v", err)
			}

			padded := make([]byte, MAX_FILE_SIZE)
			copy(padded, encrypted)

			_, err = file.Write(padded)
			if err != nil {
				t.Fatalf("Failed to write: %v", err)
			}

			meta.Files[i] = File{
				Name: fmt.Sprintf("dummy_%d.txt", i),
				Size: len(encrypted),
			}
			filled++
		}
	}

	WriteMeta(file, meta)
}

// FillAllSlots fills all filesystem slots (delegates to FillSlots)
func FillAllSlots(t *testing.T, file F) {
	t.Helper()
	FillSlots(t, file, TOTAL_FILES)
}

// Shared test file infrastructure
var (
	sharedTestFileSize int64 = 10 * 1024 * 1024 // 10MB
	fileCounter        int   = 0
)

// GetSharedTestFile returns a shared 10MB test file for this specific test
// The file is unique per test and automatically cleaned up
func GetSharedTestFile(t *testing.T) *os.File {
	t.Helper()

	// Create unique temp file for this test
	tmpDir := os.TempDir()

	// Use test name + counter for uniqueness (for tests that need multiple files)
	fileCounter++
	filename := filepath.Join(tmpDir, fmt.Sprintf("hdnfs_test_%s_%d.dat", t.Name(), fileCounter))

	// Create the file with 10MB size
	file, err := os.Create(filename)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Pre-allocate 10MB
	if err := file.Truncate(sharedTestFileSize); err != nil {
		file.Close()
		t.Fatalf("Failed to truncate file: %v", err)
	}

	// Seek to beginning
	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		t.Fatalf("Failed to seek file: %v", err)
	}

	// Register cleanup to close and remove file after test
	t.Cleanup(func() {
		file.Close()
		os.Remove(filename)
	})

	return file
}

// LogTestDuration logs test duration only if the test failed
// Usage: defer LogTestDuration(t, time.Now())
func LogTestDuration(t *testing.T, start time.Time) {
	t.Helper()
	if t.Failed() {
		t.Logf("%s took: %v", t.Name(), time.Since(start))
	}
}
