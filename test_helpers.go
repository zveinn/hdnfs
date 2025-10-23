package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type MockFile struct {
	data     []byte
	position int64
	closed   bool
}

func NewMockFile(size int) *MockFile {
	return &MockFile{
		data:     make([]byte, size),
		position: 0,
		closed:   false,
	}
}

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
	case 0:
		newPos = offset
	case 1:
		newPos = m.position + offset
	case 2:
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

func (m *MockFile) Truncate(size int64) error {
	if m.closed {
		return os.ErrClosed
	}
	if size < 0 {
		return fmt.Errorf("negative size: %d", size)
	}
	if size == 0 {
		m.data = make([]byte, 0)
		m.position = 0
		return nil
	}
	if int64(len(m.data)) > size {
		m.data = m.data[:size]
		if m.position > size {
			m.position = size
		}
	} else if int64(len(m.data)) < size {
		newData := make([]byte, size)
		copy(newData, m.data)
		m.data = newData
	}
	return nil
}

func (m *MockFile) Stat() (os.FileInfo, error) {
	if m.closed {
		return nil, os.ErrClosed
	}
	return &mockFileInfo{
		name: m.Name(),
		size: int64(len(m.data)),
		mode: os.FileMode(0o644),
	}, nil
}

type mockFileInfo struct {
	name string
	size int64
	mode os.FileMode
}

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return m.size }
func (m *mockFileInfo) Mode() os.FileMode  { return m.mode }
func (m *mockFileInfo) ModTime() time.Time { return time.Now() }
func (m *mockFileInfo) IsDir() bool        { return false }
func (m *mockFileInfo) Sys() interface{}   { return nil }

func (m *MockFile) Close() error {
	m.closed = true
	return nil
}

func (m *MockFile) GetData() []byte {
	return m.data
}

func CreateTempTestFile(t *testing.T, size int64) *os.File {
	t.Helper()
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_device.dat")

	file, err := os.Create(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	if size > 0 {
		if err := file.Truncate(size); err != nil {
			file.Close()
			t.Fatalf("Failed to truncate file: %v", err)
		}
	}

	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		t.Fatalf("Failed to seek: %v", err)
	}

	return file
}

func CreateTempSourceFile(t *testing.T, content []byte) string {
	t.Helper()
	return CreateTempSourceFileWithName(t, content, "source.dat")
}

func CreateTempSourceFileWithName(t *testing.T, content []byte, filename string) string {
	t.Helper()
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, filename)

	if err := os.WriteFile(tmpFile, content, 0o644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	return tmpFile
}

func GenerateRandomBytes(size int) []byte {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		panic(fmt.Sprintf("Failed to generate random bytes: %v", err))
	}
	return data
}

func SetupTestKey(t *testing.T) {
	t.Helper()
	testKey := "test-password-for-testing"
	SetPasswordForTesting(testKey)
}

func CleanupTestKey(t *testing.T) {
	t.Helper()
	ClearPasswordCache()
}

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

func VerifyMetadataIntegrity(t *testing.T, file F) *Meta {
	t.Helper()

	meta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("Failed to read metadata: %v", err)
	}
	if meta == nil {
		t.Fatal("Metadata is nil")
	}

	if len(meta.Files) != TOTAL_FILES {
		t.Errorf("Invalid metadata: expected %d file slots, got %d", TOTAL_FILES, len(meta.Files))
	}

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

	password, err := GetEncKey()
	if err != nil {
		t.Fatalf("Failed to get encryption key: %v", err)
	}
	decrypted, err := DecryptGCM(buff, password, meta.Salt)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, expectedContent) {
		t.Errorf("File content mismatch at index %d", index)
		t.Errorf("Expected %d bytes, got %d bytes", len(expectedContent), len(decrypted))
		if len(expectedContent) < 100 && len(decrypted) < 100 {
			t.Errorf("Expected: %v", expectedContent)
			t.Errorf("Got: %v", decrypted)
		}
	}
}

func CountUsedSlots(meta *Meta) int {
	count := 0
	for _, f := range meta.Files {
		if f.Name != "" {
			count++
		}
	}
	return count
}

func FindEmptySlot(meta *Meta) int {
	for i, f := range meta.Files {
		if f.Name == "" {
			return i
		}
	}
	return -1
}

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

func FillAllSlots(t *testing.T, file F) {
	t.Helper()
	FillSlots(t, file, TOTAL_FILES)
}

var (
	sharedTestFileSize int64 = 10 * 1024 * 1024
	fileCounter        int   = 0
)

func GetSharedTestFile(t *testing.T) *os.File {
	t.Helper()

	tmpDir := os.TempDir()

	testName := strings.ReplaceAll(t.Name(), "/", "_")
	testName = strings.ReplaceAll(testName, "\\", "_")

	fileCounter++
	filename := filepath.Join(tmpDir, fmt.Sprintf("hdnfs_test_%s_%d.dat", testName, fileCounter))

	file, err := os.Create(filename)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	if err := file.Truncate(sharedTestFileSize); err != nil {
		file.Close()
		t.Fatalf("Failed to truncate file: %v", err)
	}

	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		t.Fatalf("Failed to seek file: %v", err)
	}

	t.Cleanup(func() {
		file.Close()
		os.Remove(filename)
	})

	return file
}

func LogTestDuration(t *testing.T, start time.Time) {
	t.Helper()
	if t.Failed() {
		t.Logf("%s took: %v", t.Name(), time.Since(start))
	}
}
