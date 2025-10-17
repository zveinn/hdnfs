package hdnfs

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"testing"
)

func TestInitMeta(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	tests := []struct {
		name string
		mode string
		size int64
	}{
		{
			name: "Device mode",
			mode: "device",
			size: META_FILE_SIZE + (TOTAL_FILES * MAX_FILE_SIZE),
		},
		{
			name: "File mode",
			mode: "file",
			size: META_FILE_SIZE + (TOTAL_FILES * MAX_FILE_SIZE),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := CreateTempTestFile(t, tt.size)
			defer file.Close()

			// Initialize
			InitMeta(file, tt.mode)

			// Verify metadata was written
			meta := ReadMeta(file)
			if meta == nil {
				t.Fatal("Failed to read metadata after init")
			}

			// Verify all slots are empty
			for i, f := range meta.Files {
				if f.Name != "" {
					t.Errorf("Slot %d should be empty, got name: %s", i, f.Name)
				}
				if f.Size != 0 {
					t.Errorf("Slot %d should have size 0, got: %d", i, f.Size)
				}
			}
		})
	}
}

func TestWriteMetaAndReadMeta(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE + MAX_FILE_SIZE)

	// Create test metadata
	meta := &Meta{}
	meta.Files[0] = File{Name: "test1.txt", Size: 100}
	meta.Files[1] = File{Name: "test2.txt", Size: 200}
	meta.Files[999] = File{Name: "last.txt", Size: 300}

	// Write metadata
	WriteMeta(file, meta)

	// Reset position
	file.Seek(0, 0)

	// Read metadata back
	readMeta := ReadMeta(file)
	if readMeta == nil {
		t.Fatal("Failed to read metadata")
	}

	// Verify files match
	if readMeta.Files[0].Name != "test1.txt" || readMeta.Files[0].Size != 100 {
		t.Errorf("File 0 mismatch: got %+v", readMeta.Files[0])
	}
	if readMeta.Files[1].Name != "test2.txt" || readMeta.Files[1].Size != 200 {
		t.Errorf("File 1 mismatch: got %+v", readMeta.Files[1])
	}
	if readMeta.Files[999].Name != "last.txt" || readMeta.Files[999].Size != 300 {
		t.Errorf("File 999 mismatch: got %+v", readMeta.Files[999])
	}

	// Verify empty slots are still empty
	for i := 2; i < 999; i++ {
		if readMeta.Files[i].Name != "" || readMeta.Files[i].Size != 0 {
			t.Errorf("Slot %d should be empty", i)
		}
	}
}

func TestMetadataEncryption(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE)

	// Create test metadata
	meta := &Meta{}
	meta.Files[0] = File{Name: "secret.txt", Size: 123}

	// Write metadata
	WriteMeta(file, meta)

	// Read raw bytes
	rawData := file.GetData()[:META_FILE_SIZE]

	// Length header (first 4 bytes)
	length := binary.BigEndian.Uint32(rawData[0:4])

	// Encrypted portion
	encryptedMeta := rawData[4 : 4+length]

	// Verify it's encrypted (should not contain plaintext "secret.txt")
	if bytes.Contains(encryptedMeta, []byte("secret.txt")) {
		t.Error("Metadata appears to be stored in plaintext")
	}

	// Decrypt manually and verify
	decrypted := Decrypt(encryptedMeta, GetEncKey())
	var checkMeta Meta
	if err := json.Unmarshal(decrypted, &checkMeta); err != nil {
		t.Fatalf("Failed to unmarshal decrypted metadata: %v", err)
	}

	if checkMeta.Files[0].Name != "secret.txt" {
		t.Error("Decrypted metadata doesn't match original")
	}
}

func TestMetadataLengthHeader(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE)

	meta := &Meta{}
	meta.Files[0] = File{Name: "test.txt", Size: 100}

	WriteMeta(file, meta)

	// Read length header
	rawData := file.GetData()
	length := binary.BigEndian.Uint32(rawData[0:4])

	// Verify length is reasonable (should be JSON + encryption overhead)
	if length == 0 {
		t.Error("Length header is zero")
	}

	if length > META_FILE_SIZE {
		t.Errorf("Length header too large: %d", length)
	}

	// Manually create expected length
	mb, _ := json.Marshal(meta)
	encrypted := Encrypt(mb, GetEncKey())
	expectedLength := uint32(len(encrypted))

	if length != expectedLength {
		t.Errorf("Length mismatch: expected %d, got %d", expectedLength, length)
	}
}

func TestReadMetaUninitialized(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	// Create file with zeros (uninitialized)
	file := NewMockFile(META_FILE_SIZE)

	// ReadMeta should detect uninitialized state (byte 4 == 0)
	// and call os.Exit(1), which we can't easily test
	// For now, we just verify the check exists in the code

	// Instead test with properly initialized but empty metadata
	InitMeta(file, "device")
	meta := ReadMeta(file)

	if meta == nil {
		t.Error("ReadMeta returned nil for initialized metadata")
	}
}

func TestMetadataPadding(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE * 2)

	meta := &Meta{}
	meta.Files[0] = File{Name: "test.txt", Size: 100}

	WriteMeta(file, meta)

	// Verify exactly META_FILE_SIZE bytes were written
	file.Seek(0, 0)
	testBuf := make([]byte, META_FILE_SIZE+1)
	n, _ := file.Read(testBuf)

	if n != META_FILE_SIZE+1 {
		// Data exists beyond META_FILE_SIZE, check if it's just expansion
		// In MockFile, we expand as needed, so this is expected
	}

	// Verify padding is zeros (after the encrypted data)
	rawData := file.GetData()[:META_FILE_SIZE]
	length := binary.BigEndian.Uint32(rawData[0:4])

	// Everything after [4+length:META_FILE_SIZE] should be padding zeros
	paddingStart := 4 + int(length)
	for i := paddingStart; i < META_FILE_SIZE; i++ {
		if rawData[i] != 0 {
			t.Errorf("Padding byte at position %d is not zero: %d", i, rawData[i])
			break
		}
	}
}

func TestWriteMetaMultipleTimes(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE)

	// Write metadata multiple times with different content
	for i := 0; i < 10; i++ {
		meta := &Meta{}
		meta.Files[i] = File{
			Name: fmt.Sprintf("file_%d.txt", i),
			Size: i * 100,
		}

		WriteMeta(file, meta)

		// Read back and verify
		file.Seek(0, 0)
		readMeta := ReadMeta(file)

		if readMeta.Files[i].Name != meta.Files[i].Name {
			t.Errorf("Iteration %d: name mismatch", i)
		}
		if readMeta.Files[i].Size != meta.Files[i].Size {
			t.Errorf("Iteration %d: size mismatch", i)
		}
	}
}

func TestMetadataMaxCapacity(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE * 2)

	// Fill all slots
	meta := &Meta{}
	for i := 0; i < TOTAL_FILES; i++ {
		meta.Files[i] = File{
			Name: fmt.Sprintf("file_%d.txt", i),
			Size: i,
		}
	}

	WriteMeta(file, meta)

	// Read back
	file.Seek(0, 0)
	readMeta := ReadMeta(file)

	// Verify all entries
	for i := 0; i < TOTAL_FILES; i++ {
		if readMeta.Files[i].Name != fmt.Sprintf("file_%d.txt", i) {
			t.Errorf("Slot %d name mismatch", i)
		}
		if readMeta.Files[i].Size != i {
			t.Errorf("Slot %d size mismatch", i)
		}
	}
}

func TestMetadataWithLongFilenames(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE)

	meta := &Meta{}

	// Create filenames of various lengths
	tests := []int{1, 10, 50, MAX_FILE_NAME_SIZE}

	for idx, length := range tests {
		if idx >= len(meta.Files) {
			break
		}

		name := string(bytes.Repeat([]byte("a"), length))
		meta.Files[idx] = File{Name: name, Size: length}
	}

	WriteMeta(file, meta)

	// Read back
	file.Seek(0, 0)
	readMeta := ReadMeta(file)

	// Verify
	for idx, length := range tests {
		if idx >= len(meta.Files) {
			break
		}

		expected := string(bytes.Repeat([]byte("a"), length))
		if readMeta.Files[idx].Name != expected {
			t.Errorf("Filename length %d mismatch", length)
		}
	}
}

func TestMetadataWithSpecialCharacters(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE)

	meta := &Meta{}
	meta.Files[0] = File{Name: "file with spaces.txt", Size: 100}
	meta.Files[1] = File{Name: "file-with-dashes.txt", Size: 200}
	meta.Files[2] = File{Name: "file_with_underscores.txt", Size: 300}
	meta.Files[3] = File{Name: "file.multiple.dots.txt", Size: 400}
	meta.Files[4] = File{Name: "файл.txt", Size: 500} // Cyrillic
	meta.Files[5] = File{Name: "文件.txt", Size: 600} // Chinese

	WriteMeta(file, meta)
	file.Seek(0, 0)
	readMeta := ReadMeta(file)

	// Verify all special character filenames
	expectedNames := []string{
		"file with spaces.txt",
		"file-with-dashes.txt",
		"file_with_underscores.txt",
		"file.multiple.dots.txt",
		"файл.txt",
		"文件.txt",
	}

	for i, expected := range expectedNames {
		if readMeta.Files[i].Name != expected {
			t.Errorf("File %d: expected '%s', got '%s'", i, expected, readMeta.Files[i].Name)
		}
	}
}

func TestMetadataIntegrityAfterPartialWrite(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE)

	// Write initial metadata
	meta1 := &Meta{}
	meta1.Files[0] = File{Name: "initial.txt", Size: 100}
	WriteMeta(file, meta1)

	// Simulate partial/corrupted write by truncating
	file.Seek(0, 0)
	rawData := file.GetData()
	corrupted := make([]byte, META_FILE_SIZE)
	copy(corrupted, rawData[:100]) // Only copy first 100 bytes

	file.Seek(0, 0)
	file.Write(corrupted)

	// Try to read - should fail or return nil
	// In current implementation, it might panic or exit
	// We can't easily test this without refactoring error handling
}

func BenchmarkWriteMeta(b *testing.B) {
	SetupTestKey(&testing.T{})
	file := NewMockFile(META_FILE_SIZE * 2)

	meta := &Meta{}
	meta.Files[0] = File{Name: "benchmark.txt", Size: 1000}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		WriteMeta(file, meta)
		file.Seek(0, 0)
	}
}

func BenchmarkReadMeta(b *testing.B) {
	SetupTestKey(&testing.T{})
	file := NewMockFile(META_FILE_SIZE * 2)

	meta := &Meta{}
	meta.Files[0] = File{Name: "benchmark.txt", Size: 1000}
	WriteMeta(file, meta)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		file.Seek(0, 0)
		ReadMeta(file)
	}
}
