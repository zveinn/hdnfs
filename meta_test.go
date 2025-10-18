package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

func TestInitMeta(t *testing.T) {
	defer LogTestDuration(t, time.Now())

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

			if err := InitMeta(file, tt.mode); err != nil {
				t.Fatalf("InitMeta failed: %v", err)
			}

			meta, err := ReadMeta(file)
			if err != nil {
				t.Fatalf("Failed to read metadata after init: %v", err)
			}
			if meta == nil {
				t.Fatal("ReadMeta returned nil")
			}

			if len(meta.Salt) != SALT_SIZE {
				t.Errorf("Expected salt size %d, got %d", SALT_SIZE, len(meta.Salt))
			}

			if meta.Version != METADATA_VERSION {
				t.Errorf("Expected version %d, got %d", METADATA_VERSION, meta.Version)
			}

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
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE + MAX_FILE_SIZE)

	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	meta := &Meta{
		Version: METADATA_VERSION,
		Salt:    salt,
	}
	meta.Files[0] = File{Name: "test1.txt", Size: 100}
	meta.Files[1] = File{Name: "test2.txt", Size: 200}
	meta.Files[999] = File{Name: "last.txt", Size: 300}

	if err := WriteMeta(file, meta); err != nil {
		t.Fatalf("WriteMeta failed: %v", err)
	}

	file.Seek(0, 0)

	readMeta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if readMeta == nil {
		t.Fatal("ReadMeta returned nil")
	}

	if readMeta.Version != METADATA_VERSION {
		t.Errorf("Version mismatch: expected %d, got %d", METADATA_VERSION, readMeta.Version)
	}
	if !bytes.Equal(readMeta.Salt, salt) {
		t.Error("Salt mismatch")
	}

	if readMeta.Files[0].Name != "test1.txt" || readMeta.Files[0].Size != 100 {
		t.Errorf("File 0 mismatch: got %+v", readMeta.Files[0])
	}
	if readMeta.Files[1].Name != "test2.txt" || readMeta.Files[1].Size != 200 {
		t.Errorf("File 1 mismatch: got %+v", readMeta.Files[1])
	}
	if readMeta.Files[999].Name != "last.txt" || readMeta.Files[999].Size != 300 {
		t.Errorf("File 999 mismatch: got %+v", readMeta.Files[999])
	}

	for i := 2; i < 999; i++ {
		if readMeta.Files[i].Name != "" || readMeta.Files[i].Size != 0 {
			t.Errorf("Slot %d should be empty", i)
		}
	}
}

func TestMetadataEncryption(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE)

	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	meta := &Meta{
		Version: METADATA_VERSION,
		Salt:    salt,
	}
	meta.Files[0] = File{Name: "secret.txt", Size: 123}

	if err := WriteMeta(file, meta); err != nil {
		t.Fatalf("WriteMeta failed: %v", err)
	}

	rawData := file.GetData()[:META_FILE_SIZE]

	headerEnd := HEADER_SIZE
	lengthStart := MAGIC_SIZE + VERSION_SIZE + RESERVED_SIZE + SALT_SIZE
	length := binary.BigEndian.Uint32(rawData[lengthStart : lengthStart+LENGTH_SIZE])

	encryptedStart := headerEnd
	encryptedEnd := encryptedStart + int(length)

	if encryptedEnd > len(rawData) {
		t.Fatalf("Encrypted data extends beyond buffer: %d > %d", encryptedEnd, len(rawData))
	}

	encryptedMeta := rawData[encryptedStart:encryptedEnd]

	if bytes.Contains(encryptedMeta, []byte("secret.txt")) {
		t.Error("Metadata appears to be stored in plaintext")
	}

	file.Seek(0, 0)
	readMeta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}

	if readMeta.Files[0].Name != "secret.txt" {
		t.Error("Decrypted metadata doesn't match original")
	}
}

func TestMetadataHeaderFormat(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE)

	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	meta := &Meta{
		Version: METADATA_VERSION,
		Salt:    salt,
	}
	meta.Files[0] = File{Name: "test.txt", Size: 100}

	if err := WriteMeta(file, meta); err != nil {
		t.Fatalf("WriteMeta failed: %v", err)
	}

	rawData := file.GetData()

	magic := string(rawData[0:MAGIC_SIZE])
	if magic != MAGIC_STRING {
		t.Errorf("Expected magic %q, got %q", MAGIC_STRING, magic)
	}

	version := int(rawData[MAGIC_SIZE])
	if version != METADATA_VERSION {
		t.Errorf("Expected version %d, got %d", METADATA_VERSION, version)
	}

	saltStart := MAGIC_SIZE + VERSION_SIZE + RESERVED_SIZE
	storedSalt := rawData[saltStart : saltStart+SALT_SIZE]
	if !bytes.Equal(storedSalt, salt) {
		t.Error("Salt mismatch in header")
	}

	lengthStart := saltStart + SALT_SIZE
	length := binary.BigEndian.Uint32(rawData[lengthStart : lengthStart+LENGTH_SIZE])
	if length == 0 {
		t.Error("Length field is zero")
	}
	if length > META_FILE_SIZE {
		t.Errorf("Length field too large: %d", length)
	}
}

func TestReadMetaWithWrongMagicNumber(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE)

	file.Write([]byte("XXXXX"))
	file.Seek(0, 0)

	_, err := ReadMeta(file)
	if err == nil {
		t.Error("ReadMeta should fail with wrong magic number")
	}
}

func TestReadMetaUninitialized(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE)

	_, err := ReadMeta(file)
	if err == nil {
		t.Error("ReadMeta should fail on uninitialized metadata")
	}

	if err := InitMeta(file, "device"); err != nil {
		t.Fatalf("InitMeta failed: %v", err)
	}

	meta, err := ReadMeta(file)
	if err != nil {
		t.Errorf("ReadMeta failed after init: %v", err)
	}
	if meta == nil {
		t.Error("ReadMeta returned nil for initialized metadata")
	}
}

func TestMetadataChecksumValidation(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE)

	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	meta := &Meta{
		Version: METADATA_VERSION,
		Salt:    salt,
	}
	meta.Files[0] = File{Name: "test.txt", Size: 100}

	if err := WriteMeta(file, meta); err != nil {
		t.Fatalf("WriteMeta failed: %v", err)
	}

	rawData := file.GetData()
	corruptPos := HEADER_SIZE + 10
	rawData[corruptPos] ^= 0xFF

	file.Seek(0, 0)

	_, err = ReadMeta(file)
	if err == nil {
		t.Error("ReadMeta should fail with corrupted data (checksum mismatch)")
	}
}

func TestWriteMetaMultipleTimes(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE)

	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	for i := 0; i < 10; i++ {
		meta := &Meta{
			Version: METADATA_VERSION,
			Salt:    salt,
		}
		meta.Files[i] = File{
			Name: fmt.Sprintf("file_%d.txt", i),
			Size: i * 100,
		}

		if err := WriteMeta(file, meta); err != nil {
			t.Fatalf("WriteMeta iteration %d failed: %v", i, err)
		}

		file.Seek(0, 0)
		readMeta, err := ReadMeta(file)
		if err != nil {
			t.Fatalf("ReadMeta iteration %d failed: %v", i, err)
		}

		if readMeta.Files[i].Name != meta.Files[i].Name {
			t.Errorf("Iteration %d: name mismatch", i)
		}
		if readMeta.Files[i].Size != meta.Files[i].Size {
			t.Errorf("Iteration %d: size mismatch", i)
		}
	}
}

func TestMetadataMaxCapacity(t *testing.T) {
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE * 2)

	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	meta := &Meta{
		Version: METADATA_VERSION,
		Salt:    salt,
	}
	for i := 0; i < TOTAL_FILES; i++ {
		meta.Files[i] = File{
			Name: fmt.Sprintf("file_%d.txt", i),
			Size: i,
		}
	}

	if err := WriteMeta(file, meta); err != nil {
		t.Fatalf("WriteMeta failed: %v", err)
	}

	file.Seek(0, 0)
	readMeta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}

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
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE)

	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	meta := &Meta{
		Version: METADATA_VERSION,
		Salt:    salt,
	}

	tests := []int{1, 10, 50, MAX_FILE_NAME_SIZE}

	for idx, length := range tests {
		if idx >= len(meta.Files) {
			break
		}

		name := string(bytes.Repeat([]byte("a"), length))
		meta.Files[idx] = File{Name: name, Size: length}
	}

	if err := WriteMeta(file, meta); err != nil {
		t.Fatalf("WriteMeta failed: %v", err)
	}

	file.Seek(0, 0)
	readMeta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}

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
	defer LogTestDuration(t, time.Now())

	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := NewMockFile(META_FILE_SIZE)

	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	meta := &Meta{
		Version: METADATA_VERSION,
		Salt:    salt,
	}
	meta.Files[0] = File{Name: "file with spaces.txt", Size: 100}
	meta.Files[1] = File{Name: "file-with-dashes.txt", Size: 200}
	meta.Files[2] = File{Name: "file_with_underscores.txt", Size: 300}
	meta.Files[3] = File{Name: "file.multiple.dots.txt", Size: 400}
	meta.Files[4] = File{Name: "файл.txt", Size: 500}
	meta.Files[5] = File{Name: "文件.txt", Size: 600}

	if err := WriteMeta(file, meta); err != nil {
		t.Fatalf("WriteMeta failed: %v", err)
	}

	file.Seek(0, 0)
	readMeta, err := ReadMeta(file)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}

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

func BenchmarkWriteMeta(b *testing.B) {
	SetupTestKey(&testing.T{})
	file := NewMockFile(META_FILE_SIZE * 2)

	salt, _ := GenerateSalt()
	meta := &Meta{
		Version: METADATA_VERSION,
		Salt:    salt,
	}
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

	salt, _ := GenerateSalt()
	meta := &Meta{
		Version: METADATA_VERSION,
		Salt:    salt,
	}
	meta.Files[0] = File{Name: "benchmark.txt", Size: 1000}
	WriteMeta(file, meta)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		file.Seek(0, 0)
		ReadMeta(file)
	}
}
