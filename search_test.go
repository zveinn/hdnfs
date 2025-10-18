package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestSearchName(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	tests := []struct {
		name           string
		files          map[int]string
		searchPhrase   string
		expectedCount  int
		expectedIndices []int
	}{
		{
			name: "single match",
			files: map[int]string{
				0: "document.txt",
				1: "report.pdf",
				2: "image.png",
			},
			searchPhrase:    "document",
			expectedCount:   1,
			expectedIndices: []int{0},
		},
		{
			name: "multiple matches",
			files: map[int]string{
				0: "report_2023.pdf",
				1: "annual_report.xlsx",
				2: "image.png",
				5: "quarterly_report.doc",
			},
			searchPhrase:    "report",
			expectedCount:   3,
			expectedIndices: []int{0, 1, 5},
		},
		{
			name: "case insensitive match",
			files: map[int]string{
				0: "Document.TXT",
				1: "REPORT.PDF",
				2: "report.xlsx",
			},
			searchPhrase:    "report",
			expectedCount:   2,
			expectedIndices: []int{1, 2},
		},
		{
			name: "partial match",
			files: map[int]string{
				0: "confidential_data.txt",
				1: "public_info.pdf",
				2: "secret_confidential.doc",
			},
			searchPhrase:    "confidential",
			expectedCount:   2,
			expectedIndices: []int{0, 2},
		},
		{
			name: "no matches",
			files: map[int]string{
				0: "document.txt",
				1: "report.pdf",
			},
			searchPhrase:    "xyz",
			expectedCount:   0,
			expectedIndices: []int{},
		},
		{
			name:            "empty filesystem",
			files:           map[int]string{},
			searchPhrase:    "anything",
			expectedCount:   0,
			expectedIndices: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := GetSharedTestFile(t)
			if err := InitMeta(file, "file"); err != nil {
				t.Fatalf("Failed to init metadata: %v", err)
			}

			password, _ := GetEncKey()
			meta, _ := ReadMeta(file)

			for idx, filename := range tt.files {
				content := []byte("test content for " + filename)
				encrypted, err := EncryptGCM(content, password, meta.Salt)
				if err != nil {
					t.Fatalf("Failed to encrypt: %v", err)
				}

				seekPos := META_FILE_SIZE + (idx * MAX_FILE_SIZE)
				file.Seek(int64(seekPos), 0)

				padded := make([]byte, MAX_FILE_SIZE)
				copy(padded, encrypted)
				file.Write(padded)

				meta.Files[idx] = File{
					Name: filename,
					Size: len(encrypted),
				}
			}

			WriteMeta(file, meta)

			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			err := SearchName(file, tt.searchPhrase)

			w.Close()
			os.Stdout = old

			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			if err != nil {
				t.Fatalf("SearchName failed: %v", err)
			}

			if !strings.Contains(output, tt.searchPhrase) {
				t.Errorf("Output doesn't contain search phrase '%s'", tt.searchPhrase)
			}

			for _, idx := range tt.expectedIndices {
				expectedName := tt.files[idx]
				if !strings.Contains(output, expectedName) {
					t.Errorf("Expected to find file '%s' in output, but didn't", expectedName)
				}
			}
		})
	}
}

func TestSearchNameEmptyPhrase(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)
	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("Failed to init metadata: %v", err)
	}

	err := SearchName(file, "")
	if err == nil {
		t.Error("Expected error for empty search phrase, got nil")
	}
	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("Expected 'cannot be empty' error, got: %v", err)
	}
}

func TestSearchContent(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	tests := []struct {
		name            string
		files           map[int]string
		fileContents    map[int]string
		searchPhrase    string
		searchIndex     int
		expectMatch     bool
		expectedMatches []int
	}{
		{
			name: "single file with match",
			files: map[int]string{
				0: "doc.txt",
			},
			fileContents: map[int]string{
				0: "This document contains a secret password.\nIt is hidden here.",
			},
			searchPhrase:    "password",
			searchIndex:     OUT_OF_BOUNDS_INDEX,
			expectMatch:     true,
			expectedMatches: []int{0},
		},
		{
			name: "multiple files with matches",
			files: map[int]string{
				0: "config.txt",
				1: "readme.md",
				2: "notes.txt",
			},
			fileContents: map[int]string{
				0: "username=admin\npassword=secret123",
				1: "This is a README file\nNo secrets here",
				2: "Remember the password for tomorrow",
			},
			searchPhrase:    "password",
			searchIndex:     OUT_OF_BOUNDS_INDEX,
			expectMatch:     true,
			expectedMatches: []int{0, 2},
		},
		{
			name: "case insensitive content search",
			files: map[int]string{
				0: "doc.txt",
			},
			fileContents: map[int]string{
				0: "This contains CONFIDENTIAL information\nAlso some Confidential data",
			},
			searchPhrase:    "confidential",
			searchIndex:     OUT_OF_BOUNDS_INDEX,
			expectMatch:     true,
			expectedMatches: []int{0},
		},
		{
			name: "search specific file by index",
			files: map[int]string{
				5: "target.txt",
				7: "other.txt",
			},
			fileContents: map[int]string{
				5: "This file has the secret keyword",
				7: "This file also has the secret keyword",
			},
			searchPhrase:    "secret",
			searchIndex:     5,
			expectMatch:     true,
			expectedMatches: []int{5},
		},
		{
			name: "no matches in any file",
			files: map[int]string{
				0: "doc1.txt",
				1: "doc2.txt",
			},
			fileContents: map[int]string{
				0: "Some random text here",
				1: "More random content",
			},
			searchPhrase:    "nonexistent",
			searchIndex:     OUT_OF_BOUNDS_INDEX,
			expectMatch:     false,
			expectedMatches: []int{},
		},
		{
			name: "multiline content with matches",
			files: map[int]string{
				0: "multiline.txt",
			},
			fileContents: map[int]string{
				0: "Line 1: Introduction\nLine 2: The password is here\nLine 3: Another password mention\nLine 4: End",
			},
			searchPhrase:    "password",
			searchIndex:     OUT_OF_BOUNDS_INDEX,
			expectMatch:     true,
			expectedMatches: []int{0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := GetSharedTestFile(t)
			if err := InitMeta(file, "file"); err != nil {
				t.Fatalf("Failed to init metadata: %v", err)
			}

			password, _ := GetEncKey()
			meta, _ := ReadMeta(file)

			for idx, filename := range tt.files {
				content := []byte(tt.fileContents[idx])
				encrypted, err := EncryptGCM(content, password, meta.Salt)
				if err != nil {
					t.Fatalf("Failed to encrypt: %v", err)
				}

				seekPos := META_FILE_SIZE + (idx * MAX_FILE_SIZE)
				file.Seek(int64(seekPos), 0)

				padded := make([]byte, MAX_FILE_SIZE)
				copy(padded, encrypted)
				file.Write(padded)

				meta.Files[idx] = File{
					Name: filename,
					Size: len(encrypted),
				}
			}

			WriteMeta(file, meta)

			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			err := SearchContent(file, tt.searchPhrase, tt.searchIndex)

			w.Close()
			os.Stdout = old

			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			if err != nil {
				t.Fatalf("SearchContent failed: %v", err)
			}

			if tt.expectMatch {
				for _, idx := range tt.expectedMatches {
					expectedName := tt.files[idx]
					if !strings.Contains(output, expectedName) {
						t.Errorf("Expected to find file '%s' in output", expectedName)
					}
				}
			}
		})
	}
}

func TestSearchContentEmptyPhrase(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)
	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("Failed to init metadata: %v", err)
	}

	err := SearchContent(file, "", OUT_OF_BOUNDS_INDEX)
	if err == nil {
		t.Error("Expected error for empty search phrase, got nil")
	}
	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("Expected 'cannot be empty' error, got: %v", err)
	}
}

func TestSearchContentInvalidIndex(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)
	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("Failed to init metadata: %v", err)
	}

	tests := []struct {
		name  string
		index int
	}{
		{"negative index", -1},
		{"index too large", TOTAL_FILES},
		{"index way too large", TOTAL_FILES + 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SearchContent(file, "test", tt.index)
			if err == nil {
				t.Error("Expected error for invalid index, got nil")
			}
			if !strings.Contains(err.Error(), "out of range") {
				t.Errorf("Expected 'out of range' error, got: %v", err)
			}
		})
	}
}

func TestSearchContentEmptySlot(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)
	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("Failed to init metadata: %v", err)
	}

	err := SearchContent(file, "test", 0)
	if err == nil {
		t.Error("Expected error for empty slot, got nil")
	}
	if !strings.Contains(err.Error(), "no file exists") {
		t.Errorf("Expected 'no file exists' error, got: %v", err)
	}
}

func TestSearchFileContent(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	tests := []struct {
		name             string
		content          string
		searchPhrase     string
		expectedMatches  int
		shouldContain    []string
		shouldNotContain []string
	}{
		{
			name:            "single line match",
			content:         "This line contains the keyword here",
			searchPhrase:    "keyword",
			expectedMatches: 1,
			shouldContain:   []string{"keyword"},
		},
		{
			name:            "multiple line matches",
			content:         "Line 1 has keyword\nLine 2 is normal\nLine 3 has keyword too",
			searchPhrase:    "keyword",
			expectedMatches: 2,
			shouldContain:   []string{"Line 1", "Line 3"},
		},
		{
			name:             "no matches",
			content:          "This text has nothing special",
			searchPhrase:     "keyword",
			expectedMatches:  0,
			shouldNotContain: []string{"keyword"},
		},
		{
			name:            "case insensitive",
			content:         "KEYWORD in caps\nkeyword in lowercase\nKeYwOrD mixed",
			searchPhrase:    "keyword",
			expectedMatches: 3,
		},
		{
			name:            "partial word match",
			content:         "The keywords are important",
			searchPhrase:    "keyword",
			expectedMatches: 1,
			shouldContain:   []string{"keywords"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := GetSharedTestFile(t)
			if err := InitMeta(file, "file"); err != nil {
				t.Fatalf("Failed to init metadata: %v", err)
			}

			password, _ := GetEncKey()
			meta, _ := ReadMeta(file)

			encrypted, err := EncryptGCM([]byte(tt.content), password, meta.Salt)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			seekPos := META_FILE_SIZE
			file.Seek(int64(seekPos), 0)

			padded := make([]byte, MAX_FILE_SIZE)
			copy(padded, encrypted)
			file.Write(padded)

			meta.Files[0] = File{
				Name: "test.txt",
				Size: len(encrypted),
			}

			matches, err := searchFileContent(file, meta, password, 0, strings.ToLower(tt.searchPhrase))
			if err != nil {
				t.Fatalf("searchFileContent failed: %v", err)
			}

			if len(matches) != tt.expectedMatches {
				t.Errorf("Expected %d matches, got %d", tt.expectedMatches, len(matches))
			}

			for _, shouldContain := range tt.shouldContain {
				found := false
				for _, match := range matches {
					if strings.Contains(match, shouldContain) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected to find '%s' in matches", shouldContain)
				}
			}

			for _, shouldNotContain := range tt.shouldNotContain {
				for _, match := range matches {
					if strings.Contains(match, shouldNotContain) {
						t.Errorf("Did not expect to find '%s' in matches", shouldNotContain)
					}
				}
			}
		})
	}
}

func TestSearchFileContentDecryptionError(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)
	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("Failed to init metadata: %v", err)
	}

	meta, _ := ReadMeta(file)

	seekPos := META_FILE_SIZE
	file.Seek(int64(seekPos), 0)

	corruptData := []byte("this is not properly encrypted data")
	padded := make([]byte, MAX_FILE_SIZE)
	copy(padded, corruptData)
	file.Write(padded)

	meta.Files[0] = File{
		Name: "corrupt.txt",
		Size: len(corruptData),
	}

	password, _ := GetEncKey()

	_, err := searchFileContent(file, meta, password, 0, "test")
	if err == nil {
		t.Error("Expected decryption error for corrupt data, got nil")
	}
	if !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("Expected 'decrypt' in error message, got: %v", err)
	}
}

func TestSearchWithSpecialCharacters(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)
	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("Failed to init metadata: %v", err)
	}

	password, _ := GetEncKey()
	meta, _ := ReadMeta(file)

	specialContent := "Special chars: @#$%^&*()_+-=[]{}|;:',.<>?/`~"
	encrypted, _ := EncryptGCM([]byte(specialContent), password, meta.Salt)

	seekPos := META_FILE_SIZE
	file.Seek(int64(seekPos), 0)

	padded := make([]byte, MAX_FILE_SIZE)
	copy(padded, encrypted)
	file.Write(padded)

	meta.Files[0] = File{
		Name: "special_chars.txt",
		Size: len(encrypted),
	}
	WriteMeta(file, meta)

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := SearchContent(file, "@#$%", OUT_OF_BOUNDS_INDEX)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("SearchContent failed with special chars: %v", err)
	}
}

func TestSearchNameWithUnicodeCharacters(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	file := GetSharedTestFile(t)
	if err := InitMeta(file, "file"); err != nil {
		t.Fatalf("Failed to init metadata: %v", err)
	}

	password, _ := GetEncKey()
	meta, _ := ReadMeta(file)

	unicodeFilename := "文档_документ_📄.txt"
	content := []byte("Unicode test content")
	encrypted, _ := EncryptGCM(content, password, meta.Salt)

	seekPos := META_FILE_SIZE
	file.Seek(int64(seekPos), 0)

	padded := make([]byte, MAX_FILE_SIZE)
	copy(padded, encrypted)
	file.Write(padded)

	meta.Files[0] = File{
		Name: unicodeFilename,
		Size: len(encrypted),
	}
	WriteMeta(file, meta)

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := SearchName(file, "文档")

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if err != nil {
		t.Fatalf("SearchName failed with unicode: %v", err)
	}

	if !strings.Contains(output, "文档") {
		t.Error("Expected to find unicode characters in output")
	}
}
