package main

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

func SearchName(file F, phrase string) error {
	if phrase == "" {
		return fmt.Errorf("search phrase cannot be empty")
	}

	meta, err := ReadMeta(file)
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	Println("----------- FILENAME SEARCH RESULTS -----------------")
	Printf("Searching for: \"%s\"\n", phrase)
	Println("-----------------------------------------------------")

	matchCount := 0
	lowerPhrase := strings.ToLower(phrase)

	for i := range TOTAL_FILES {
		if meta.Files[i].Name == "" {
			continue
		}

		lowerName := strings.ToLower(meta.Files[i].Name)
		if strings.Contains(lowerName, lowerPhrase) {
			Printf(" %-5d %s\n", i, meta.Files[i].Name)
			matchCount++
		}
	}

	Println("-----------------------------------------------------")
	Printf("Total matches: %d\n", matchCount)

	return nil
}

func SearchContent(file F, phrase string, index int) error {
	if phrase == "" {
		return fmt.Errorf("search phrase cannot be empty")
	}

	meta, err := ReadMeta(file)
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	password, err := GetEncKey()
	if err != nil {
		return fmt.Errorf("failed to get encryption key: %w", err)
	}

	lowerPhrase := strings.ToLower(phrase)
	totalMatches := 0

	if index != OUT_OF_BOUNDS_INDEX {
		if index < 0 || index >= TOTAL_FILES {
			return fmt.Errorf("index out of range: %d (valid range: 0-%d)", index, TOTAL_FILES-1)
		}

		if meta.Files[index].Name == "" {
			return fmt.Errorf("no file exists at index %d", index)
		}

		matches, err := searchFileContent(file, meta, password, index, lowerPhrase)
		if err != nil {
			return fmt.Errorf("search failed at index %d: %w", index, err)
		}

		if len(matches) > 0 {
			Printf("\n%d: %s\n", index, meta.Files[index].Name)
			for _, line := range matches {
				Printf("%s\n", line)
			}
			// totalMatches += len(matches)
		} else {
			Printf("\nNo matches found in [%d] %s\n", index, meta.Files[index].Name)
		}
	} else {
		Println("----------- CONTENT SEARCH RESULTS -----------------")
		Printf("Searching for: \"%s\"\n", phrase)
		Println("----------------------------------------------------")

		for i := range TOTAL_FILES {
			if meta.Files[i].Name == "" {
				continue
			}

			matches, err := searchFileContent(file, meta, password, i, lowerPhrase)
			if err != nil {
				Printf("\nError searching [%d] %s: %v\n", i, meta.Files[i].Name, err)
				continue
			}

			if len(matches) > 0 {
				Printf("\n%d: %s\n", i, meta.Files[i].Name)
				for _, line := range matches {
					Printf("%s\n", line)
				}
				totalMatches += len(matches)
			}
		}

		Println("----------------------------------------------------")
		Printf("Total matching lines: %d\n", totalMatches)
	}

	return nil
}

func searchFileContent(file F, meta *Meta, password string, index int, lowerPhrase string) ([]string, error) {
	df := meta.Files[index]

	seekPos := int64(META_FILE_SIZE) + (int64(index) * int64(MAX_FILE_SIZE))
	_, err := file.Seek(seekPos, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to seek: %w", err)
	}

	buff := make([]byte, df.Size)
	n, err := file.Read(buff)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}

	if n != df.Size {
		return nil, fmt.Errorf("short read: read %d bytes, expected %d", n, df.Size)
	}

	decrypted, err := DecryptGCM(buff, password, meta.Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	var matches []string
	scanner := bufio.NewScanner(bytes.NewReader(decrypted))
	lineNum := 1

	for scanner.Scan() {
		line := scanner.Text()
		lowerLine := strings.ToLower(line)

		if strings.Contains(lowerLine, lowerPhrase) {
			matches = append(matches, fmt.Sprintf("%s", line))
		}
		lineNum++
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading content: %w", err)
	}

	return matches, nil
}
