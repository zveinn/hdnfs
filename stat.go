package hdnfs

import (
	"fmt"
	"os"
)

func Stat(file *os.File) error {
	s, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat device: %w", err)
	}

	Println("----------- DEVICE STATS -----------------")
	Println("Name:", s.Name())
	Println("Size:", s.Size(), "bytes")
	Println("Modified:", s.ModTime())
	Println("Mode:", s.Mode())
	Println("------------------------------------------")

	return nil
}
