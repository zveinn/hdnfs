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

	fmt.Println("----------- DEVICE STATS -----------------")
	fmt.Println("Name:", s.Name())
	fmt.Println("Size:", s.Size(), "bytes")
	fmt.Println("Modified:", s.ModTime())
	fmt.Println("Mode:", s.Mode())
	fmt.Println("------------------------------------------")

	return nil
}
