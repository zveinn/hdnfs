package main

import (
	"fmt"
	"os"
)

func Stat(file *os.File) error {
	s, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat device: %w", err)
	}

	PrintHeader("DEVICE STATS")
	PrintSeparator(50)
	PrintLabel("Name", C(ColorWhite, s.Name()))
	PrintLabel("Size", C(ColorLightBlue, fmt.Sprintf("%d bytes", s.Size())))
	PrintLabel("Modified", C(ColorBrightBlue, s.ModTime().Format("2006-01-02 15:04:05")))
	PrintLabel("Mode", C(ColorLightBlue, s.Mode().String()))
	PrintSeparator(50)

	return nil
}
