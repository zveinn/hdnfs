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
	PrintSeparator(60)
	Printf(" %-15s %s\n", C(ColorBold+ColorLightBlue, "Name:"), C(ColorWhite, s.Name()))
	Printf(" %-15s %s\n", C(ColorBold+ColorLightBlue, "Size:"), C(ColorWhite, fmt.Sprintf("%d bytes (%.2f MB)", s.Size(), float64(s.Size())/1024/1024)))
	Printf(" %-15s %s\n", C(ColorBold+ColorLightBlue, "Modified:"), C(ColorWhite, s.ModTime().Format("2006-01-02 15:04:05")))
	Printf(" %-15s %s\n", C(ColorBold+ColorLightBlue, "Mode:"), C(ColorWhite, s.Mode().String()))
	PrintSeparator(60)

	return nil
}
