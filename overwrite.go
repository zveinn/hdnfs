package main

import (
	"fmt"
	"log"
	"strings"
	"time"
)

func Overwrite(file F, start int64, end uint64) error {
	chunk := make([]byte, ERASE_CHUNK_SIZE)

	_, err := file.Seek(start, 0)
	if err != nil {
		return fmt.Errorf("failed to seek to start position: %w", err)
	}

	var total uint64 = uint64(start)
	var stopWriting bool = false

	for {
		if stopWriting {
			return nil
		}

		missing := end - total
		if missing == 0 {
			return nil
		}
		if missing < ERASE_CHUNK_SIZE {
			stopWriting = true
			chunk = chunk[:missing]
		}

		n, err := file.Write(chunk)
		if err != nil {
			return fmt.Errorf("failed to write chunk: %w", err)
		}

		if err := file.Sync(); err != nil {
			return fmt.Errorf("failed to sync: %w", err)
		}

		total += uint64(n)
	}
}

func OverwriteDevice(file F) error {
	chunk := make([]byte, ERASE_CHUNK_SIZE)

	_, err := file.Seek(0, 0)
	if err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}

	var total uint64 = 0

	for {
		writeStart := time.Now()
		n, err := file.Write(chunk)
		if err != nil {
			if strings.Contains(err.Error(), "no space left on device") {
				PrintSuccess(fmt.Sprintf("Device overwrite complete: %s",
					C(ColorWhite, fmt.Sprintf("%d MB", total/1_000_000))))
				return nil
			}
			return fmt.Errorf("failed to write chunk: %w", err)
		}

		if err := file.Sync(); err != nil {
			return fmt.Errorf("failed to sync: %w", err)
		}

		total += uint64(n)

		if time.Since(writeStart).Milliseconds() > 500 {
			time.Sleep(3 * time.Second)
		}

		if !Silent {
			log.Printf("%s %s\n",
				C(ColorLightBlue, "Written:"),
				C(ColorWhite, fmt.Sprintf("%d MB", total/1_000_000)))
		}
	}
}
