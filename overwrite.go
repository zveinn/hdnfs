package hdnfs

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
			fmt.Println("Done writing, total MB:", total/1_000_000)
			return nil
		}

		missing := end - total
		if missing < ERASE_CHUNK_SIZE {
			stopWriting = true
			chunk = chunk[:missing]
		}

		// Write chunk
		writeStart := time.Now()
		n, err := file.Write(chunk)
		if err != nil {
			if strings.Contains(err.Error(), "no space left on device") {
				fmt.Println("Device full, stopping at", total/1_000_000, "MB")
				return nil
			}
			return fmt.Errorf("failed to write chunk: %w", err)
		}

		// Sync to ensure data is written
		if err := file.Sync(); err != nil {
			return fmt.Errorf("failed to sync: %w", err)
		}

		total += uint64(n)

		// Throttle writes for slow devices
		if time.Since(writeStart).Milliseconds() > 500 {
			time.Sleep(3 * time.Second)
		}

		log.Println("Written MB:", total/1_000_000)
	}
}
