package hdnfs

import (
	"fmt"
	"log"
	"strings"
	"time"
)

func Overwrite(file F, start int64, end uint64) {
	chunk := make([]byte, ERASE_CHUNK_SIZE, ERASE_CHUNK_SIZE)
	_, _ = file.Seek(start, 0)
	var total uint64 = uint64(start)
	var stopWriting bool = false
	for {
		if stopWriting {
			fmt.Println("Done writing, total MB: ", total/1_000_000)
			return
		}

		missing := end - total
		if missing < ERASE_CHUNK_SIZE {
			stopWriting = true
			chunk = chunk[:missing]
		}

		// when are we at the end index..
		start := time.Now()
		n, err := file.Write(chunk)
		_ = file.Sync()
		total += uint64(n)
		if time.Since(start).Milliseconds() > 500 {
			time.Sleep(3 * time.Second)
		} else {
			time.Sleep(5 * time.Millisecond)
		}
		log.Println("Written MB:", total/1_000_000)
		if err != nil {
			if strings.Contains(err.Error(), "no space left of device") {
				return
			}
			PrintError("Error while syncing devices", err)
			return
		}
	}
}
