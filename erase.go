package hdnfs

import (
	"log"
	"strings"
	"time"
)

func Erase(file F, start int64) {
	chunk := make([]byte, 1_000_000, 1_000_000)
	_, _ = file.Seek(start, 0)
	var total int64 = start
	for {
		start := time.Now()
		n, err := file.Write(chunk)
		_ = file.Sync()
		total += int64(n)
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
