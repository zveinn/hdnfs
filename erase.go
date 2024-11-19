package hdnfs

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

func Erase(file *os.File, start int64) {
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
		log.Println("Written MB:", total/1_000_000, " err:", err)
		// if total%1_000_000_000 == 0 {
		// 	fmt.Println("Written:", total/1_000_000_000, " GB")
		// }
		if err == io.EOF {
			fmt.Println("ERR:", err)
			return
		}
		if err != nil {
			fmt.Println("ERR:", err)
			return
		}
	}
}
