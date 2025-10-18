package main

import (
	"fmt"
	"os"
)

func Cat(file *os.File, start, end int64) {
	buf := make([]byte, end-start)
	_, err := file.Seek(start, 0)
	if err != nil {
		fmt.Println("Seek error:", err)
		return
	}
	n, err := file.Read(buf)
	if err != nil {
		fmt.Println("Read error:", err)
		return
	}
	fmt.Println("Read ", n, " bytes")
	fmt.Println(buf[:n])
	fmt.Println(string(buf[:n]))
}
