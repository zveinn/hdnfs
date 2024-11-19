package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/zveinn/hdnfs"
)

var (
	drive  string
	remove string

	start int64

	diskPointer *os.File
)

// drive cmd params..
func main() {
	if len(os.Args) < 3 {
		fmt.Println("No enough arguments")
		os.Exit(0)
	}

	drive = os.Args[1]
	if drive == "" {
		fmt.Println("drive missing")
		os.Exit(0)
	}
	cmd := os.Args[2]
	if cmd == "" {
		fmt.Println("cmd missing")
		os.Exit(0)
	}
	// fmt.Println(os.Args)
	// fmt.Println("CMD:", cmd)
	// fmt.Println("DRIVE:", drive)

	file, err := os.OpenFile(drive, os.O_RDWR, 0o777)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	switch cmd {
	case "erase":
		var startIndex int
		if len(os.Args) > 3 {
			startIndex, err = strconv.Atoi(os.Args[3])
			if err != nil {
				fmt.Println("Invalid starting index:", err)
				os.Exit(0)
			}
		}
		hdnfs.Erase(file, int64(startIndex))
	case "init":
		hdnfs.InitMeta(file)
	case "add":
		var index int
		var path, name string
		if len(os.Args) < 5 {
			fmt.Println("Not enough arguments")
			os.Exit(0)
		}
		if len(os.Args) > 5 {
			index, err = strconv.Atoi(os.Args[5])
			if err != nil {
				fmt.Println("Index is not a valid int")
				os.Exit(0)
			}
		} else {
			index = hdnfs.OUT_OF_BOUNDS_INDEX
		}
		path = os.Args[3]
		if path == "" {
			fmt.Println("No local file selected")
			os.Exit(0)
		}
		name = os.Args[4]
		hdnfs.Add(file, path, name, index)
	case "get":
		var path string
		if len(os.Args) < 5 {
			fmt.Println("Not enough arguments")
			os.Exit(0)
		}
		index, err := strconv.Atoi(os.Args[3])
		if err != nil {
			fmt.Println("Index is not a valid int")
			os.Exit(0)
		}
		path = os.Args[4]
		hdnfs.Get(file, index, path)
	case "del":
		index, err := strconv.Atoi(os.Args[3])
		if err != nil {
			fmt.Println("Index is not a valid int")
			os.Exit(0)
		}
		hdnfs.Del(file, index)
	case "list":
		hdnfs.List(file)
	case "stat":
		hdnfs.Stat(file)
	case "lock":
		// hdnfs.Lock(file, []byte("01234567890123456789012345678900"))
	default:
		fmt.Println("Unknown command...")
	}
}
