package hdnfs

import (
	"fmt"
	"os"
	"runtime/debug"
)

// META: 1_000_000:1_000_000*2
// FILE1: 1_000_000*2:1_000_000*3

type F interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	Seek(int64, int) (int64, error)
	Name() string
	Sync() error
}

var (
	DISK      = "/dev/sda"
	HDNFS_ENV = "HDNFS"
)

func PrintError(msg string, err error) {
	fmt.Println("----------------------------")
	fmt.Println("MSG:", msg)
	if err != nil {
		fmt.Println("ERROR:", err)
	}
	fmt.Println("----------------------------")
	fmt.Println(string(debug.Stack()))
	fmt.Println("----------------------------")
}

func GetEncKey() (key []byte) {
	k := os.Getenv(HDNFS_ENV)
	if k == "" {
		panic("HDNFS not defined")
	}

	if len(k) < 32 {
		panic("HDNFS less then 32 bytes long")
	}

	key = []byte(k)

	return
}

const (
	META_FILE_SIZE      = 200_000
	MAX_FILE_SIZE       = 50_000
	MAX_FILE_NAME_SIZE  = 100
	TOTAL_FILES         = 1000
	OUT_OF_BOUNDS_INDEX = 99999999
)

type Meta struct {
	Files [TOTAL_FILES]File
}

// 8:8:84
type File struct {
	Name string
	Size int
}
