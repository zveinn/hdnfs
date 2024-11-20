package hdnfs

import (
	"fmt"
	"runtime/debug"
)

const (
	META_FILE_SIZE      = 200_000
	MAX_FILE_SIZE       = 50_000
	MAX_FILE_NAME_SIZE  = 100
	TOTAL_FILES         = 1000
	ERASE_CHUNK_SIZE    = 1_000_000
	OUT_OF_BOUNDS_INDEX = 99999999
)

var HDNFS_ENV = "HDNFS"

type Meta struct {
	Files [TOTAL_FILES]File
}

type File struct {
	Name string
	Size int
}

type F interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	Seek(int64, int) (int64, error)
	Name() string
	Sync() error
}

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
