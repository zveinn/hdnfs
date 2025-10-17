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

	MAGIC_SIZE     = 5
	VERSION_SIZE   = 1
	RESERVED_SIZE  = 2
	SALT_SIZE      = 32
	LENGTH_SIZE    = 4
	CHECKSUM_SIZE  = 32
	HEADER_SIZE    = MAGIC_SIZE + VERSION_SIZE + RESERVED_SIZE + SALT_SIZE + LENGTH_SIZE

	METADATA_VERSION = 2
)

const (
	MAGIC_STRING = "HDNFS"
)

var HDNFS_ENV = "HDNFS"

var Silent = false

type Meta struct {
	Version int
	Salt    []byte
	Files   [TOTAL_FILES]File
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

func Print(a ...interface{}) {
	if !Silent {
		fmt.Print(a...)
	}
}

func Println(a ...interface{}) {
	if !Silent {
		fmt.Println(a...)
	}
}

func Printf(format string, a ...interface{}) {
	if !Silent {
		fmt.Printf(format, a...)
	}
}
