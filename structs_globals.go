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

	// Metadata format constants
	MAGIC_SIZE     = 5  // "HDNFS"
	VERSION_SIZE   = 1  // Version byte
	RESERVED_SIZE  = 2  // Reserved for future use
	SALT_SIZE      = 32 // Argon2 salt
	LENGTH_SIZE    = 4  // uint32 length
	CHECKSUM_SIZE  = 32 // SHA-256 checksum
	HEADER_SIZE    = MAGIC_SIZE + VERSION_SIZE + RESERVED_SIZE + SALT_SIZE + LENGTH_SIZE // 44 bytes

	// Current metadata version
	METADATA_VERSION = 2 // Version 2: GCM + Argon2 + checksums
)

const (
	MAGIC_STRING = "HDNFS"
)

var HDNFS_ENV = "HDNFS"

type Meta struct {
	Version int               // Metadata format version
	Salt    []byte            // Salt for key derivation (stored separately in header)
	Files   [TOTAL_FILES]File // File entries
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
