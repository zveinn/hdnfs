package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/zveinn/hdnfs"
)

type File struct {
	Name  string
	Index int
	Size  int
}

type Meta struct {
	Files [1000]File
}

func main() {
	file, err := os.OpenFile("/dev/sda", os.O_RDWR, 0o777)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	hdnfs.Cat(file, hdnfs.META_FILE_SIZE, hdnfs.META_FILE_SIZE+2000)

}

func zzerobytes() {
	x := new(Meta)
	x.Files[0] = File{Name: "meow!", Index: 1, Size: 10}

	xb, err := json.Marshal(x)
	if err != nil {
		panic(err)
	}
	xb = append(xb, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}...)
	xx := new(Meta)

	xb = bytes.ReplaceAll(xb, []byte{0}, []byte{})
	err = json.Unmarshal(xb, xx)
	if err != nil {
		panic(err)
	}

	fmt.Println(xx)
}
