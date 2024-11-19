package hdnfs

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
)

func WriteMeta(file *os.File, m *Meta) {
	mb, err := json.Marshal(m)
	if err != nil {
		fmt.Println("Unable to create json meta:", err)
		return
	}

	mb = Encrypt(mb, GetEncKey())
	originalLength := len(mb)
	missing := META_FILE_SIZE - len(mb) - 4
	mb = append([]byte{0, 0, 0, 0}, mb...)
	binary.BigEndian.PutUint32(mb[0:4], uint32(originalLength))
	mb = append(mb, make([]byte, missing, missing)...)
	fmt.Println("OL:", originalLength)
	// fmt.Println(len(mb))

	_, err = file.Seek(0, 0)
	if err != nil {
		fmt.Println("Unable to seek meta:", err)
		return
	}

	n, err := file.Write(mb)
	if err != nil {
		fmt.Println("Unable to write meta:", err)
		return
	}
	if n != len(mb) {
		fmt.Println("Short meta write:", n)
		return
	}
}

func InitMeta(file *os.File) {
	m := new(Meta)
	mb, err := json.Marshal(m)
	if err != nil {
		fmt.Println("Unable to create json meta:", err)
		return
	}
	_, err = file.Seek(0, 0)
	if err != nil {
		fmt.Println("Unable to seek meta:", err)
		return
	}

	mb = Encrypt(mb, GetEncKey())
	originalLength := len(mb)
	missing := META_FILE_SIZE - len(mb) - 4
	mb = append([]byte{0, 0, 0, 0}, mb...)
	binary.BigEndian.PutUint32(mb[0:4], uint32(originalLength))
	mb = append(mb, make([]byte, missing, missing)...)
	fmt.Println("OL:", originalLength)

	n, err := file.Write(mb)
	if err != nil {
		fmt.Println("Unable to write meta:", err)
		return
	}
	if n != len(mb) {
		fmt.Println("Short meta write:", n)
		return
	}
}

func ReadMeta(file *os.File) (m *Meta) {
	metaBuff := make([]byte, META_FILE_SIZE, META_FILE_SIZE)
	_, err := file.Seek(0, 0)
	if err != nil {
		fmt.Println("Error seeking meta file:", err)
		return
	}

	n, err := file.Read(metaBuff[0:META_FILE_SIZE])
	if err != nil {
		fmt.Println("Error reading meta file:", err)
		return
	}

	if n != META_FILE_SIZE {
		fmt.Println("Meta file short read:", n)
		return
	}

	length := binary.BigEndian.Uint32(metaBuff[0:4])
	fmt.Println("meta length:", length)
	metaData := Decrypt(metaBuff[4:4+length], GetEncKey())
	// fmt.Println(nb)
	// fmt.Println(string(nb))
	m = new(Meta)
	err = json.Unmarshal(metaData, m)
	if err != nil {
		fmt.Println("Unable to decode meta:", err)
		return

	}

	return
}
