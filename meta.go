package hdnfs

import (
	"encoding/binary"
	"encoding/json"
	"strconv"
)

func WriteMeta(file F, m *Meta) {
	mb, err := json.Marshal(m)
	if err != nil {
		PrintError("Unable to create json meta:", err)
		return
	}

	mb = Encrypt(mb, GetEncKey())
	originalLength := len(mb)
	missing := META_FILE_SIZE - len(mb) - 4
	mb = append([]byte{0, 0, 0, 0}, mb...)
	binary.BigEndian.PutUint32(mb[0:4], uint32(originalLength))
	mb = append(mb, make([]byte, missing, missing)...)
	// PrintError(len(mb))

	_, err = file.Seek(0, 0)
	if err != nil {
		PrintError("Unable to seek meta:", err)
		return
	}

	n, err := file.Write(mb)
	if err != nil {
		PrintError("Unable to write meta:", err)
		return
	}
	if n != len(mb) {
		PrintError("Short meta write: "+strconv.Itoa(n), nil)
		return
	}
}

func InitFileMeta(file F) {
	return
}

func InitMeta(file F) {
	m := new(Meta)
	mb, err := json.Marshal(m)
	if err != nil {
		PrintError("unable to create json metadata", err)
		return
	}
	_, err = file.Seek(0, 0)
	if err != nil {
		PrintError("unable to seek on [device]:", err)
		return
	}

	mb = Encrypt(mb, GetEncKey())
	originalLength := len(mb)
	missing := META_FILE_SIZE - len(mb) - 4
	mb = append([]byte{0, 0, 0, 0}, mb...)
	binary.BigEndian.PutUint32(mb[0:4], uint32(originalLength))
	mb = append(mb, make([]byte, missing, missing)...)

	n, err := file.Write(mb)
	if err != nil {
		PrintError("Unable to write meta:", err)
		return
	}
	if n != len(mb) {
		PrintError("Short meta write: "+strconv.Itoa(n), nil)
		return
	}
}

func ReadMeta(file F) (m *Meta) {
	metaBuff := make([]byte, META_FILE_SIZE, META_FILE_SIZE)
	_, err := file.Seek(0, 0)
	if err != nil {
		PrintError("Error seeking meta file:", err)
		return
	}

	n, err := file.Read(metaBuff[0:META_FILE_SIZE])
	if err != nil {
		PrintError("Error reading meta file:", err)
		return
	}

	if n != META_FILE_SIZE {
		PrintError("Short meta read: "+strconv.Itoa(n), nil)
		return
	}

	length := binary.BigEndian.Uint32(metaBuff[0:4])
	metaData := Decrypt(metaBuff[4:4+length], GetEncKey())
	// PrintError(nb)
	// PrintError(string(nb))
	m = new(Meta)
	err = json.Unmarshal(metaData, m)
	if err != nil {
		PrintError("Unable to decode meta:", err)
		return

	}

	return
}
