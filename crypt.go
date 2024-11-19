package hdnfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
)

func Decrypt(text, key []byte) (out []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println("ENC ERR:", err)
		return nil
	}
	if len(text) < aes.BlockSize {
		// log.Println(string(text))
		// log.Println(string(key))
		log.Println("CYPHER TOO SHORT")
		return nil
	}

	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	out = make([]byte, len(text))
	cfb.XORKeyStream(out, text)
	data, err := base64.StdEncoding.DecodeString(string(out))
	if err != nil {
		log.Println("DATA ERROR", err)
		return nil
	}
	return data
}

func GetKey(bytes []byte, key []byte) string {
	out := Decrypt(bytes, key)
	outs := string(out)
	split := strings.Split(outs, ":")
	return split[1]
}

func StringToBytes(k string) (out []byte) {
	splitK := strings.Split(k, "-")
	for _, b := range splitK {
		bi, err := strconv.Atoi(b)
		if err != nil {
			log.Println("UNABLE TO PARSE KEY", err)
			os.Exit(1)
		}
		out = append(out, byte(bi))
	}

	return
}

func Encrypt(text, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
		return nil
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Println(err)
		return nil
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext
}
