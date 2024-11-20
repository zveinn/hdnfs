package hdnfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"os"
)

func Decrypt(text, key []byte) (out []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		PrintError("ENC ERR:", err)
		os.Exit(1)
	}
	if len(text) < aes.BlockSize {
		PrintError("CYPHER TOO SHORT", nil)
		os.Exit(1)
	}

	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	out = make([]byte, len(text))
	cfb.XORKeyStream(out, text)
	return out
}

func Encrypt(text, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		PrintError("unable to create new cypher", err)
		os.Exit(1)
	}
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		PrintError("unable to read random bytes into padding block", err)
		os.Exit(1)
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text))
	return ciphertext
}
