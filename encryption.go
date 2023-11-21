package tpke

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"

	"github.com/phoreproject/bls"
)

func AESEncrypt(g1 *bls.G1Projective, msg []byte) ([]byte, error) {
	if len(msg) < 1 {
		return nil, errors.New("empty message")
	}
	seed := g1.ToAffine().SerializeBytes()
	hash := sha256.Sum256(seed[0:96])
	block, _ := aes.NewCipher(hash[0:32])
	blockSize := block.BlockSize()

	data := pkcs7Padding(msg, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, hash[:blockSize])
	encrypted := make([]byte, len(data))
	blockMode.CryptBlocks(encrypted, data)

	return encrypted, nil
}

func AESDecrypt(g1 *bls.G1Projective, cipherText []byte) ([]byte, error) {
	if len(cipherText) < 1 {
		return nil, errors.New("empty ciphertext")
	}
	seed := g1.ToAffine().SerializeBytes()
	hash := sha256.Sum256(seed[0:96])
	block, _ := aes.NewCipher(hash[0:32])
	blockSize := block.BlockSize()

	blockMode := cipher.NewCBCDecrypter(block, hash[:blockSize])
	decrypted := make([]byte, len(cipherText))
	blockMode.CryptBlocks(decrypted, cipherText)
	result, _ := pkcs7UnPadding(decrypted)

	return result, nil
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("empty array")
	}
	unPadding := int(data[length-1])
	return data[:(length - unPadding)], nil
}
