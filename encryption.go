package tpke

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"math/rand"
	"time"

	bls "github.com/kilic/bls12-381"
)

func AESEncrypt(pg1 *bls.PointG1, msg []byte) ([]byte, error) {
	if len(msg) < 1 {
		return nil, NewAESMessageError()
	}
	// Take pg1 as the input of sha256 to generate an aes key
	seed := bls.NewG1().ToBytes(pg1)
	hash := sha256.Sum256(seed[0:96])
	block, err := aes.NewCipher(hash[0:32])
	if err != nil {
		return nil, NewAESEncryptionError()
	}
	blockSize := block.BlockSize()

	data := pkcs7Padding(msg, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, hash[:blockSize])
	encrypted := make([]byte, len(data))
	blockMode.CryptBlocks(encrypted, data)

	return encrypted, nil
}

func AESDecrypt(pg1 *bls.PointG1, cipherText []byte) ([]byte, error) {
	if len(cipherText) < 1 {
		return nil, NewAESCiphertextError()
	}
	// Take pg1 as the input of sha256 to generate an aes key
	seed := bls.NewG1().ToBytes(pg1)
	hash := sha256.Sum256(seed[0:96])
	block, err := aes.NewCipher(hash[0:32])
	if err != nil {
		return nil, NewAESDecryptionError()
	}
	blockSize := block.BlockSize()

	blockMode := cipher.NewCBCDecrypter(block, hash[:blockSize])
	decrypted := make([]byte, len(cipherText))
	blockMode.CryptBlocks(decrypted, cipherText)
	result, err := pkcs7UnPadding(decrypted)
	if err != nil {
		return nil, NewAESError(err.Error())
	}

	return result, nil
}

func RandPG1() *bls.PointG1 {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	r, _ := bls.NewFr().Rand(r1)
	g1 := bls.NewG1()
	pg1 := g1.New()
	return g1.MulScalar(pg1, &bls.G1One, r)
}
