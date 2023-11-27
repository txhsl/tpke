package tpke

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"

	"github.com/phoreproject/bls"
)

func AESEncrypt(g1 *bls.G1Projective, msg []byte) ([]byte, error) {
	if len(msg) < 1 {
		return nil, NewAESMessageError()
	}
	// Take g1 as the input of sha256 to generate an aes key
	seed := g1.ToAffine().SerializeBytes()
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

func AESDecrypt(g1 *bls.G1Projective, cipherText []byte) ([]byte, error) {
	if len(cipherText) < 1 {
		return nil, NewAESCiphertextError()
	}
	// Take g1 as the input of sha256 to generate an aes key
	seed := g1.ToAffine().SerializeBytes()
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
