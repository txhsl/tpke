/*
Copyright 2023 Jan Lauinger

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package circom

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"golang.org/x/crypto/sha3"
	"math/rand"
	"testing"
	"time"
)

// AES gcm testing
type GCM256Wrapper struct {
	Key          [32]frontend.Variable
	PlainChunks  []frontend.Variable
	Iv           [12]frontend.Variable `gnark:",public"`
	ChunkIndex   frontend.Variable     `gnark:",public"`
	CipherChunks []frontend.Variable   `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *GCM256Wrapper) Define(api frontend.API) error {

	aes := NewAES256(api)

	gcm := NewGCM256(api, &aes)

	// verify aes gcm of chunks
	gcm.Assert256(circuit.Key, circuit.Iv, circuit.ChunkIndex, circuit.PlainChunks, circuit.CipherChunks)

	return nil
}

type AES interface {
	Encrypt(key [32]frontend.Variable, pt [16]frontend.Variable) [16]frontend.Variable
}

func NewGCM256(api frontend.API, aes AES) GCM256 {
	return GCM256{api: api, aes: aes}
}

type GCM256 struct {
	api frontend.API
	aes AES
}

// aes gcm encryption
func (gcm *GCM256) Assert256(key [32]frontend.Variable, iv [12]frontend.Variable, chunkIndex frontend.Variable, plaintext, ciphertext []frontend.Variable) {

	inputSize := len(plaintext)
	numberBlocks := int(inputSize / 16)
	var epoch int
	for epoch = 0; epoch < numberBlocks; epoch++ {

		idx := gcm.api.Add(chunkIndex, frontend.Variable(epoch))
		eIndex := epoch * 16

		var ptBlock [16]frontend.Variable
		var ctBlock [16]frontend.Variable

		for j := 0; j < 16; j++ {
			ptBlock[j] = plaintext[eIndex+j]
			ctBlock[j] = ciphertext[eIndex+j]
		}

		ivCounter := gcm.GetIV256(iv, idx)
		intermediate := gcm.aes.Encrypt(key, ivCounter)
		ct := gcm.Xor16256(intermediate, ptBlock)

		// check ciphertext to plaintext constraints
		for i := 0; i < 16; i++ {
			gcm.api.AssertIsEqual(ctBlock[i], ct[i])
		}
	}
}

// required for aes_gcm
func (gcm *GCM256) GetIV256(nonce [12]frontend.Variable, ctr frontend.Variable) [16]frontend.Variable {

	var out [16]frontend.Variable
	var i int
	for i = 0; i < len(nonce); i++ {
		out[i] = nonce[i]
	}
	bits := gcm.api.ToBinary(ctr, 32)
	remain := 12
	for j := 3; j >= 0; j-- {
		start := 8 * j
		// little endian order chunk parsing from back to front
		out[remain] = gcm.api.FromBinary(bits[start : start+8]...)
		remain += 1
	}

	return out
}

// required for plaintext xor encrypted counter blocks
func (gcm *GCM256) Xor16256(a [16]frontend.Variable, b [16]frontend.Variable) [16]frontend.Variable {

	var out [16]frontend.Variable
	for i := 0; i < 16; i++ {
		out[i] = gcm.variableXor256(a[i], b[i], 8)
	}
	return out
}

func (gcm *GCM256) variableXor256(a frontend.Variable, b frontend.Variable, size int) frontend.Variable {
	bitsA := gcm.api.ToBinary(a, size)
	bitsB := gcm.api.ToBinary(b, size)
	x := make([]frontend.Variable, size)
	for i := 0; i < size; i++ {
		x[i] = gcm.api.Xor(bitsA[i], bitsB[i])
	}
	return gcm.api.FromBinary(x...)
}

func TestAESGCM256Circuit(t *testing.T) {

	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	privKey, err := ecies.GenerateKey(rand, crypto.S256(), nil)
	if err != nil {
		return
	}
	var px fp.Element
	px.SetInterface(privKey.PublicKey.X)
	var py fp.Element
	py.SetInterface(privKey.PublicKey.Y)
	Pub := secp256k1.G1Affine{
		px,
		py,
	}
	RawKey := Pub.RawBytes()
	//m := RawKey[:]
	//m := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D}
	//m := []byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34}
	m := []byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34, 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34}
	M_bytes := make([]frontend.Variable, len(m))
	for i := 0; i < len(m); i++ {
		M_bytes[i] = m[i]
	}

	hasher := sha3.New256()
	hasher.Write(RawKey[:])
	//expected := hasher.Sum(nil)
	expected := [32]byte{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}
	keyBytes := [32]frontend.Variable{}
	for i := 0; i < len(keyBytes); i++ {
		keyBytes[i] = expected[i]
	}

	ciphertext, nonce := AesGcmEncrypt(expected[:], m)
	//iphertext = ciphertext[len(nonce):]
	t.Logf("out aesencrypt,m:%x", m)
	t.Logf("out aesencrypt,ciphertext:%x", ciphertext)
	t.Logf("out aesencrypt,nonce:%x", nonce)
	Ciphertext_bytes := make([]frontend.Variable, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		Ciphertext_bytes[i] = ciphertext[i]
	}
	nonce_bytes := [12]frontend.Variable{}
	for i := 0; i < len(nonce); i++ {
		nonce_bytes[i] = nonce[i]
	}

	/*	var ChunkIndex int
		if len(ciphertext)%16 == 0 {
			ChunkIndex = len(ciphertext) / 16
		} else {
			ChunkIndex = len(ciphertext)/16 + 1
		}*/
	var ChunkIndex int
	ChunkIndex |= int(0) << 24
	ChunkIndex |= int(1) << 31
	/*	ChunkIndex |= int(nonce[0])
		ChunkIndex |= int(nonce[1]) << 8
		ChunkIndex |= int(nonce[2]) << 16
		ChunkIndex |= int(nonce[3]) << 24
		ChunkIndex |= 1*/
	circuit := GCM256Wrapper{
		PlainChunks:  make([]frontend.Variable, len(M_bytes)),
		CipherChunks: make([]frontend.Variable, len(Ciphertext_bytes)),
	}
	witness := GCM256Wrapper{
		Key:         keyBytes,
		PlainChunks: M_bytes,
		Iv:          nonce_bytes,
		ChunkIndex:  2,
		//ChunkIndex:   ChunkIndex,
		CipherChunks: Ciphertext_bytes,
	}

	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
