package circom

import (
	"crypto/rand"
	"io"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

const (
	sizeFr         = fr.Bytes
	sizeFrBits     = fr.Bits
	sizeFp         = fp.Bytes
	sizePublicKey  = 2 * sizeFp
	sizePrivateKey = sizeFr + sizePublicKey
	sizeSignature  = 2 * sizeFr
)

var order = fr.Modulus()
var one = new(big.Int).SetInt64(1)

type PK struct {
	A secp256k1.G1Affine
}

type SK struct {
	PublicKey PK
	scalar    [sizeFr]byte // secret scalar, in big Endian
}

type CT struct {
	C secp256k1.G1Affine
	R secp256k1.G1Affine
}

type EccCircuit[T, S emulated.FieldParams] struct {
	Cpr CipherText[T]
	Msg emulated.Element[S]
	R   emulated.Element[S]
	Pub PublicKey[T, S]
}

func (c *EccCircuit[T, S]) Define(api frontend.API) error {
	c.Pub.VerifyEncrypt(api, sw_emulated.GetCurveParams[T](), &c.Msg, &c.R, &c.Cpr)
	return nil
}

func TestEcdsaEncryptionCircuit1(t *testing.T) {
	privKey, _ := generateKey(rand.Reader)
	publicKey := privKey.PublicKey

	msg, err := randFieldElement(rand.Reader)
	if err != nil {
		t.Errorf(err.Error())
	}
	r, err := randFieldElement(rand.Reader)
	if err != nil {
		t.Errorf(err.Error())
	}

	cipher := publicKey.Encrypt(msg, r)

	circuit := EccCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := EccCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Cpr: CipherText[emulated.Secp256k1Fp]{
			C: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](cipher.C.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](cipher.C.Y),
			},
			R: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](cipher.R.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](cipher.R.Y),
			},
		},
		Msg: emulated.ValueOf[emulated.Secp256k1Fr](msg),
		R:   emulated.ValueOf[emulated.Secp256k1Fr](r),
		Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](publicKey.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](publicKey.A.Y),
		},
	}

	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func generateKey(rand io.Reader) (*SK, error) {
	k, err := randFieldElement(rand)
	if err != nil {
		return nil, err

	}
	_, g := secp256k1.Generators()

	privateKey := new(SK)
	k.FillBytes(privateKey.scalar[:sizeFr])
	privateKey.PublicKey.A.ScalarMultiplication(&g, k)
	return privateKey, nil
}

func randFieldElement(rand io.Reader) (k *big.Int, err error) {
	b := make([]byte, fr.Bits/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(order, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func (pk *PK) Encrypt(msg *big.Int, r *big.Int) *CT {
	ct := new(CT)
	bigM := new(secp256k1.G1Affine)
	// R
	ct.R.ScalarMultiplicationBase(r)
	// C
	ct.C.ScalarMultiplication(&pk.A, r)
	bigM.ScalarMultiplicationBase(msg)
	ct.C.Add(&ct.C, bigM)
	return ct
}
