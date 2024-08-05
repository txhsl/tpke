package circom

import (
	"crypto/rand"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"math/big"
	"testing"
)

type EccCircuit[T, S emulated.FieldParams] struct {
	Cpr  CipherText[T]
	Msg  emulated.Element[S]
	Rand emulated.Element[S]
	Pub  PublicKey[T, S]
}

func (c *EccCircuit[T, S]) Define(api frontend.API) error {
	c.Pub.VerifyEncrypt(api, sw_emulated.GetCurveParams[T](), &c.Msg, &c.Rand, &c.Cpr)
	return nil
}

func TestCircuit(t *testing.T) {
	// generate parameters
	privKey, _ := ecdsa.GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	fi, err := rand.Int(rand.Reader, max)
	if err != nil {
		return
	}

	//fi as x to get y,to build keypoint
	_, k1256_g1 := secp256k1.Generators()
	var keyPoint secp256k1.G1Affine
	keyPoint.ScalarMultiplication(&k1256_g1, fi)

	//C=M+rpk, R1=rG1
	Randr, err := rand.Int(rand.Reader, max)
	if err != nil {
		return
	}
	t.Logf("Randr : %v", Randr.String())

	_, g1 := secp256k1.Generators()
	var R secp256k1.G1Affine
	R.ScalarMultiplication(&g1, Randr)

	var CPoint secp256k1.G1Affine
	var temp secp256k1.G1Affine
	temp.ScalarMultiplication(&publicKey.A, Randr)
	CPoint.Add(&keyPoint, &temp)

	exx := EccCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}

	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &exx)
	if err != nil {
		t.Fatalf(err.Error())
	}
	//初始化
	pk, vk, _ := doMPCSetUp(css)
	// 1. One time setup
	err = groth16.Setup(css.(*cs.R1CS), &pk, &vk)
	if err != nil {
		t.Fatalf(err.Error())
	}

	//提供输入输出
	assignment := &EccCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{

		Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](publicKey.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](publicKey.A.Y),
		},
		Cpr: CipherText[emulated.Secp256k1Fp]{
			C: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](CPoint.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](CPoint.Y),
			},
			R: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](R.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](R.Y),
			},
		},
		Rand: emulated.ValueOf[emulated.Secp256k1Fr](Randr),
		Msg:  emulated.ValueOf[emulated.Secp256k1Fr](fi),
	}
	//计算witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf(err.Error())
	}
	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf(err.Error())
	}
	// 计算证明
	proof, err := groth16.Prove(css.(*cs.R1CS), &pk, witness)
	if err != nil {
		t.Fatalf(err.Error())
	}
	//验证证明
	err = groth16.Verify(proof, &vk, publicWitness.Vector().(fr_bn254.Vector))
	if err != nil {
		return
	}
	t.Logf("circom test ok ")
}
