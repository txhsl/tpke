package circom

import (
	"crypto/rand"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"math/big"
	"testing"
)

// test circom
type MyCircuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
}

func (circuit *MyCircuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

func TestCircom(t *testing.T) {
	//编译电路
	var myCircuit MyCircuit
	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
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
	assignment := &MyCircuit{
		X: 3,
		Y: 35,
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

func doMPCSetUp(ccs constraint.ConstraintSystem) (pk groth16.ProvingKey, vk groth16.VerifyingKey, err error) {
	const (
		nContributionsPhase1 = 3
		nContributionsPhase2 = 3
		power                = 9 //2^9 元素个数
	)

	srs1 := mpcsetup.InitPhase1(power)

	// Make and verify contributions for phase1
	for i := 1; i < nContributionsPhase1; i++ {
		// we clone test purposes; but in practice, participant will receive a []byte, deserialize it,
		// add his contribution and send back to coordinator.
		prev := Phase1clone(srs1)

		srs1.Contribute()
		err := mpcsetup.VerifyPhase1(&prev, &srs1)
		if err != nil {
			return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
		}
	}

	// Prepare for phase-1.5
	var evals mpcsetup.Phase2Evaluations
	r1cs := ccs.(*cs.R1CS)
	// Prepare for phase-2
	srs2, evals := mpcsetup.InitPhase2(r1cs, &srs1)
	// Make and verify contributions for phase1
	for i := 1; i < nContributionsPhase2; i++ {
		// we clone for test purposes; but in practice, participant will receive a []byte, deserialize it,
		// add his contribution and send back to coordinator.
		prev := Phase2clone(srs2)

		srs2.Contribute()
		err := mpcsetup.VerifyPhase2(&prev, &srs2)
		if err != nil {
			return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
		}
	}

	// Extract the proving and verifying keys
	pk, vk = mpcsetup.ExtractKeys(&srs1, &srs2, &evals, ccs.GetNbConstraints())
	return pk, vk, nil
}

func Phase1clone(phase1 mpcsetup.Phase1) mpcsetup.Phase1 {
	r := mpcsetup.Phase1{}
	r.Parameters.G1.Tau = append(r.Parameters.G1.Tau, phase1.Parameters.G1.Tau...)
	r.Parameters.G1.AlphaTau = append(r.Parameters.G1.AlphaTau, phase1.Parameters.G1.AlphaTau...)
	r.Parameters.G1.BetaTau = append(r.Parameters.G1.BetaTau, phase1.Parameters.G1.BetaTau...)

	r.Parameters.G2.Tau = append(r.Parameters.G2.Tau, phase1.Parameters.G2.Tau...)
	r.Parameters.G2.Beta = phase1.Parameters.G2.Beta

	r.PublicKeys = phase1.PublicKeys
	r.Hash = append(r.Hash, phase1.Hash...)
	return r
}

func Phase2clone(phase2 mpcsetup.Phase2) mpcsetup.Phase2 {
	r := mpcsetup.Phase2{}
	r.Parameters.G1.Delta = phase2.Parameters.G1.Delta
	r.Parameters.G1.L = append(r.Parameters.G1.L, phase2.Parameters.G1.L...)
	r.Parameters.G1.Z = append(r.Parameters.G1.Z, phase2.Parameters.G1.Z...)
	r.Parameters.G2.Delta = phase2.Parameters.G2.Delta
	r.PublicKey = phase2.PublicKey
	r.Hash = append(r.Hash, phase2.Hash...)
	return r
}

func TestEcdsaEncryptionCircuit(t *testing.T) {
	// generate parameters
	privKey, _ := ecdsa.GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey

	_, keyPoint := secp256k1.Generators()

	//C=M+rpk, R1=rG1
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	r, err := rand.Int(rand.Reader, max)
	if err != nil {
		return
	}

	_, R := secp256k1.Generators()
	R.ScalarMultiplicationBase(r)

	_, CPoint := secp256k1.Generators()
	temp := publicKey.A.ScalarMultiplicationBase(r)
	CPoint.Add(&keyPoint, temp)
	//C=M+rpk, R1=rG1

	var ecdsaEC ECDSAEncryptionCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &ecdsaEC)
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
	assignment := &ECDSAEncryptionCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		PublicKey_X:  publicKey.A.X,
		PublicKey_Y:  publicKey.A.Y,
		CipherText_X: CPoint.X,
		CipherText_Y: CPoint.Y,
		//R_X:          R.X,
		//R_Y:          R.Y,

		KeyPoint_X: keyPoint.X,
		KeyPoint_Y: keyPoint.Y,

		//r: emulated.ValueOf[emulated.Secp256k1Fr](r),
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

type ECDSAEncryptionCircuit[Base, Scalar emulated.FieldParams] struct {
	PublicKey_X frontend.Variable `gnark:",public"`
	PublicKey_Y frontend.Variable `gnark:",public"`

	CipherText_X frontend.Variable `gnark:",public"`
	CipherText_Y frontend.Variable `gnark:",public"`

	//R_X frontend.Variable `gnark:",public"`
	//R_Y frontend.Variable `gnark:",public"`

	KeyPoint_X frontend.Variable
	KeyPoint_Y frontend.Variable

	//r emulated.Element[Scalar]
}

func (circuit *ECDSAEncryptionCircuit[Base, Scalar]) Define(api frontend.API) error {

	PublicKey := sw_emulated.AffinePoint[Base]{X: emulated.ValueOf[Base](circuit.PublicKey_X), Y: emulated.ValueOf[Base](circuit.PublicKey_Y)}
	CipherText := sw_emulated.AffinePoint[Base]{X: emulated.ValueOf[Base](circuit.CipherText_X), Y: emulated.ValueOf[Base](circuit.CipherText_Y)}
	//R := sw_emulated.AffinePoint[Base]{X: emulated.ValueOf[Base](circuit.R_X), Y: emulated.ValueOf[Base](circuit.R_Y)}
	KeyPoint := sw_emulated.AffinePoint[Base]{X: emulated.ValueOf[Base](circuit.KeyPoint_X), Y: emulated.ValueOf[Base](circuit.KeyPoint_Y)}

	/*	CipherText CipherText[Base] `gnark:",public"`
		R          R[Base]          `gnark:",public"`
		KeyPoint   KeyPoint[Base]
		r          big.Int*/

	//encrypt[Base, Scalar](api, sw_emulated.GetCurveParams[Base](), circuit.r, KeyPoint, CipherText, PublicKey)
	cr, err := sw_emulated.New[Base, Scalar](api, sw_emulated.GetCurveParams[Base]())
	if err != nil {
		// TODO: softer handling.
		panic(err)
	}
	cr.AssertIsEqual(&PublicKey, &CipherText)
	cr.AssertIsEqual(&KeyPoint, &KeyPoint)
	cr.AssertIsEqual(&CipherText, &CipherText)
	return nil
}

/*
type PublicKey[Base emulated.FieldParams] sw_emulated.AffinePoint[Base]

type CipherText[Base emulated.FieldParams] sw_emulated.AffinePoint[Base]

type KeyPoint[Base emulated.FieldParams] sw_emulated.AffinePoint[Base]

type R[Base emulated.FieldParams] sw_emulated.AffinePoint[Base]
*/
func encrypt[T, S emulated.FieldParams](api frontend.API, params sw_emulated.CurveParams, r emulated.Element[S], keyPoint sw_emulated.AffinePoint[T], ciptext sw_emulated.AffinePoint[T], PublicKey sw_emulated.AffinePoint[T]) {
	cr, err := sw_emulated.New[T, S](api, params)
	if err != nil {
		// TODO: softer handling.
		panic(err)
	}
	/*	scalarApi, err := emulated.NewField[S](api)
		if err != nil {
			panic(err)
		}
		baseApi, err := emulated.NewField[T](api)
		if err != nil {
			panic(err)
		}*/
	mul := cr.ScalarMul(&PublicKey, &r)

	result := cr.AddUnified(mul, &keyPoint)

	cptt := sw_emulated.AffinePoint[T](ciptext)
	cr.AssertIsEqual(result, &cptt)
}
