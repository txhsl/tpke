package circom

import (
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	bls "github.com/kilic/bls12-381"
	"math/big"
	"math/rand"
	"testing"
	"time"
)

// test circom
type MyCircuit[S emulated.FieldParams] struct {
	X *big.Int `gnark:",public"`
}

func (circuit *MyCircuit[S]) Define(api frontend.API) error {
	f, err := emulated.NewField[S](api)
	if err != nil {
		return err
	}
	R := f.NewElement(circuit.X)
	api.Println("result", R)
	return nil
}

func TestCircom(t *testing.T) {
	//编译电路
	var myCircuit MyCircuit[emulated.Secp256k1Fr]
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
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)
	r := big.NewInt(int64(random.Uint64()))
	//提供输入输出
	assignment := &MyCircuit[emulated.Secp256k1Fr]{
		X: r,
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
		power                = 3 //2^9 元素个数
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
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)
	privKey, err := ecies.GenerateKey(random, crypto.S256(), nil)
	if err != nil {
		return
	}
	publicKey := privKey.PublicKey

	var pkx fp.Element
	pkx.SetInterface(publicKey.X)

	var pky fp.Element
	pky.SetInterface(publicKey.X)

	Pubkey := secp256k1.G1Affine{
		pkx,
		pky,
	}
	t.Logf("create pk ok ")
	fi, _ := bls.NewFr().Rand(random)
	t.Logf("create fi ok ")
	//fi as x to get y,to build keypoint
	head := []byte{0x03}
	res := append(head, fi.ToBytes()...)
	keyPoint, err := crypto.DecompressPubkey(res)

	var kpx fp.Element
	kpx.SetInterface(keyPoint.X)

	var kpy fp.Element
	kpy.SetInterface(keyPoint.X)

	KeyPoint := secp256k1.G1Affine{
		kpx,
		kpy,
	}
	t.Logf("create keypoint ok ")
	//F(i)=f(i)G
	_, _, bls_g1, _ := bls12381.Generators()
	var Fi bls12381.G1Affine
	Fi.ScalarMultiplication(&bls_g1, fi.ToBig())
	t.Logf("create Fi ok ")
	//C=M+rpk, R1=rG1
	r := big.NewInt(int64(random.Uint64()))
	_, g1 := secp256k1.Generators()
	var R secp256k1.G1Affine
	R.ScalarMultiplication(&g1, r)
	t.Logf("create R ok ")
	var CPoint secp256k1.G1Affine
	var temp secp256k1.G1Affine
	temp.ScalarMultiplication(&Pubkey, r)
	CPoint.Add(&KeyPoint, &temp)
	t.Logf("create Cpoint ok ")
	exx := ECDSAEncryptionCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{}

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
	assignment := &ECDSAEncryptionCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{

		PublicKey: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](Pubkey.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](Pubkey.Y),
		},
		CipherText: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](CPoint.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](CPoint.Y),
		},
		R: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](R.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](R.Y),
		},
		KeyPoint: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](KeyPoint.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](KeyPoint.Y),
		},
		SmallR: r,

		SmallFi: fi.ToBig(),

		Fi: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](Fi.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](Fi.Y),
		},
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

func encrypt[B1, S1 emulated.FieldParams](api frontend.API, params sw_emulated.CurveParams, KeyPoint sw_emulated.AffinePoint[B1], Ciptext sw_emulated.AffinePoint[B1], PublicKey sw_emulated.AffinePoint[B1], R sw_emulated.AffinePoint[B1], SmallR *big.Int, SmallFi *big.Int) {
	curve, err := sw_emulated.New[B1, S1](api, params)
	if err != nil {
		panic("initalize new Secp256k1Fp curve fault")
	}
	//check point
	curve.AssertIsOnCurve(&KeyPoint)
	curve.AssertIsOnCurve(&Ciptext)
	curve.AssertIsOnCurve(&PublicKey)
	curve.AssertIsOnCurve(&R)

	G := curve.Generator()

	f, err := emulated.NewField[S1](api)
	r := f.NewElement(SmallR)

	rg := curve.ScalarMul(G, r)                // r*G
	rPk := curve.ScalarMul(&PublicKey, r)      // r*PublicKey
	result := curve.AddUnified(rPk, &KeyPoint) //KeyPoint+r*PublicKey
	curve.AssertIsEqual(result, &Ciptext)
	curve.AssertIsEqual(rg, &R)

	api.AssertIsEqual(KeyPoint.X, emulated.ValueOf[S1](SmallFi))
	//curve.AssertIsEqual(Fi.x, emulated.ValueOf[S1](smallFi))
}

func checkPairng[B2, S2 emulated.FieldParams](api frontend.API, params sw_emulated.CurveParams, fi emulated.Element[S2], Fi sw_emulated.AffinePoint[B2]) {
	curve, err := sw_emulated.New[B2, S2](api, params)
	if err != nil {
		panic("initalize new curve")
	}
	curve.AssertIsOnCurve(&Fi)
	G := curve.Generator()
	result := curve.ScalarMul(G, &fi) // fi*G
	curve.AssertIsEqual(result, &Fi)
}

type ECDSAEncryptionCircuit[Base1, Scalar1, Base2, Scalar2 emulated.FieldParams] struct {
	PublicKey  sw_emulated.AffinePoint[Base1] `gnark:",public"`
	CipherText sw_emulated.AffinePoint[Base1] `gnark:",public"`
	R          sw_emulated.AffinePoint[Base1] `gnark:",public"`
	KeyPoint   sw_emulated.AffinePoint[Base1]

	SmallR *big.Int

	SmallFi *big.Int

	Fi sw_emulated.AffinePoint[Base2] `gnark:",public"`
}

func (c *ECDSAEncryptionCircuit[Base1, Scalar1, Base2, Scalar2]) Define(api frontend.API) error {
	api.Println("PublicKey.X", c.PublicKey.X)
	api.Println("PublicKey.Y", c.PublicKey.Y)
	api.Println("CipherText.X", c.CipherText.X)
	api.Println("CipherText.Y", c.CipherText.Y)
	api.Println("R.X", c.R.X)
	api.Println("R.Y", c.R.Y)
	api.Println("KeyPoint.X", c.KeyPoint.X)
	api.Println("KeyPoint.Y", c.KeyPoint.Y)
	api.Println("Fi.X", c.Fi.X)
	api.Println("Fi.Y", c.Fi.Y)
	api.Println("SmallFi", c.SmallFi)

	params1 := sw_emulated.GetCurveParams[Base1]()
	encrypt[Base1, Scalar1](api, params1, c.KeyPoint, c.CipherText, c.PublicKey, c.R, c.SmallR, c.SmallFi)

	//params2 := sw_emulated.GetCurveParams[emulated.BLS12381Fp]()
	/*	c.KeyPoint.X.
		fr.Element.
		c.KeyPoint.X.
		checkPairng[Base2, Scalar1](api, params2, c.KeyPoint.X, c.Fi)*/
	return nil
}
