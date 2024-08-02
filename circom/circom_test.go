package circom

import (
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
)

// // test circom
// type MyCircuit[S emulated.FieldParams] struct {
// 	X emulated.Element[S] `gnark:",public"`
// }

// func (circuit *MyCircuit[S]) Define(api frontend.API) error {
// 	api.Println("result.y", circuit.X)
// 	return nil
// }

// func TestCircom(t *testing.T) {
// 	//编译电路
// 	var myCircuit MyCircuit[emulated.Secp256k1Fr]
// 	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
// 	if err != nil {
// 		t.Fatalf(err.Error())
// 	}
// 	//初始化
// 	pk, vk, _ := doMPCSetUp(css)
// 	// 1. One time setup
// 	err = groth16.Setup(css.(*cs.R1CS), &pk, &vk)
// 	if err != nil {
// 		t.Fatalf(err.Error())
// 	}
// 	var r fr.Element
// 	r.SetRandom()
// 	//提供输入输出
// 	assignment := &MyCircuit[emulated.Secp256k1Fr]{
// 		X: emulated.ValueOf[emulated.Secp256k1Fr](r),
// 	}
// 	//计算witness
// 	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
// 	if err != nil {
// 		t.Fatalf(err.Error())
// 	}
// 	publicWitness, err := witness.Public()
// 	if err != nil {
// 		t.Fatalf(err.Error())
// 	}
// 	// 计算证明
// 	proof, err := groth16.Prove(css.(*cs.R1CS), &pk, witness)
// 	if err != nil {
// 		t.Fatalf(err.Error())
// 	}
// 	//验证证明
// 	err = groth16.Verify(proof, &vk, publicWitness.Vector().(fr_bn254.Vector))
// 	if err != nil {
// 		return
// 	}
// 	t.Logf("circom test ok ")
// }

func doMPCSetUp(ccs constraint.ConstraintSystem) (pk groth16.ProvingKey, vk groth16.VerifyingKey, err error) {
	const (
		nContributionsPhase1 = 3
		nContributionsPhase2 = 3
		power                = 18 //2^9 元素个数
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

// func TestEcdsaEncryptionCircuit(t *testing.T) {
// 	// generate parameters
// 	privKey, _ := ecdsa.GenerateKey(rand.Reader)
// 	publicKey := privKey.PublicKey

// 	_, keyPoint := secp256k1.Generators()

// 	//C=M+rpk, R1=rG1
// 	var r fr.Element
// 	r.SetRandom()
// 	var r_int = big.Int{}

// 	r.BigInt(&r_int)

// 	/*	//max := new(big.Int).Lsh(big.NewInt(1), 128)
// 		r := new(big.Int).SetUint64(uint64(5))
// 		/*	r, err := rand.Int(rand.Reader, max)
// 			if err != nil {
// 				return
// 			}
// 	*/
// 	_, g := secp256k1.Generators()
// 	var R secp256k1.G1Affine
// 	R.ScalarMultiplication(&g, &r_int)

// 	var CPoint secp256k1.G1Affine
// 	var temp secp256k1.G1Affine
// 	temp.ScalarMultiplication(&publicKey.A, &r_int)
// 	CPoint.Add(&keyPoint, &temp)
// 	//C=M+rpk, R1=rG1

// 	exx := ECDSAEncryptionCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}

// 	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &exx)
// 	if err != nil {
// 		t.Fatalf(err.Error())
// 	}
// 	//初始化
// 	pk, vk, _ := doMPCSetUp(css)
// 	// 1. One time setup
// 	err = groth16.Setup(css.(*cs.R1CS), &pk, &vk)
// 	if err != nil {
// 		t.Fatalf(err.Error())
// 	}

// 	//提供输入输出
// 	assignment := &ECDSAEncryptionCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{

// 		PublicKey: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
// 			X: emulated.ValueOf[emulated.Secp256k1Fp](publicKey.A.X),
// 			Y: emulated.ValueOf[emulated.Secp256k1Fp](publicKey.A.Y),
// 		},
// 		CipherText: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
// 			X: emulated.ValueOf[emulated.Secp256k1Fp](CPoint.X),
// 			Y: emulated.ValueOf[emulated.Secp256k1Fp](CPoint.Y),
// 		},
// 		R: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
// 			X: emulated.ValueOf[emulated.Secp256k1Fp](R.X),
// 			Y: emulated.ValueOf[emulated.Secp256k1Fp](R.Y),
// 		},
// 		KeyPoint: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
// 			X: emulated.ValueOf[emulated.Secp256k1Fp](keyPoint.X),
// 			Y: emulated.ValueOf[emulated.Secp256k1Fp](keyPoint.Y),
// 		},
// 		r: emulated.ValueOf[emulated.Secp256k1Fr](r),
// 	}
// 	//计算witness
// 	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
// 	if err != nil {
// 		t.Fatalf(err.Error())
// 	}
// 	publicWitness, err := witness.Public()
// 	if err != nil {
// 		t.Fatalf(err.Error())
// 	}
// 	schema, _ := frontend.NewSchema(assignment)
// 	ret, _ := publicWitness.ToJSON(schema)
// 	var b bytes.Buffer
// 	json.Indent(&b, ret, "", "\t")
// 	fmt.Println(b.String())
// 	// 计算证明
// 	proof, err := groth16.Prove(css.(*cs.R1CS), &pk, witness)
// 	if err != nil {
// 		t.Fatalf(err.Error())
// 	}
// 	//验证证明
// 	err = groth16.Verify(proof, &vk, publicWitness.Vector().(fr_bn254.Vector))
// 	if err != nil {
// 		return
// 	}
// 	t.Logf("circom test ok ")

// }

// func encrypt[B, S emulated.FieldParams](api frontend.API, params sw_emulated.CurveParams, r emulated.Element[S], keyPoint sw_emulated.AffinePoint[B], ciptext sw_emulated.AffinePoint[B], PublicKey sw_emulated.AffinePoint[B], R sw_emulated.AffinePoint[B]) {
// 	curve, err := sw_emulated.New[B, S](api, params)
// 	if err != nil {
// 		panic("initalize new curve")
// 	}

// 	G := curve.Generator()
// 	rg := curve.ScalarMul(G, &r)               // r*G
// 	rPk := curve.ScalarMul(&PublicKey, &r)     // r*PublicKey
// 	result := curve.AddUnified(rPk, &keyPoint) //keyPoint+r*PublicKey
// 	api.Println("rPk.x", rPk.X)
// 	api.Println("rPk.y", rPk.Y)
// 	api.Println("result.x", result.X)
// 	api.Println("result.y", result.Y)
// 	curve.AssertIsEqual(result, &ciptext)
// 	curve.AssertIsEqual(rg, &R)
// }

// type ECDSAEncryptionCircuit[Base, Scalar emulated.FieldParams] struct {
// 	PublicKey  sw_emulated.AffinePoint[Base] `gnark:",public"`
// 	CipherText sw_emulated.AffinePoint[Base] `gnark:",public"`
// 	R          sw_emulated.AffinePoint[Base] `gnark:",public"`
// 	KeyPoint   sw_emulated.AffinePoint[Base] `gnark:",public"`

// 	r emulated.Element[Scalar]
// }

// func (c *ECDSAEncryptionCircuit[B, S]) Define(api frontend.API) error {
// 	api.Println("PublicKey.X", c.PublicKey.X)
// 	api.Println("PublicKey.Y", c.PublicKey.Y)
// 	api.Println("CipherText.X", c.CipherText.X)
// 	api.Println("CipherText.Y", c.CipherText.Y)
// 	api.Println("R.X", c.R.X)
// 	api.Println("R.Y", c.R.Y)
// 	api.Println("KeyPoint.X", c.KeyPoint.X)
// 	api.Println("KeyPoint.Y", c.KeyPoint.Y)

// 	params := sw_emulated.GetCurveParams[emulated.Secp256k1Fp]()
// 	encrypt(api, params, c.r, c.KeyPoint, c.CipherText, c.PublicKey, c.R)
// 	return nil
// }
