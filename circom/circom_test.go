package circom

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	zksha3 "github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"golang.org/x/crypto/sha3"
	"io"
	"math/big"
	"math/rand"
	"testing"
	"time"
)

type TCircom[Base, Scalars emulated.FieldParams] struct {
	Key          [32]frontend.Variable
	PlainChunks  []frontend.Variable
	Iv           [12]frontend.Variable `gnark:",public"`
	ChunkIndex   frontend.Variable     `gnark:",public"`
	CipherChunks []frontend.Variable   `gnark:",public"`

	In       []uints.U8
	Expected []uints.U8

	SmallR emulated.Element[Scalars]
	BigR   sw_emulated.AffinePoint[Base]
	Pub    sw_emulated.AffinePoint[Base]
	RPub   sw_emulated.AffinePoint[Base]
}

// Define declares the circuit's constraints
func (circuit *TCircom[Base, Scalars]) Define(api frontend.API) error {

	aes := NewAES256(api)

	gcm := NewGCM256(api, &aes)

	gcm.Assert256(circuit.Key, circuit.Iv, circuit.ChunkIndex, circuit.PlainChunks, circuit.CipherChunks)

	hasher, err := zksha3.New256(api)

	if err != nil {
		return fmt.Errorf("hash function unknown ")
	}
	hasher.Write(circuit.In)
	res := hasher.Sum()
	uapi, err := uints.New[uints.U64](api)
	for i := range circuit.Expected {
		uapi.ByteAssertEq(circuit.Expected[i], res[i])
	}

	params := sw_emulated.GetCurveParams[Base]()
	cr, err := sw_emulated.New[Base, Scalars](api, params)
	if err != nil {
		panic(err)
	}

	cr.AssertIsOnCurve(&circuit.Pub)
	api.Println("Pub check on curve ok")
	//SmallR := emulated.ValueOf[Scalars](circuit.SmallR)
	BigR := cr.ScalarMulBase(&circuit.SmallR)

	Rpub := cr.ScalarMul(&circuit.Pub, &circuit.SmallR)

	cr.AssertIsEqual(Rpub, &circuit.RPub)
	api.Println("RPub check equal ok")

	cr.AssertIsEqual(BigR, &circuit.BigR)
	api.Println("BigR check equal ok")

	//to do
	// check rpub==>key

	return nil
}

var order = fr.Modulus()
var one = new(big.Int).SetInt64(1)

func randFieldElement1(rand io.Reader) (k *big.Int, err error) {
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

func TestCircom(t *testing.T) {

	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)

	r := big.Int{}
	SmallR := r.SetInt64(rand.Int63())

	//generator R
	//SmallR, err := randFieldElement1(rand)
	//_, g1 := secp256k1.Generators()
	var R secp256k1.G1Affine
	R.ScalarMultiplicationBase(SmallR)

	//generator PublicKey
	privKey, err := ecies.GenerateKey(rand, crypto.S256(), nil)
	if err != nil {
		return
	}
	pub := privKey.PublicKey

	var px fp.Element
	px.SetInterface(pub.X)

	var py fp.Element
	py.SetInterface(pub.Y)

	Pub := secp256k1.G1Affine{
		px,
		py,
	}

	var RPub secp256k1.G1Affine
	RPub.ScalarMultiplication(&Pub, SmallR)

	m := []byte{0x01, 0x02}
	M_bytes := make([]frontend.Variable, len(m))
	for i := 0; i < len(m); i++ {
		M_bytes[i] = m[i]
	}

	//key := pub.X.Bytes()
	//key := RPub.X.Bytes() //因该取x+y
	key := make([]byte, len(RPub.RawBytes()))
	for i := 0; i < len(key); i++ {
		key[i] = RPub.RawBytes()[i]
	}
	hasher := sha3.New256()
	hasher.Write(key)
	expected := hasher.Sum(nil)
	//key = key[:16]
	key_bytes := [32]frontend.Variable{}
	for i := 0; i < len(expected); i++ {
		key_bytes[i] = expected[i]
	}

	ciphertext, nonce := AesGcmEncrypt(key, m)
	Ciphertext_bytes := make([]frontend.Variable, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		Ciphertext_bytes[i] = ciphertext[i]
	}
	ChunkIndex := len(Ciphertext_bytes)/16 + 1

	nonce_bytes := [12]frontend.Variable{}
	for i := 0; i < len(nonce); i++ {
		nonce_bytes[i] = nonce[i]
	}

	circuit := TCircom[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := TCircom[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Key:          key_bytes,
		PlainChunks:  M_bytes,
		Iv:           nonce_bytes,
		ChunkIndex:   ChunkIndex,
		CipherChunks: Ciphertext_bytes,
		In:           uints.NewU8Array(key),
		Expected:     uints.NewU8Array(expected),
		SmallR:       emulated.ValueOf[emulated.Secp256k1Fr](SmallR),
		BigR: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](R.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](R.Y),
		},
		Pub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pub.Y),
		},
		RPub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](RPub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](RPub.Y),
		},
	}

	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestCircom2(t *testing.T) {
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)

	r := big.Int{}
	SmallR := r.SetInt64(rand.Int63())
	//_, g1 := secp256k1.Generators()
	var R secp256k1.G1Affine
	R.ScalarMultiplicationBase(SmallR)
	t.Logf("create R ok %s", R.String())

	//generator PublicKey
	privKey, err := ecies.GenerateKey(rand, crypto.S256(), nil)
	if err != nil {
		return
	}
	pub := privKey.PublicKey

	var px fp.Element
	px.SetInterface(pub.X)

	var py fp.Element
	py.SetInterface(pub.Y)

	Pub := secp256k1.G1Affine{
		px,
		py,
	}

	var RPub secp256k1.G1Affine
	RPub.ScalarMultiplication(&Pub, SmallR)
	t.Logf("create R ok %s", RPub.String())

	m := []byte{0x01, 0x02}
	M_bytes := make([]frontend.Variable, len(m))
	for i := 0; i < len(m); i++ {
		M_bytes[i] = m[i]
	}

	//key := pub.X.Bytes()
	key := pub.X.Bytes()
	hasher := sha3.New256()
	hasher.Write(key)
	expected := hasher.Sum(nil)
	//key = key[:16]
	key_bytes := [32]frontend.Variable{}
	for i := 0; i < len(expected); i++ {
		key_bytes[i] = expected[i]
	}

	ciphertext, nonce := AesGcmEncrypt(key, m)
	Ciphertext_bytes := make([]frontend.Variable, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		Ciphertext_bytes[i] = ciphertext[i]
	}
	ChunkIndex := len(Ciphertext_bytes)/16 + 1

	nonce_bytes := [12]frontend.Variable{}
	for i := 0; i < len(nonce); i++ {
		nonce_bytes[i] = nonce[i]
	}

	//编译电路
	var myCircuit TCircom[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
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
	assignment := &TCircom[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Key:          key_bytes,
		PlainChunks:  M_bytes,
		Iv:           nonce_bytes,
		ChunkIndex:   ChunkIndex,
		CipherChunks: Ciphertext_bytes,
		In:           uints.NewU8Array(key),
		Expected:     uints.NewU8Array(expected),
		SmallR:       emulated.ValueOf[emulated.Secp256k1Fr](SmallR),
		BigR: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](R.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](R.Y),
		},
		Pub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pub.Y),
		},
		RPub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](RPub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](RPub.Y),
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

func doMPCSetUp(ccs constraint.ConstraintSystem) (pk groth16.ProvingKey, vk groth16.VerifyingKey, err error) {
	const (
		nContributionsPhase1 = 3
		nContributionsPhase2 = 3
		power                = 19 //2^9 元素个数
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
