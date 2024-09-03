package circom

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	fr_secp "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
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
	"math/big"
	"math/rand"
	"testing"
	"time"
)

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

type MixEncryptionTest[T, S emulated.FieldParams] struct {
	SmallR   emulated.Element[S]
	BigR     sw_emulated.AffinePoint[T]
	Pub      sw_emulated.AffinePoint[T]
	RPub     sw_emulated.AffinePoint[T]
	In       []uints.U8
	Expected []uints.U8

	Key          [32]frontend.Variable
	PlainChunks  []frontend.Variable
	Iv           [12]frontend.Variable `gnark:",public"`
	ChunkIndex   frontend.Variable     `gnark:",public"`
	CipherChunks []frontend.Variable   `gnark:",public"`
}

func (c *MixEncryptionTest[T, S]) Define(api frontend.API) error {
	cr, err := sw_emulated.New[T, S](api, sw_emulated.GetCurveParams[T]())
	if err != nil {
		return err
	}
	//check BigR=rG
	cr.AssertIsOnCurve(&c.BigR)
	api.Println("R check on curve ok")
	BigR := cr.ScalarMulBase(&c.SmallR)
	cr.AssertIsEqual(BigR, &c.BigR)
	api.Println("R =rG check ok")
	//check pub
	cr.AssertIsOnCurve(&c.Pub)
	api.Println("Pub check on curve ok")
	//check RPub
	cr.AssertIsOnCurve(&c.RPub)
	api.Println("RPub check on curve ok")
	RPub := cr.ScalarMul(&c.Pub, &c.SmallR)
	cr.AssertIsEqual(RPub, &c.RPub)
	api.Println("RPub =rPub check ok")

	//check hash(Rpub)==circuit.Key
	hasher, err := zksha3.New256(api)
	if err != nil {
		return fmt.Errorf("hash function unknown ")
	}
	hasher.Write(c.In)
	expected := hasher.Sum()
	uapi, err := uints.New[uints.U64](api)
	for i := range c.Expected {
		uapi.ByteAssertEq(c.Expected[i], expected[i])
	}
	api.Println("hash(Rpub) check ok")

	//check aes process
	aes := NewAES256(api)
	gcm := NewGCM256(api, &aes)
	gcm.Assert256(c.Key, c.Iv, c.ChunkIndex, c.PlainChunks, c.CipherChunks)
	api.Println("aes check ok")

	return nil
}

func TestMixEncryption(t *testing.T) {
	_, g := secp256k1.Generators()
	var r fr_secp.Element
	_, _ = r.SetRandom()
	SmallR := new(big.Int)
	r.BigInt(SmallR)
	var BigR secp256k1.G1Affine
	BigR.ScalarMultiplication(&g, SmallR)

	//generator PublicKey
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
	//generator RPub=r*PublicKey
	var RPub secp256k1.G1Affine
	RPub.ScalarMultiplication(&Pub, SmallR)
	//t.Logf("create RPub ok %s", RPub.String())

	Raw_RPUb := RPub.RawBytes()
	key := Raw_RPUb[:]
	hasher := sha3.New256()
	hasher.Write(key)
	expected := hasher.Sum(nil)
	key_bytes := [32]frontend.Variable{}
	for i := 0; i < len(expected); i++ {
		key_bytes[i] = expected[i]
	}

	m := []byte{0x01, 0x02}
	M_bytes := make([]frontend.Variable, len(m))
	for i := 0; i < len(m); i++ {
		M_bytes[i] = m[i]
	}
	ciphertext, nonce := AesGcmEncrypt(expected, m)
	Ciphertext_bytes := make([]frontend.Variable, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		Ciphertext_bytes[i] = ciphertext[i]
	}
	ChunkIndex := len(Ciphertext_bytes)/16 + 1

	nonce_bytes := [12]frontend.Variable{}
	for i := 0; i < len(nonce); i++ {
		nonce_bytes[i] = nonce[i]
	}

	circuit := MixEncryptionTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := MixEncryptionTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		SmallR: emulated.ValueOf[emulated.Secp256k1Fr](SmallR),
		BigR: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](BigR.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](BigR.Y),
		},
		Pub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](Pub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](Pub.Y),
		},
		RPub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](RPub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](RPub.Y),
		},
		In:       uints.NewU8Array(key),
		Expected: uints.NewU8Array(expected),

		Key:          key_bytes,
		PlainChunks:  M_bytes,
		Iv:           nonce_bytes,
		ChunkIndex:   ChunkIndex,
		CipherChunks: Ciphertext_bytes,
	}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert := test.NewAssert(t)
	assert.NoError(err)
}

func TestMixEncryptionByMPC(t *testing.T) {
	_, g := secp256k1.Generators()
	var r fr_secp.Element
	_, _ = r.SetRandom()
	SmallR := new(big.Int)
	r.BigInt(SmallR)
	var BigR secp256k1.G1Affine
	BigR.ScalarMultiplication(&g, SmallR)

	//generator PublicKey
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
	//generator RPub=r*PublicKey
	var RPub secp256k1.G1Affine
	RPub.ScalarMultiplication(&Pub, SmallR)
	//t.Logf("create RPub ok %s", RPub.String())

	Raw_RPUb := RPub.RawBytes()
	key := Raw_RPUb[:]
	hasher := sha3.New256()
	hasher.Write(key)
	expected := hasher.Sum(nil)
	key_bytes := [32]frontend.Variable{}
	for i := 0; i < len(expected); i++ {
		key_bytes[i] = expected[i]
	}

	m := []byte{0x01, 0x02}
	M_bytes := make([]frontend.Variable, len(m))
	for i := 0; i < len(m); i++ {
		M_bytes[i] = m[i]
	}
	ciphertext, nonce := AesGcmEncrypt(expected, m)
	Ciphertext_bytes := make([]frontend.Variable, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		Ciphertext_bytes[i] = ciphertext[i]
	}
	ChunkIndex := len(Ciphertext_bytes)/16 + 1

	nonce_bytes := [12]frontend.Variable{}
	for i := 0; i < len(nonce); i++ {
		nonce_bytes[i] = nonce[i]
	}

	circuit := MixEncryptionTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
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

	assignment := &MixEncryptionTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		SmallR: emulated.ValueOf[emulated.Secp256k1Fr](SmallR),
		BigR: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](BigR.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](BigR.Y),
		},
		Pub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](Pub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](Pub.Y),
		},
		RPub: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](RPub.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](RPub.Y),
		},
		In:       uints.NewU8Array(key),
		Expected: uints.NewU8Array(expected),

		Key:          key_bytes,
		PlainChunks:  M_bytes,
		Iv:           nonce_bytes,
		ChunkIndex:   ChunkIndex,
		CipherChunks: Ciphertext_bytes,
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
