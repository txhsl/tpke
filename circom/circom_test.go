package circom

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
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
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"golang.org/x/crypto/sha3"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"
)

func doMPCSetUp(ccs constraint.ConstraintSystem) (pk groth16.ProvingKey, vk groth16.VerifyingKey, err error) {
	const (
		nContributionsPhase1 = 3
		nContributionsPhase2 = 3
		power                = 20 //19 //2^9 元素个数
	)

	initPhase1 := mpcsetup.InitPhase1(power)

	FilePhase1Init, err := os.Create("Phase1_1")
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	_, err = initPhase1.WriteTo(FilePhase1Init)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	err = FilePhase1Init.Close()
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	// Make and verify contributions for phase1
	for i := 1; i < nContributionsPhase1; i++ {
		// we clone test purposes; but in practice, participant will receive a []byte, deserialize it,
		// add his contribution and send back to coordinator.

		//prev := Phase1clone(srs1)
		FilePhase1Prev, err := os.Open("Phase1_" + strconv.Itoa(i))
		var prev mpcsetup.Phase1
		_, err = prev.ReadFrom(FilePhase1Prev)
		if err != nil {
			return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
		}
		curr := Phase1clone(prev)
		curr.Contribute()
		err = mpcsetup.VerifyPhase1(&prev, &curr)
		if err != nil {
			return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
		}
		FilePhase1Next, err := os.Create("Phase1_" + strconv.Itoa(i+1))
		if err != nil {
			return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
		}
		_, err = curr.WriteTo(FilePhase1Next)
		if err != nil {
			return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
		}
	}

	FilePhase1Final, err := os.Open("Phase1_" + strconv.Itoa(nContributionsPhase1))
	var srs1 mpcsetup.Phase1
	_, err = srs1.ReadFrom(FilePhase1Final)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}

	// Prepare for phase-1.5
	var evals mpcsetup.Phase2Evaluations
	r1cs := ccs.(*cs.R1CS)
	// Prepare for phase-2
	//srs2, evals := mpcsetup.InitPhase2(r1cs, &srs1)
	initPhase2, evals := mpcsetup.InitPhase2(r1cs, &srs1)

	FilePhase2Init, err := os.Create("Phase2_1")
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	_, err = initPhase2.WriteTo(FilePhase2Init)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	err = FilePhase2Init.Close()
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}

	// Make and verify contributions for phase1
	for i := 1; i < nContributionsPhase2; i++ {
		// we clone for test purposes; but in practice, participant will receive a []byte, deserialize it,
		// add his contribution and send back to coordinator.
		//prev := Phase2clone(srs2)

		FilePhase2Prev, err := os.Open("Phase2_" + strconv.Itoa(i))
		var prev mpcsetup.Phase2
		_, err = prev.ReadFrom(FilePhase2Prev)
		if err != nil {
			return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
		}
		curr := Phase2clone(prev)
		curr.Contribute()
		err = mpcsetup.VerifyPhase2(&prev, &curr)
		if err != nil {
			return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
		}
		FilePhase2Next, err := os.Create("Phase2_" + strconv.Itoa(i+1))
		if err != nil {
			return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
		}
		_, err = curr.WriteTo(FilePhase2Next)
		if err != nil {
			return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
		}
	}

	FilePhase2Final, err := os.Open("Phase2_" + strconv.Itoa(nContributionsPhase1))
	var srs2 mpcsetup.Phase2
	_, err = srs2.ReadFrom(FilePhase2Final)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
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

type MixEncryptionTest[T1, S1, T2, S2 emulated.FieldParams] struct {
	SmallR emulated.Element[S1]
	BigR   sw_emulated.AffinePoint[T1] `gnark:",public"`
	Pub    sw_emulated.AffinePoint[T1] `gnark:",public"`
	RPub   sw_emulated.AffinePoint[T1]

	PlainChunks  []uints.U8
	Iv           [12]frontend.Variable `gnark:",public"`
	ChunkIndex   frontend.Variable     `gnark:",public"`
	CipherChunks []uints.U8            `gnark:",public"`

	SmallFi emulated.Element[S2]
	Fi      sw_emulated.AffinePoint[T2] `gnark:",public"`
}

func (c *MixEncryptionTest[T1, S1, T2, S2]) Define(api frontend.API) error {
	MBytes := make([]frontend.Variable, len(c.PlainChunks))
	for i := 0; i < len(c.PlainChunks); i++ {
		MBytes[i] = c.PlainChunks[i]
	}

	CiphertextBytes := make([]frontend.Variable, len(c.CipherChunks))
	for i := 0; i < len(c.CipherChunks); i++ {
		CiphertextBytes[i] = c.CipherChunks[i]
	}

	cr, err := sw_emulated.New[T1, S1](api, sw_emulated.GetCurveParams[T1]())
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
	//generate key=hash(RPub)
	uapi, err := uints.New[uints.U64](api)
	nbBits := 8 * ((fp.Modulus().BitLen() + 7) / 8)
	rawRpub := make([]uints.U8, 2*nbBits)
	for i := range cr.MarshalG1(c.RPub) {
		rawRpub[i] = uapi.ByteValueOf(cr.MarshalG1(c.RPub)[i])
	}
	hasher, err := zksha3.New256(api)
	if err != nil {
		return fmt.Errorf("hash function unknown ")
	}
	hasher.Write(rawRpub)
	expected := hasher.Sum()
	key := [32]frontend.Variable{}
	for j := range key {
		key[j] = expected[j]
	}
	api.Println("key generate ok")
	//check Fi=fiG
	cr2, err := sw_emulated.New[T2, S2](api, sw_emulated.GetCurveParams[T2]())
	if err != nil {
		return err
	}
	cr2.AssertIsOnCurve(&c.Fi)
	Fi := cr2.ScalarMulBase(&c.SmallFi)
	cr2.AssertIsEqual(Fi, &c.Fi)
	api.Println("Fi=fiG check ok")
	//check aes process
	aes := NewAES256(api)
	gcm := NewGCM256(api, &aes)
	gcm.Assert256(key, c.Iv, c.ChunkIndex, MBytes, CiphertextBytes)
	api.Println("aes check ok")

	//check smallFi==m
	f, err := emulated.NewField[S2](api)
	if err != nil {
		return err
	}
	smallFiBits := f.ToBits(&c.SmallFi)
	var plainBits []frontend.Variable
	for i := range c.PlainChunks {
		chunkBits := bits.ToBinary(api, c.PlainChunks[len(c.PlainChunks)-i-1].Val, bits.WithNbDigits(8))
		plainBits = append(plainBits, chunkBits...)
	}
	if len(plainBits) != len(smallFiBits) {
		return fmt.Errorf("mismatch length: %d != %d", len(plainBits), len(smallFiBits))
	}
	for i := range plainBits {
		api.AssertIsEqual(plainBits[i], smallFiBits[i])
	}
	return nil
}

func TestMixEncryption(t *testing.T) {
	//check BigR=rG
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
	RawRpub := RPub.RawBytes()
	//generator key=hash(RPub)
	key := RawRpub[:]
	hasher := sha3.New256()
	hasher.Write(key)
	expected := hasher.Sum(nil)
	keyBytes := [32]frontend.Variable{}
	for i := 0; i < len(expected); i++ {
		keyBytes[i] = expected[i]
	}
	//message
	var fi fr_bls12381.Element
	_, _ = fi.SetRandom()
	SmallFi := new(big.Int)
	fi.BigInt(SmallFi)

	//m := SmallFi.Bytes()
	var m [32]byte
	SmallFi.FillBytes(m[:])
	//m := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	//m := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x01}
	//aes
	ciphertext, nonce := AesGcmEncrypt(expected, m[:])
	/*	var ChunkIndex int
		if len(ciphertext)%16 == 0 {
			ChunkIndex = len(ciphertext) / 16
		} else {
			ChunkIndex = len(ciphertext)/16 + 1
		}*/
	nonceBytes := [12]frontend.Variable{}
	for i := 0; i < len(nonce); i++ {
		nonceBytes[i] = nonce[i]
	}
	//Fi=fiG
	_, _, g12381, _ := bls12381.Generators()
	//var fi big.Int
	var Fi bls12381.G1Affine
	Fi.ScalarMultiplication(&g12381, SmallFi)
	t.Logf("create Fi ok ")
	//proof
	circuit := MixEncryptionTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		PlainChunks:  make([]uints.U8, len(m)),
		CipherChunks: make([]uints.U8, len(ciphertext)),
	}
	witness := MixEncryptionTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
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
		PlainChunks:  uints.NewU8Array(m[:]),
		Iv:           nonceBytes,
		ChunkIndex:   2,
		CipherChunks: uints.NewU8Array(ciphertext),

		SmallFi: emulated.ValueOf[emulated.BLS12381Fr](SmallFi),
		Fi: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](Fi.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](Fi.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert := test.NewAssert(t)
	assert.NoError(err)
}

func TestMixEncryptionByMPC(t *testing.T) {
	//generator R=rg
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
	RawRPub := RPub.RawBytes()
	//generator key=hash(rPub)
	key := RawRPub[:]
	hasher := sha3.New256()
	hasher.Write(key)
	expected := hasher.Sum(nil)
	keyBytes := [32]frontend.Variable{}
	for i := 0; i < len(expected); i++ {
		keyBytes[i] = expected[i]
	}
	//message
	m := []byte{0x01, 0x02}
	ciphertext, nonce := AesGcmEncrypt(expected, m)
	ChunkIndex := len(ciphertext)/16 + 1
	nonceBytes := [12]frontend.Variable{}
	for i := 0; i < len(nonce); i++ {
		nonceBytes[i] = nonce[i]
	}
	//proof
	circuit := MixEncryptionTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{}
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
	assignment := &MixEncryptionTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
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
		PlainChunks:  uints.NewU8Array(m),
		Iv:           nonceBytes,
		ChunkIndex:   ChunkIndex,
		CipherChunks: uints.NewU8Array(ciphertext),
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
