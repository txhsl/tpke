package circom

import (
	"bytes"
	"encoding/json"
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
		power                = 21 //element count range 2^0-2^27
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

func getFromExistedMPCSetUp(ccs constraint.ConstraintSystem) (pk groth16.ProvingKey, vk groth16.VerifyingKey, err error) {
	FilePhase1Final, err := os.Open("Phase1_" + strconv.Itoa(3))
	var srs1 mpcsetup.Phase1
	_, err = srs1.ReadFrom(FilePhase1Final)
	if err != nil {
		return groth16.ProvingKey{}, groth16.VerifyingKey{}, err
	}
	// Prepare for phase-1.5
	var evals mpcsetup.Phase2Evaluations
	r1cs := ccs.(*cs.R1CS)
	// Prepare for phase-2
	_, evals = mpcsetup.InitPhase2(r1cs, &srs1)
	FilePhase2Final, err := os.Open("Phase2_" + strconv.Itoa(3))
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
	BigR   sw_emulated.AffinePoint[T1] //`gnark:",public"`
	Pub    sw_emulated.AffinePoint[T1] //`gnark:",public"`
	RPub   sw_emulated.AffinePoint[T1]

	PlainChunks  []frontend.Variable
	Iv           [12]frontend.Variable //`gnark:",public"`
	ChunkIndex   frontend.Variable     //`gnark:",public"`
	CipherChunks []frontend.Variable   //`gnark:",public"`

	SmallFi emulated.Element[S2]
	Fi      sw_emulated.AffinePoint[T2] //`gnark:",public"`
	//maybe can make a hash =(input1,input2.....) to reduce public input counts
	AllHash []frontend.Variable `gnark:",public"`
}

func (c *MixEncryptionTest[T1, S1, T2, S2]) Define(api frontend.API) error {
	PlainChunksBytes := make([]uints.U8, len(c.PlainChunks))
	for i := 0; i < len(c.PlainChunks); i++ {
		PlainChunksBytes[i] = uints.U8{Val: c.PlainChunks[i]}
	}
	CiphertextBytes := make([]uints.U8, len(c.CipherChunks))
	for i := 0; i < len(c.CipherChunks); i++ {
		CiphertextBytes[i] = uints.U8{Val: c.CipherChunks[i]}
	}
	IV := [12]uints.U8{}
	for i := 0; i < len(c.Iv); i++ {
		IV[i] = uints.U8{Val: c.Iv[i]}
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
	nbBits := 8 * ((fp.Modulus().BitLen() + 7) / 8)
	rawRpub := make([]uints.U8, 2*nbBits)
	raw := cr.MarshalG1(c.RPub)
	for i := range raw {
		rawRpub[i] = uints.U8{Val: raw[i]}
	}
	hasher, err := zksha3.New256(api)
	if err != nil {
		return fmt.Errorf("hash function unknown ")
	}
	hasher.Write(rawRpub)
	expected := hasher.Sum()
	key := [32]uints.U8{}
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
	gcm.Assert(key, IV, c.ChunkIndex, PlainChunksBytes, CiphertextBytes)
	api.Println("aes check ok")
	//check smallFi==m
	f, err := emulated.NewField[S2](api)
	if err != nil {
		return err
	}
	smallFiBits := f.ToBits(&c.SmallFi)
	var plainBits []frontend.Variable
	for i := range PlainChunksBytes {
		chunkBits := bits.ToBinary(api, PlainChunksBytes[len(PlainChunksBytes)-i-1].Val, bits.WithNbDigits(8))
		plainBits = append(plainBits, chunkBits...)
	}
	if len(plainBits) != len(smallFiBits) {
		return fmt.Errorf("mismatch length: %d != %d", len(plainBits), len(smallFiBits))
	}
	for i := range plainBits {
		api.AssertIsEqual(plainBits[i], smallFiBits[i])
	}
	//check AllHash =(pub1,pub2.....)
	rawBigR := cr.MarshalG1(c.BigR)
	rawPub := cr.MarshalG1(c.Pub)
	rawFi := cr2.MarshalG1(c.Fi)
	nbBits1 := 8 * ((fp.Modulus().BitLen() + 7) / 8)
	nbBits2 := 8 * ((fr_bls12381.Modulus().BitLen() + 7) / 8)
	rawBigR_u8 := VariabletoU8(rawBigR, nbBits1)
	rawPub_U8 := VariabletoU8(rawPub, nbBits1)
	rawFi_u8 := VariabletoU8(rawFi, nbBits2)
	length := len(rawBigR_u8) + len(rawPub_U8) + len(rawFi_u8) + len(c.Iv) + 1 + len(c.CipherChunks)
	rawPubInputs := make([]uints.U8, length)

	for i := range rawBigR_u8 {
		rawPubInputs[i] = rawBigR_u8[i]
	}
	for i := range rawPub_U8 {
		rawPubInputs[len(rawBigR_u8)+i] = rawPub_U8[i]
	}
	for i := range rawFi_u8 {
		rawPubInputs[len(rawBigR_u8)+len(rawPub_U8)+i] = rawFi_u8[i]
	}

	for i := range c.Iv {
		rawPubInputs[len(rawBigR_u8)+len(rawPub_U8)+len(rawFi_u8)+i] = uints.U8{Val: c.Iv[i]}
	}
	rawPubInputs[len(rawBigR_u8)+len(rawPub_U8)+len(rawFi_u8)+len(c.Iv)] = uints.U8{Val: c.ChunkIndex}
	for i := range c.CipherChunks {
		rawPubInputs[len(rawBigR_u8)+len(rawPub_U8)+len(rawFi_u8)+len(c.Iv)+1+i] = uints.U8{Val: c.CipherChunks[i]}
	}

	//rawPubInputs := append(append(append(append(append(rawBigR, rawPub), rawFi), c.Iv), c.ChunkIndex), c.CipherChunks)

	mc, err := zksha3.New256(api)
	mc.Write(rawPubInputs)
	result := mc.Sum()

	for i := 0; i < len(result); i++ {
		api.AssertIsEqual(result[i].Val, c.AllHash[i])
	}

	return nil
}

func VariabletoU8(in []frontend.Variable, nbBits int) []uints.U8 {
	out := make([]uints.U8, 2*nbBits)
	for i := 0; i < len(out); i++ {
		out[i] = uints.U8{Val: in[i]}
	}
	return out
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
	nbBytes := 2 * fr_secp.Bytes
	key := make([]byte, nbBytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			key[i*8+j] = (RawRpub[i] >> (7 - j)) & 1
		}
	}
	hasher := sha3.New256()
	hasher.Write(key)
	expected := hasher.Sum(nil)
	keyBytes := [32]frontend.Variable{}
	for i := 0; i < len(expected); i++ {
		keyBytes[i] = expected[i]
	}
	//aes
	var fi fr_bls12381.Element
	_, _ = fi.SetRandom()
	SmallFi := new(big.Int)
	fi.BigInt(SmallFi)
	//message
	var m [32]byte
	SmallFi.FillBytes(m[:])
	PlainChunksBytes := make([]frontend.Variable, len(m))
	for i := 0; i < len(m); i++ {
		PlainChunksBytes[i] = m[i]
	}
	ciphertext, nonce := AesGcmEncrypt(expected, m[:])
	Ciphertext_bytes := make([]frontend.Variable, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		Ciphertext_bytes[i] = ciphertext[i]
	}
	nonceBytes := [12]frontend.Variable{}
	for i := 0; i < len(nonce); i++ {
		nonceBytes[i] = nonce[i]
	}
	//Fi=fiG
	_, _, g12381, _ := bls12381.Generators()
	var Fi bls12381.G1Affine
	Fi.ScalarMultiplication(&g12381, SmallFi)

	//get allHash
	rawBigR := BigR.RawBytes()
	RawBigR := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			RawBigR[i*8+j] = (rawBigR[i] >> (7 - j)) & 1
		}
	}
	rawPub := Pub.RawBytes()
	RawPub := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			RawPub[i*8+j] = (rawPub[i] >> (7 - j)) & 1
		}
	}
	rawFi := Fi.RawBytes()
	RawFi := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			RawFi[i*8+j] = (rawFi[i] >> (7 - j)) & 1
		}
	}
	temp := append(append(append(append(append(RawBigR, RawPub...), RawFi...), nonce...), 2), ciphertext...)

	hasher2 := sha3.New256()
	hasher2.Write(temp)
	raw_allHash := hasher2.Sum(nil)
	allHash := make([]frontend.Variable, len(raw_allHash))
	for i := 0; i < len(allHash); i++ {
		allHash[i] = raw_allHash[i]
	}
	/*	goMimc := hash.MIMC_BN254.New()
		for i := 0; i < 10; i++ {
			goMimc.Write(temp)
		}
		allHash := goMimc.Sum(nil)*/
	//proof
	circuit := MixEncryptionTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		PlainChunks:  make([]frontend.Variable, len(PlainChunksBytes)),
		CipherChunks: make([]frontend.Variable, len(Ciphertext_bytes)),
		AllHash:      make([]frontend.Variable, len(allHash)),
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
		PlainChunks:  PlainChunksBytes,
		Iv:           nonceBytes,
		ChunkIndex:   2,
		CipherChunks: Ciphertext_bytes,

		SmallFi: emulated.ValueOf[emulated.BLS12381Fr](SmallFi),
		Fi: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](Fi.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](Fi.Y),
		},
		AllHash: allHash,
	}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert := test.NewAssert(t)
	assert.NoError(err)
}

func TestMixEncryptionByMPC(t *testing.T) {
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
	nbBytes := 2 * fr_secp.Bytes
	key := make([]byte, nbBytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			key[i*8+j] = (RawRpub[i] >> (7 - j)) & 1
		}
	}
	hasher := sha3.New256()
	hasher.Write(key)
	expected := hasher.Sum(nil)
	keyBytes := [32]frontend.Variable{}
	for i := 0; i < len(expected); i++ {
		keyBytes[i] = expected[i]
	}
	var fi fr_bls12381.Element
	_, _ = fi.SetRandom()
	//aes
	SmallFi := new(big.Int)
	fi.BigInt(SmallFi)
	//message
	var m [32]byte
	SmallFi.FillBytes(m[:])
	PlainChunksBytes := make([]frontend.Variable, len(m))
	for i := 0; i < len(m); i++ {
		PlainChunksBytes[i] = m[i]
	}
	ciphertext, nonce := AesGcmEncrypt(expected, m[:])
	Ciphertext_bytes := make([]frontend.Variable, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		Ciphertext_bytes[i] = ciphertext[i]
	}
	nonceBytes := [12]frontend.Variable{}
	for i := 0; i < len(nonce); i++ {
		nonceBytes[i] = nonce[i]
	}
	//Fi=fiG
	_, _, g12381, _ := bls12381.Generators()
	var Fi bls12381.G1Affine
	Fi.ScalarMultiplication(&g12381, SmallFi)

	//get allHash
	rawBigR := BigR.RawBytes()
	RawBigR := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			RawBigR[i*8+j] = (rawBigR[i] >> (7 - j)) & 1
		}
	}
	rawPub := Pub.RawBytes()
	RawPub := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			RawPub[i*8+j] = (rawPub[i] >> (7 - j)) & 1
		}
	}
	rawFi := Fi.RawBytes()
	RawFi := make([]byte, 2*fr_secp.Bytes*8)
	for i := 0; i < nbBytes; i++ {
		for j := 0; j < 8; j++ {
			RawFi[i*8+j] = (rawFi[i] >> (7 - j)) & 1
		}
	}
	temp := append(append(append(append(append(RawBigR, RawPub...), RawFi...), nonce...), 2), ciphertext...)

	hasher2 := sha3.New256()
	hasher2.Write(temp)
	raw_allHash := hasher2.Sum(nil)
	allHash := make([]frontend.Variable, len(raw_allHash))
	for i := 0; i < len(allHash); i++ {
		allHash[i] = raw_allHash[i]
	}
	//proof
	circuit := MixEncryptionTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr, emulated.BLS12381Fp, emulated.BLS12381Fr]{
		PlainChunks:  make([]frontend.Variable, len(PlainChunksBytes)),
		CipherChunks: make([]frontend.Variable, len(Ciphertext_bytes)),
		AllHash:      make([]frontend.Variable, len(allHash)),
	}
	css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf(err.Error())
	}
	//init,2ways: way1 make a new mpc, way2 from a existed mpc
	//pk, vk, _ := doMPCSetUp(css)
	pk, vk, _ := getFromExistedMPCSetUp(css)
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
		PlainChunks:  PlainChunksBytes,
		Iv:           nonceBytes,
		ChunkIndex:   2,
		CipherChunks: Ciphertext_bytes,

		SmallFi: emulated.ValueOf[emulated.BLS12381Fr](SmallFi),
		Fi: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](Fi.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](Fi.Y),
		},
		AllHash: allHash,
	}
	//compute witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf(err.Error())
	}
	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf(err.Error())
	}
	// compute proof
	proof, err := groth16.Prove(css.(*cs.R1CS), &pk, witness)
	if err != nil {
		t.Fatalf(err.Error())
	}
	//verify proof
	err = groth16.Verify(proof, &vk, publicWitness.Vector().(fr_bn254.Vector))
	if err != nil {
		t.Fatalf(err.Error())
	}
	//print proof public msg
	// Save publicWitness
	schema, _ := frontend.NewSchema(assignment)
	ret, _ := publicWitness.ToJSON(schema)
	var b bytes.Buffer
	json.Indent(&b, ret, "", "\t")
	t.Logf(b.String())
	// Save proof
	t.Logf("proof :,key:%x", proof.MarshalSolidity())
	//export solidity contract
	contract, err := os.Create("verify.sol")
	err = vk.ExportSolidity(contract)
	if err != nil {
		t.Fatalf(err.Error())
	}
	// solidity contract inputs
	proofBytes := proof.MarshalSolidity()
	fpSize := 4 * 8
	var prf [8]*big.Int
	// proof.Ar, proof.Bs, proof.Krs
	t.Logf("printf proof")
	for i := 0; i < 8; i++ {
		prf[i] = new(big.Int).SetBytes(proofBytes[fpSize*i : fpSize*(i+1)])
		t.Logf("proof:" + prf[i].String())
	}

	/*	var commitments [{{mul 2 .NbCommitments}}]*big.Int
		var commitmentPok [2]*big.Int

		// commitments
		t.Logf("printf commitments")
		for i := 0; i < 2*commitmentCount; i++ {
		commitments[i] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+i*fpSize : fpSize*8+4+(i+1)*fpSize])
		t.Logf("commitments:"+commitments[i])
		}
		// commitmentPok
		commitmentPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize : fpSize*8+4+2*commitmentCount*fpSize+fpSize])
		commitmentPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize+fpSize : fpSize*8+4+2*commitmentCount*fpSize+2*fpSize])
		t.Logf("printf commitmentPok")
		t.Logf("commitmentPok 0:"+commitmentPok[0] )
		t.Logf("commitmentPok 1:"+commitmentPok[1] )*/

}
