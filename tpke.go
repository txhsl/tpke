package tpke

import (
	"math"
	"math/big"

	bls "github.com/kilic/bls12-381"
)

var fpByteSize = 48

type CipherText struct {
	cMsg       *bls.PointG1
	bigR       *bls.PointG1
	commitment *bls.PointG2
}

func (ct *CipherText) ToBytes() []byte {
	out := make([]byte, 4*fpByteSize)
	g1 := bls.NewG1()
	g2 := bls.NewG2()
	copy(out[:fpByteSize], g1.ToCompressed(ct.cMsg))
	copy(out[fpByteSize:2*fpByteSize], g1.ToCompressed(ct.bigR))
	copy(out[2*fpByteSize:4*fpByteSize], g2.ToCompressed(ct.commitment))
	return out
}

func BytesToCipherText(b []byte) (*CipherText, error) {
	g1 := bls.NewG1()
	g2 := bls.NewG2()
	cMsg, err := g1.FromCompressed(b[:fpByteSize])
	if err != nil {
		return nil, err
	}
	bigR, err := g1.FromCompressed(b[fpByteSize : 2*fpByteSize])
	if err != nil {
		return nil, err
	}
	commitment, err := g2.FromCompressed(b[2*fpByteSize : 4*fpByteSize])
	if err != nil {
		return nil, err
	}
	return &CipherText{
		cMsg:       cMsg,
		bigR:       bigR,
		commitment: commitment,
	}, nil
}

func (ct *CipherText) Verify() error {
	// User sends an invalid commitment for his random r
	pairing := bls.NewEngine()
	e1 := pairing.AddPair(ct.bigR, &bls.G2One).Result()
	e2 := pairing.AddPair(&bls.G1One, ct.commitment).Result()
	if !e1.Equal(e2) {
		return NewTPKECiphertextError()
	}
	return nil
}

func Encrypt(msgs []*bls.PointG1, pub *PublicKey) []*CipherText {
	results := make([]*CipherText, len(msgs))
	for i := 0; i < len(msgs); i++ {
		results[i] = pub.Encrypt(msgs[i])
	}
	return results
}

type DecryptionShare struct {
	pg1 *bls.PointG1
}

func (s *DecryptionShare) ToBytes() []byte {
	return bls.NewG1().ToCompressed(s.pg1)
}

func BytesToDecryptionShare(b []byte) (*DecryptionShare, error) {
	pg1, err := bls.NewG1().FromCompressed(b)
	if err != nil {
		return nil, err
	}
	return &DecryptionShare{
		pg1: pg1,
	}, nil
}

type decryptMessage struct {
	index  int
	shares []*DecryptionShare
}

type verifyMessage struct {
	index int
	err   error
}

func decryptShare(cts []*CipherText, prvs map[int]*PrivateKey) map[int]([]*DecryptionShare) {
	results := make(map[int]([]*DecryptionShare))
	ch := make(chan decryptMessage, len(prvs))
	for i := 0; i < len(prvs); i++ {
		go parallelDecryptShare(i+1, prvs[i+1], cts, ch)
	}
	for i := 0; i < len(prvs); i++ {
		msg := <-ch
		results[msg.index] = msg.shares
	}
	close(ch)

	return results
}

func parallelDecryptShare(index int, key *PrivateKey, cts []*CipherText, ch chan<- decryptMessage) {
	shares := make([]*DecryptionShare, len(cts))
	for j := 0; j < len(cts); j++ {
		shares[j] = key.DecryptShare(cts[j])
	}
	ch <- decryptMessage{
		index:  index,
		shares: shares,
	}
}

// PublicKey is used for immediate verification, method returns error if all combinations of shares fail
func Decrypt(cts []*CipherText, inputs map[int]([]*DecryptionShare), pub *PublicKey, threshold int, scaler int) ([]*bls.PointG1, error) {
	if len(inputs) < threshold {
		return nil, NewTPKENotEnoughShareError()
	}

	matrix := make([][]int, len(inputs))              // size=len(inputs)*threshold, including all rows
	shares := make([][]*DecryptionShare, len(inputs)) // size=len(inputs)*len(cts), including all shares

	// Be aware of a random order of decryption shares
	i := 0
	for index, v := range inputs {
		row := make([]int, threshold)
		for j := 0; j < threshold; j++ {
			row[j] = int(math.Pow(float64(index), float64(j)))
		}
		matrix[i] = row
		shares[i] = v
		i++
	}

	// Use different combinations to decrypt
	combs := getCombs(len(inputs), threshold)
	for _, v := range combs {
		m := make([][]int, threshold)              // size=threshold*threshold, only seleted rows
		s := make([][]*DecryptionShare, threshold) // size=threshold*len(cts), only seleted shares
		for i := 0; i < len(v); i++ {
			m[i] = matrix[v[i]]
			s[i] = shares[v[i]]
		}
		results, err := tryDecrypt(cts, m, s, pub, scaler)
		if err == nil {
			return results, nil
		}
	}
	return nil, NewTPKEDecryptionError()
}

func tryDecrypt(cts []*CipherText, matrix [][]int, shares [][]*DecryptionShare, pub *PublicKey, scaler int) ([]*bls.PointG1, error) {
	// Be aware of the integer overflow when the size and threshold of tpke grow big
	d, coeff := feldman(matrix)
	d = scaler / d
	results := make([]*bls.PointG1, len(cts))
	// Compute M=C-d1/d
	denominator := bls.NewFr().FromBytes(big.NewInt(int64(abs(d))).Bytes())
	if d < 0 {
		denominator.Neg(denominator)
	}
	ch := make(chan verifyMessage, len(cts))
	g1 := bls.NewG1()
	for i := 0; i < len(cts); i++ {
		rpk := g1.Zero()
		// Add up shares with some factors as d1, and plus -1
		for j := 0; j < len(shares); j++ {
			minor := g1.New()
			g1.MulScalar(minor, shares[j][i].pg1, bls.NewFr().FromBytes(big.NewInt(int64(abs(coeff[j]))).Bytes()))
			if coeff[j] > 0 {
				g1.Neg(minor, minor)
			}
			g1.Add(rpk, rpk, minor)
		}
		// Divide -d1 by d
		g1.MulScalar(rpk, rpk, denominator)
		// Decrypt
		results[i] = g1.Add(g1.Zero(), cts[i].cMsg, rpk)
		// Verify the decryption
		go parallelVerify(i, cts[i], pub.pg1, rpk, ch)
	}
	for i := 0; i < len(cts); i++ {
		msg := <-ch
		if msg.err != nil {
			return nil, msg.err
		}
	}

	return results, nil
}

func parallelVerify(index int, ct *CipherText, pk *bls.PointG1, rpk *bls.PointG1, ch chan<- verifyMessage) {
	// User sends an invalid commitment for his random r
	g2 := bls.NewG2()
	pairing := bls.NewEngine()
	cmt := g2.New()
	g2.Neg(cmt, ct.commitment)
	// Decrypted rpk is not correct, e(pk,rG2)!=e(rpk,G2), decryption fails
	e1 := pairing.AddPair(pk, cmt).Result()
	e2 := pairing.AddPair(rpk, &bls.G2One).Result()
	if !e1.Equal(e2) {
		ch <- verifyMessage{
			index: index,
			err:   NewTPKEDecryptionError(),
		}
		return
	}
	ch <- verifyMessage{
		index: index,
		err:   nil,
	}
}
