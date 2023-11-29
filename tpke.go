package tpke

import (
	"math"
	"math/big"

	bls "github.com/kilic/bls12-381"
)

type TPKE struct {
	size      int
	threshold int
	scaler    int
	prvkeys   map[int]*PrivateKey
	pubkey    *PublicKey
}

type DecryptMessage struct {
	index  int
	shares []*DecryptionShare
}

type VerifyMessage struct {
	index int
	err   error
}

func NewTPKEFromDKG(dkg *DKG) *TPKE {
	return &TPKE{
		size:      dkg.size,
		threshold: dkg.threshold,
		scaler:    dkg.scaler,
		prvkeys:   dkg.GetPrivateKeys(),
		pubkey:    dkg.PublishPublicKey(),
	}
}

func (tpke *TPKE) Encrypt(msgs []*bls.PointG1) []*CipherText {
	results := make([]*CipherText, len(msgs))
	for i := 0; i < len(msgs); i++ {
		results[i] = tpke.pubkey.Encrypt(msgs[i])
	}
	return results
}

func (tpke *TPKE) DecryptShare(cts []*CipherText) map[int]([]*DecryptionShare) {
	results := make(map[int]([]*DecryptionShare))
	ch := make(chan DecryptMessage, tpke.size)
	for i := 0; i < tpke.size; i++ {
		go parallelDecryptShare(i+1, tpke.prvkeys[i+1], cts, ch)
	}
	for i := 0; i < tpke.size; i++ {
		msg := <-ch
		results[msg.index] = msg.shares
	}
	close(ch)

	return results
}

func parallelDecryptShare(index int, key *PrivateKey, cts []*CipherText, ch chan<- DecryptMessage) {
	shares := make([]*DecryptionShare, len(cts))
	for j := 0; j < len(cts); j++ {
		shares[j] = key.DecryptShare(cts[j])
	}
	ch <- DecryptMessage{
		index:  index,
		shares: shares,
	}
}

type CipherText struct {
	cMsg       *bls.PointG1
	bigR       *bls.PointG1
	commitment *bls.PointG2
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

type DecryptionShare struct {
	pg1 *bls.PointG1
}

func (tpke *TPKE) Decrypt(cts []*CipherText, inputs map[int]([]*DecryptionShare)) ([]*bls.PointG1, error) {
	if len(inputs) < tpke.threshold {
		return nil, NewTPKENotEnoughShareError()
	}

	matrix := make([][]int, len(inputs))              // size=len(inputs)*threshold, including all rows
	shares := make([][]*DecryptionShare, len(inputs)) // size=len(inputs)*len(cts), including all shares

	// Be aware of a random order of decryption shares
	i := 0
	for index, v := range inputs {
		row := make([]int, tpke.threshold)
		for j := 0; j < tpke.threshold; j++ {
			row[j] = int(math.Pow(float64(index), float64(j)))
		}
		matrix[i] = row
		shares[i] = v
		i++
	}

	// Use different combinations to decrypt
	combs := getCombs(len(inputs), tpke.threshold)
	for _, v := range combs {
		m := make([][]int, tpke.threshold)              // size=threshold*threshold, only seleted rows
		s := make([][]*DecryptionShare, tpke.threshold) // size=threshold*len(cts), only seleted shares
		for i := 0; i < len(v); i++ {
			m[i] = matrix[v[i]]
			s[i] = shares[v[i]]
		}
		results, err := tpke.tryDecrypt(cts, m, s)
		if err == nil {
			return results, nil
		}
	}
	return nil, NewTPKEDecryptionError()
}

func (tpke *TPKE) tryDecrypt(cts []*CipherText, matrix [][]int, shares [][]*DecryptionShare) ([]*bls.PointG1, error) {
	// Be aware of the integer overflow when the size and threshold of tpke grow big
	d, coeff := feldman(matrix)
	d = tpke.scaler / d
	results := make([]*bls.PointG1, len(cts))
	// Compute M=C-d1/d
	denominator := bls.NewFr().FromBytes(big.NewInt(int64(abs(d))).Bytes())
	if d < 0 {
		denominator.Neg(denominator)
	}
	ch := make(chan VerifyMessage, len(cts))
	g1 := bls.NewG1()
	for i := 0; i < len(cts); i++ {
		rpk := g1.Zero()
		// Add up shares with some factors as d1, and plus -1
		for j := 0; j < tpke.threshold; j++ {
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
		go parallelVerify(i, cts[i], tpke.pubkey.pg1, rpk, ch)
	}
	for i := 0; i < len(cts); i++ {
		msg := <-ch
		if msg.err != nil {
			return nil, msg.err
		}
	}

	return results, nil
}

func parallelVerify(index int, ct *CipherText, pk *bls.PointG1, rpk *bls.PointG1, ch chan<- VerifyMessage) {
	// User sends an invalid commitment for his random r
	g2 := bls.NewG2()
	pairing := bls.NewEngine()
	cmt := g2.New()
	g2.Neg(cmt, ct.commitment)
	// Decrypted rpk is not correct, e(pk,rG2)!=e(rpk,G2), decryption fails
	e1 := pairing.AddPair(pk, cmt).Result()
	e2 := pairing.AddPair(rpk, &bls.G2One).Result()
	if !e1.Equal(e2) {
		ch <- VerifyMessage{
			index: index,
			err:   NewTPKEDecryptionError(),
		}
		return
	}
	ch <- VerifyMessage{
		index: index,
		err:   nil,
	}
}
