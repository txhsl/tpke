package tpke

import (
	"errors"
	"math"

	"github.com/phoreproject/bls"
)

type TPKE struct {
	size    int
	prvkeys map[int]*PrivateKey
	pubkey  *PublicKey
}

type DecryptMessage struct {
	index  int
	shares []*DecryptionShare
}

func NewTPKEFromDKG(dkg *DKG) *TPKE {
	return &TPKE{
		size:    dkg.size,
		prvkeys: dkg.GetPrivateKeys(),
		pubkey:  dkg.PublishPublicKey(),
	}
}

func (tpke *TPKE) Encrypt(msgs []*bls.G1Projective) []*CipherText {
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
	g1   *bls.G1Projective
	bigR *bls.G1Projective
}

type DecryptionShare struct {
	g1 *bls.G1Projective
}

func Decrypt(cts []*CipherText, threshold int, inputs map[int]([]*DecryptionShare)) ([]*bls.G1Projective, error) {
	if len(inputs) < threshold {
		return nil, errors.New("not enough share")
	}

	matrix := make([][]int, threshold)                // size=threshold*threshold
	matrixG1 := make([][]*DecryptionShare, threshold) // size=threshold*len(cts)
	i := 0
	for index, v := range inputs {
		row := make([]int, threshold)
		for j := 0; j < threshold; j++ {
			row[j] = int(math.Pow(float64(index), float64(j)))
		}
		matrix[i] = row
		matrixG1[i] = v
		i++
		if i >= threshold {
			break
		}
	}

	d, coeff := feldman(matrix)
	results := make([]*bls.G1Projective, len(cts))
	// Compute M=C-d1/d
	denominator := bls.FRReprToFR(bls.NewFRRepr(uint64(abs(d)))).Inverse()
	if d < 0 {
		denominator.NegAssign()
	}
	for i := 0; i < len(cts); i++ {
		dec := bls.G1ProjectiveZero
		for j := 0; j < threshold; j++ {
			minor := matrixG1[j][i].g1.MulFR(bls.NewFRRepr(uint64(abs(coeff[j])))).ToAffine()
			if coeff[j] > 0 {
				minor.NegAssign()
			}
			dec = dec.AddAffine(minor)
		}
		results[i] = cts[i].g1.Add(dec.MulFR(denominator.ToRepr()))
	}

	return results, nil
}
