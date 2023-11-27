package tpke

import (
	"math"

	"github.com/phoreproject/bls"
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
	cMsg       *bls.G1Projective
	bigR       *bls.G1Projective
	commitment *bls.G2Projective
}

type DecryptionShare struct {
	g1 *bls.G1Projective
}

func (tpke *TPKE) Decrypt(cts []*CipherText, inputs map[int]([]*DecryptionShare)) ([]*bls.G1Projective, error) {
	if len(inputs) < tpke.threshold {
		return nil, NewTPKENotEnoughShareError()
	}

	matrix := make([][]int, tpke.threshold)              // size=threshold*threshold
	shares := make([][]*DecryptionShare, tpke.threshold) // size=threshold*len(cts)

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
		if i >= tpke.threshold {
			break
		}
	}

	// Be aware of the integer overflow when the size and threshold of tpke grow big
	d, coeff := feldman(matrix)
	d = tpke.scaler / d
	results := make([]*bls.G1Projective, len(cts))
	// Compute M=C-d1/d
	denominator := bls.FRReprToFR(bls.NewFRRepr(uint64(abs(d))))
	if d < 0 {
		denominator.NegAssign()
	}
	ch := make(chan VerifyMessage, len(cts))
	for i := 0; i < len(cts); i++ {
		dec := bls.G1ProjectiveZero
		// Add up shares with some factors as d1, and plus -1
		for j := 0; j < tpke.threshold; j++ {
			minor := shares[j][i].g1.MulFR(bls.NewFRRepr(uint64(abs(coeff[j])))).ToAffine()
			if coeff[j] > 0 {
				minor.NegAssign()
			}
			dec = dec.AddAffine(minor)
		}
		// Divide -d1 by d
		rpk := dec.MulFR(denominator.ToRepr())
		// Decrypt
		results[i] = cts[i].cMsg.Add(rpk)
		// Verify the decryption
		go parallelVerify(i, cts[i], tpke.pubkey.g1, rpk, ch)
	}
	for i := 0; i < len(cts); i++ {
		msg := <-ch
		if msg.err != nil {
			return nil, msg.err
		}
	}

	return results, nil
}

func parallelVerify(index int, ct *CipherText, pk *bls.G1Projective, rpk *bls.G1Projective, ch chan<- VerifyMessage) {
	// User sends an invalid commitment for his random r
	if !bls.Pairing(ct.bigR, bls.G2ProjectiveOne).Equals(bls.Pairing(bls.G1ProjectiveOne, ct.commitment)) {
		ch <- VerifyMessage{
			index: index,
			err:   NewTPKECiphertextError(),
		}
		return
	}
	cmt := ct.commitment.ToAffine()
	cmt.NegAssign()
	// Decrypted rpk is not correct, decryption fails because of some evil share
	if !bls.Pairing(pk, cmt.ToProjective()).Equals(bls.Pairing(rpk, bls.G2ProjectiveOne)) {
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
