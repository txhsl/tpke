package tpke

import (
	"math"
	"math/rand"
	"testing"
	"time"

	bls "github.com/kilic/bls12-381"
)

func TestSingleSignature(t *testing.T) {
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)
	fr, _ := bls.NewFr().Rand(r)
	g1 := bls.NewG1()
	sk := &PrivateKey{
		fr: fr,
	}
	pk := &PublicKey{
		pg1: g1.MulScalar(g1.New(), &bls.G1One, fr),
	}

	msg := []byte("pizza pizza pizza pizza pizza pizza pizza pizza pizza pizza pizza pizza pizza")
	share := sk.SignShare(msg)
	if !pk.VerifySigShare(msg, share) {
		t.Fatalf("invalid signature")
	}
}

func TestThresholdSignature(t *testing.T) {
	size := 7
	threshold := 5
	dkg := NewDKG(size, threshold)
	dkg.Prepare()
	if err := dkg.Verify(); err != nil {
		t.Fatalf(err.Error())
	}
	sks := dkg.GetPrivateKeys()
	pk := dkg.PublishGlobalPublicKey()
	scaler := dkg.GetScaler()

	// Test functionality
	msg := []byte("pizza pizza pizza pizza pizza pizza pizza pizza pizza pizza pizza pizza pizza")
	shares := make(map[int]*SignatureShare)
	for i := 1; i <= len(sks); i++ {
		shares[i] = sks[i].SignShare(msg)
	}
	sig, err := AggregateAndVerifySig(pk, msg, threshold, shares, scaler)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if sig == nil {
		t.Fatalf("invalid signature")
	}

	// Test consistency
	matrix := make([][]int, len(shares))           // size=len(shares)*threshold, including all rows
	inputs := make([]*SignatureShare, len(shares)) // size=len(shares), including all shares

	// Be aware of a random order of decryption shares
	i := 0
	for index, v := range shares {
		row := make([]int, threshold)
		for j := 0; j < threshold; j++ {
			row[j] = int(math.Pow(float64(index), float64(j)))
		}
		matrix[i] = row
		inputs[i] = v
		i++
	}

	// Use different combinations to aggregate
	combs := getCombs(len(shares), threshold)
	sigs := make([]*Signature, 0)
	for _, v := range combs {
		m := make([][]int, threshold)           // size=threshold*threshold, only seleted rows
		s := make([]*SignatureShare, threshold) // size=threshold, only seleted shares
		for i := 0; i < len(v); i++ {
			m[i] = matrix[v[i]]
			s[i] = inputs[v[i]]
		}
		sig := aggregateShares(m, s, scaler)
		sigs = append(sigs, sig)
	}

	s0 := sigs[0]
	for i := 1; i < len(sigs); i++ {
		if !sigs[i].Equals(s0) {
			t.Fatalf("different signature")
		}
	}
}
