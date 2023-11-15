package tpke

import (
	"math/rand"
	"time"

	rng "github.com/leesper/go_rng"
	"github.com/phoreproject/bls"
)

type DKG struct {
	size         int
	threshold    int
	participants []*Participant
}

type Participant struct {
	secret *SecretKeySet
	public *PublicKeySet
	pvss   *PVSS // All PVSS in one, just for test, secret shares are not encrypted
}

func NewDKG(size int, threshold int) *DKG {
	return &DKG{
		size:      size,
		threshold: threshold,
	}
}

func (dkg *DKG) Prepare() *DKG {
	for i := 0; i < dkg.size; i++ {
		// Init random polynomial a
		secret := RandomSecretKeySet(dkg.threshold)
		// Compute A=a*G1
		p := NewParticipant(secret)
		// Compute PVSS
		p.GeneratePVSS(dkg.size)

		dkg.participants = append(dkg.participants, p)
	}
	return dkg
}

func (dkg *DKG) Verify() bool {
	flag := true
	for i := 0; i < dkg.size; i++ {
		// Verify PVSS
		flag = flag && dkg.participants[i].VerifyPVSS()
	}
	return flag
}

func (dkg *DKG) PublishPubKey() *PublicKey {
	// Compute public key S=sum(A_oi)
	pubkey := dkg.participants[0].GetAZero()
	for i := 1; i < dkg.size; i++ {
		pubkey.Add(dkg.participants[i].GetAZero())
	}
	return &PublicKey{
		G1: pubkey,
	}
}

func NewParticipant(secret *SecretKeySet) *Participant {
	return &Participant{
		secret: secret,
		public: secret.PublicKeySet(),
	}
}

func (p *Participant) GeneratePVSS(size int) {
	// Generate local random number
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	uRng := rng.NewUniformGenerator(int64(r1.Int()))
	r := bls.NewFRRepr(uint64(uRng.Int64()))

	p.pvss = GeneratePVSS(r, size, p.secret)
}

func (p *Participant) VerifyPVSS() bool {
	return p.pvss.Verify()
}

func (p *Participant) GetAZero() *bls.G1Projective {
	return p.pvss.GetAZero()
}
