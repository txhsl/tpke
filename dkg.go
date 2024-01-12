package tpke

import (
	"math/rand"
	"time"

	crypto "github.com/ethereum/go-ethereum/crypto"
	ecies "github.com/ethereum/go-ethereum/crypto/ecies"
	bls "github.com/kilic/bls12-381"
)

type DKG struct {
	size         int
	threshold    int
	scaler       int // Scaler for global public key, to speed up decryption
	participants []*Participant
	messageBox   [][][]byte
}

type Participant struct {
	ethPrvKey       *ecies.PrivateKey
	ethPubKey       *ecies.PublicKey
	secret          *Secret
	pvss            *PVSS
	receivedSecrets []*bls.Fr
}

func NewDKG(size int, threshold int) *DKG {
	participants := make([]*Participant, size)
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)
	for i := 0; i < size; i++ {
		key, _ := ecies.GenerateKey(random, crypto.S256(), nil)
		participants[i] = NewParticipant(key)
	}
	return &DKG{
		size:         size,
		threshold:    threshold,
		scaler:       getEncryptionScaler(size, threshold),
		participants: participants,
	}
}

func (dkg *DKG) Prepare() {
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)
	dkg.messageBox = make([][][]byte, dkg.size)
	for i := 0; i < dkg.size; i++ {
		dkg.messageBox[i] = make([][]byte, dkg.size)
	}
	for i := 0; i < dkg.size; i++ {
		// Init random polynomial a
		dkg.participants[i].GenerateSecret(dkg.threshold)
		// Compute PVSS
		sharedSecrets := dkg.participants[i].GenerateShares(dkg.size)
		// Send messages
		for j := 0; j < dkg.size; j++ {
			sharedSecret := sharedSecrets[j].ToBytes()
			msg, _ := ecies.Encrypt(random, dkg.participants[j].ethPubKey, sharedSecret[:32], nil, nil)
			dkg.messageBox[j][i] = msg
		}
	}
}

func (dkg *DKG) Verify() error {
	for i := 0; i < dkg.size; i++ {
		// Verify PVSS
		if !dkg.participants[i].VerifyPVSS() {
			return NewDKGPVSSError()
		}
	}
	g1 := bls.NewG1()
	pairing := bls.NewEngine()
	for i := 0; i < dkg.size; i++ {
		dkg.participants[i].receivedSecrets = make([]*bls.Fr, dkg.size)
		// Verify received secrets
		for j := 0; j < dkg.size; j++ {
			ss, _ := dkg.participants[i].ethPrvKey.Decrypt(dkg.messageBox[i][j], nil, nil)
			// e(r1*fi,g2)=e(bigfi,r2)
			fi := bls.NewFr().FromBytes(ss)
			commitment := dkg.participants[j].pvss
			r1 := g1.New().Set(commitment.r1)
			e1 := pairing.AddPair(g1.MulScalar(r1, r1, fi), &bls.G2One).Result()
			e2 := pairing.AddPair(commitment.bigf[i], commitment.r2).Result()
			if !e1.Equal(e2) {
				return NewDKGSecretError()
			}
			// Cache received secrets
			dkg.participants[i].receivedSecrets[j] = fi
		}
	}
	return nil
}

func (dkg *DKG) PublishGlobalPublicKey() *PublicKey {
	// Compute public key S=sum(A0)
	scs := make([]*SecretCommitment, dkg.size)
	for i := 0; i < dkg.size; i++ {
		scs[i] = dkg.participants[i].pvss.public
	}
	return NewGlobalPublicKey(scs, dkg.scaler)
}

func (dkg *DKG) GetPrivateKeys() map[int]*PrivateKey {
	pks := make(map[int]*PrivateKey)
	for i := 0; i < dkg.size; i++ {
		pks[i+1] = NewPrivateKey(dkg.participants[i].receivedSecrets)
	}
	return pks
}

func (dkg *DKG) GetScaler() int {
	return dkg.scaler
}

func NewParticipant(key *ecies.PrivateKey) *Participant {
	return &Participant{
		ethPrvKey: key,
		ethPubKey: &key.PublicKey,
	}
}

func (p *Participant) GenerateSecret(threshold int) {
	p.secret = RandomSecret(threshold)
}

func (p *Participant) GenerateShares(size int) []*bls.Fr {
	// Generate local random number
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)
	r, _ := bls.NewFr().Rand(random)

	pvss, ss := GenerateSharedSecrets(r, size, p.secret)
	p.pvss = pvss
	return ss
}

func (p *Participant) VerifyPVSS() bool {
	return p.pvss.Verify()
}
