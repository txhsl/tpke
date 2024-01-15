package tpke

import (
	"crypto/rand"
	"testing"
	"time"

	bls "github.com/kilic/bls12-381"
)

func TestBenchmark(t *testing.T) {
	sampleAmount := 1000
	size := 7
	threshold := 5

	// DKG
	t1 := time.Now()
	dkg := NewDKG(size, threshold)
	dkg.Prepare()
	if err := dkg.Verify(); err != nil {
		t.Fatalf(err.Error())
	}
	pubkey := dkg.PublishGlobalPublicKey()
	prvkeys := dkg.GetPrivateKeys()
	t.Logf("dkg time: %v", time.Since(t1))

	// Build a 1MB script
	script := make([]byte, 1048576)
	rand.Read(script)
	ch := make(chan Message, 10)

	// Encrypt seeds
	seeds := make([]*bls.PointG1, sampleAmount)
	for i := 0; i < sampleAmount; i++ {
		seeds[i] = RandPG1()
	}
	encryptedSeeds := Encrypt(seeds, pubkey)

	// Verify encrypted seeds
	for i := 0; i < sampleAmount; i++ {
		go parallelCTVerify(encryptedSeeds[i], ch)
	}
	_, err := messageHandler(ch, sampleAmount)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// AES encrypt with different seeds
	for i := 0; i < sampleAmount; i++ {
		go parallelAESEncrypt(i, seeds[i], script, ch)
	}
	cipherTexts, err := messageHandler(ch, sampleAmount)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Generate shares
	t2 := time.Now()
	shares := decryptShare(encryptedSeeds, prvkeys)
	t.Logf("share generation time: %v", time.Since(t2))

	// Decrypt seeds
	t3 := time.Now()
	decryptedSeeds, err := Decrypt(encryptedSeeds, shares, pubkey, threshold, dkg.GetScaler())
	if err != nil {
		t.Fatalf(err.Error())
	}
	t.Logf("threshold decryption time: %v", time.Since(t3))

	// Decrypt scripts
	t4 := time.Now()
	for i := 0; i < sampleAmount; i++ {
		go parallelAESDecrypt(i, decryptedSeeds[i], cipherTexts[i], ch)
	}
	results, err := messageHandler(ch, sampleAmount)
	if err != nil {
		t.Fatalf(err.Error())
	}
	t.Logf("aes decryption time: %v", time.Since(t4))

	for i := 0; i < 1000; i++ {
		if !bls.NewG1().Equal(seeds[i], decryptedSeeds[i]) {
			t.Fatalf("tpke decryption failed.")
		}
		for j := 0; j < len(script); j++ {
			if results[i][j] != script[j] {
				t.Fatalf("aes decryption failed.")
			}
		}
	}
}

type Message struct {
	index int
	data  []byte
	err   error
}

func parallelCTVerify(ct *CipherText, ch chan<- Message) {
	ch <- Message{
		index: 0,
		err:   ct.Verify(),
		data:  nil,
	}
}

func parallelAESEncrypt(index int, seed *bls.PointG1, input []byte, ch chan<- Message) {
	result, err := AESEncrypt(seed, input)
	ch <- Message{
		index: index,
		data:  result,
		err:   err,
	}
}

func parallelAESDecrypt(index int, seed *bls.PointG1, input []byte, ch chan<- Message) {
	result, err := AESDecrypt(seed, input)
	ch <- Message{
		index: index,
		data:  result,
		err:   err,
	}
}

func messageHandler(ch <-chan Message, amount int) ([][]byte, error) {
	results := make([][]byte, amount)
	for i := 0; i < amount; i++ {
		msg := <-ch
		if msg.err != nil {
			return nil, msg.err
		}
		results[msg.index] = msg.data
	}
	return results, nil
}
