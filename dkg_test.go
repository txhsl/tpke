package tpke

import (
	"testing"
)

func TestDKG(t *testing.T) {
	dkg := NewDKG(7, 5)
	dkg = dkg.Prepare()
	if !dkg.Verify() {
		t.Fatalf("test failed.")
	}
	pk := dkg.PublishPubKey()
	t.Logf("pks: %v", pk.Serialize())
}
