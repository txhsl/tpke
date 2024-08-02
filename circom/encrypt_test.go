package circom

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type EccCircuit[T, S emulated.FieldParams] struct {
	Cpr CipherText[T]
	Msg emulated.Element[S]
	r   emulated.Element[S]
	Pub PublicKey[T, S]
}

func (c *EccCircuit[T, S]) Define(api frontend.API) error {
	c.Pub.VerifyEncrypt(api, sw_emulated.GetCurveParams[T](), &c.Msg, &c.r, &c.Cpr)
	return nil
}

func TestEcdsaEncryptionCircuit(t *testing.T) {

}
