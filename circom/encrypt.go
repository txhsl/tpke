package circom

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type PublicKey[Base, Scalar emulated.FieldParams] sw_emulated.AffinePoint[Base]

type CipherText[Base emulated.FieldParams] struct {
	C, R sw_emulated.AffinePoint[Base]
}

func (pk PublicKey[T, S]) VerifyEncrypt(
	api frontend.API,
	params sw_emulated.CurveParams,
	msg frontend.Variable,
	r frontend.Variable,
	cipher *CipherText[T],
) {
	cr, err := sw_emulated.New[T, S](api, params)
	if err != nil {
		panic(err)
	}
	// scalarApi, err := emulated.NewField[S](api)
	// if err != nil {
	// 	panic(err)
	// }
	baseApi, err := emulated.NewField[T](api)
	if err != nil {
		panic(err)
	}
	// Convert bigint to scalar
	scalarM := ToElement[S](api, msg)
	scalarR := ToElement[S](api, r)

	// C = M + rpk
	pkpt := sw_emulated.AffinePoint[T](pk)
	bigR := cr.ScalarMulBase(scalarR)
	bigC := cr.JointScalarMulBase(&pkpt, scalarR, scalarM)

	rx := baseApi.Reduce(&bigR.X)
	rxBits := baseApi.ToBits(rx)
	rbits := baseApi.ToBits(&cipher.R.X)
	if len(rbits) != len(rxBits) {
		panic("non-equal lengths")
	}
	for i := range rbits {
		api.AssertIsEqual(rbits[i], rxBits[i])
	}

	cx := baseApi.Reduce(&bigC.X)
	cxBits := baseApi.ToBits(cx)
	cbits := baseApi.ToBits(&cipher.C.X)
	if len(cbits) != len(cxBits) {
		panic("non-equal lengths")
	}
	for i := range cbits {
		api.AssertIsEqual(cbits[i], cxBits[i])
	}
}

func ToElement[T emulated.FieldParams](api frontend.API, input frontend.Variable) *emulated.Element[T] {
	f, err := emulated.NewField[T](api)
	if err != nil {
		panic(err)
	}

	return f.NewElement(input)
}
