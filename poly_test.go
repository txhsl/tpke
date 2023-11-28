package tpke

import (
	"math/big"
	"testing"

	bls "github.com/kilic/bls12-381"
)

func TestPoly_AddAssign(t *testing.T) {
	fr1 := bls.NewFr().FromBytes(big.NewInt(1).Bytes())
	poly := &Poly{
		coeff: []*bls.Fr{
			bls.NewFr().Set(fr1),
			bls.NewFr().Set(fr1),
			bls.NewFr().Set(fr1),
		},
	}
	poly2 := &Poly{
		coeff: []*bls.Fr{
			bls.NewFr().Set(fr1),
			bls.NewFr().Set(fr1),
			bls.NewFr().Set(fr1),
			bls.NewFr().Set(fr1),
			bls.NewFr().Set(fr1),
		},
	}
	t.Logf("%v", poly.coeff)
	poly.AddAssign(poly2)
	t.Logf("%v", poly.coeff)
}

func TestPoly_evaluate(t *testing.T) {
	expectedFr := &bls.Fr{5181237716180834938, 12933092709012868809, 7449062242929247980, 4519714088997883368}
	fr1 := &bls.Fr{18254824737299055921, 12301176899088639156, 11044415995378916883, 357667238319585097}
	fr2 := &bls.Fr{12824654784770937420, 5378575280977611710, 2705578970549845177, 4801150429553808887}
	fr3 := &bls.Fr{4520685442247980328, 10536932062350377723, 4028339353248801528, 1646571793378913296}
	poly := &Poly{
		[]*bls.Fr{
			fr1,
			fr2,
			fr3,
		},
	}

	result := poly.evaluate(*bls.NewFr().FromBytes(big.NewInt(3).Bytes()))
	if !result.Equal(expectedFr) {
		t.Errorf("results are not equal.")
	}
	// PASS
}

func TestPoly_commitment(t *testing.T) {
	fr1 := &bls.Fr{3430707088094777087, 2455690239785479458, 5507155159914335843, 7341630481516121204}
	fr2 := &bls.Fr{360679164676216945, 589008160366285188, 18428004055273428688, 2723678784642027464}
	fr3 := &bls.Fr{5511946094596868462, 16040801034001542498, 9453513069589497919, 2081802114026746926}

	poly := &Poly{
		coeff: []*bls.Fr{
			fr1,
			fr2,
			fr3,
		},
	}

	com := poly.commitment()
	result := com.evaluate(*bls.NewFr().FromBytes(big.NewInt(3).Bytes()))
	t.Logf("%v", com)
	t.Logf("%v", result)
}
