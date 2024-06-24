package tpke

import (
	"math/big"
	"testing"
)

func TestRecover(t *testing.T) {
	p := polyRecover([]int{1, 2, 3, 4, 5}, []*big.Int{big.NewInt(3), big.NewInt(7), big.NewInt(13), big.NewInt(21), big.NewInt(31)})
	if p[0].Int64() != 1 || p[1].Int64() != 1 || p[2].Int64() != 1 || p[3].Int64() != 0 || p[4].Int64() != 0 {
		t.Fatalf("recover failed. %v", p)
	}
}

func TestDeterminant(t *testing.T) {
	matrix := [][]int{{7, 8, 9, 4, 3}, {4, 9, 7, 0, 0}, {3, 6, 1, 0, 0}, {0, 5, 6, 0, 0}, {0, 6, 8, 0, 0}}
	result, _ := determinant(matrix, len(matrix))
	if result != 0 {
		t.Fatalf("test failed. %v", result)
	}
	matrix = [][]int{{6, 5, 4, 3, 2}, {4, 9, 7, 0, 0}, {3, 6, 1, 0, 0}, {0, 5, 6, 0, 0}, {0, 6, 8, 0, 0}}
	result, _ = determinant(matrix, len(matrix))
	if result != 0 {
		t.Fatalf("test failed. %v", result)
	}
	matrix = [][]int{{6, 5, 4, 3, 2}, {7, 8, 9, 4, 3}, {3, 6, 1, 0, 0}, {0, 5, 6, 0, 0}, {0, 6, 8, 0, 0}}
	result, _ = determinant(matrix, len(matrix))
	if result != 12 {
		t.Fatalf("test failed. %v", result)
	}
	matrix = [][]int{{6, 5, 4, 3, 2}, {7, 8, 9, 4, 3}, {4, 9, 7, 0, 0}, {0, 5, 6, 0, 0}, {0, 6, 8, 0, 0}}
	result, _ = determinant(matrix, len(matrix))
	if result != 16 {
		t.Fatalf("test failed. %v", result)
	}
	matrix = [][]int{{6, 5, 4, 3, 2}, {7, 8, 9, 4, 3}, {4, 9, 7, 0, 0}, {3, 6, 1, 0, 0}, {0, 6, 8, 0, 0}}
	result, _ = determinant(matrix, len(matrix))
	if result != 78 {
		t.Fatalf("test failed. %v", result)
	}
	matrix = [][]int{{6, 5, 4, 3, 2}, {7, 8, 9, 4, 3}, {4, 9, 7, 0, 0}, {3, 6, 1, 0, 0}, {0, 5, 6, 0, 0}}
	result, _ = determinant(matrix, len(matrix))
	if result != 67 {
		t.Fatalf("test failed. %v", result)
	}
	matrix = [][]int{{7, 6, 5, 4, 3, 2}, {9, 7, 8, 9, 4, 3}, {7, 4, 9, 7, 0, 0}, {5, 3, 6, 1, 0, 0}, {0, 0, 5, 6, 0, 0}, {0, 0, 6, 8, 0, 0}}
	result, coeff := determinant(matrix, len(matrix))
	if result != 4 {
		t.Fatalf("test failed. %v", result)
	}
	if coeff[0]*7+coeff[1]*9+coeff[2]*7+coeff[3]*5+coeff[4]*0+coeff[5]*0 != result {
		t.Fatalf("test failed.")
	}
}
