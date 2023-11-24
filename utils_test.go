package tpke

import (
	"testing"
)

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
