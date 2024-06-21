package tpke

import (
	"bytes"
	"errors"
	"math"
)

func polyRecover(xs []int, ys []int) []int {
	if len(xs) != len(ys) {
		panic("array length mismatch")
	}
	// Compute lagrange
	length := len(ys)
	ns := make([][]int, length)
	ds := make([]int, length)
	for i := 0; i < length; i++ {
		ns[i], ds[i] = lagrange(xs[i], length)
	}
	bigR := 1
	for i := 0; i < length; i++ {
		bigR *= ds[i]
	}
	for i := 0; i < length; i++ {
		div := bigR / ds[i]
		for j := 0; j < len(ns[i]); j++ {
			ns[i][j] *= div
		}
		ds[i] = bigR
	}

	// Recover polynomial
	t := make([]int, 0)
	for i := 0; i < length; i++ {
		poly := make([]int, len(ns[i]))
		for j := 0; j < len(ns[i]); j++ {
			poly[j] = ns[i][j] * ys[i]
		}
		t = polyAdd(t, poly)
	}
	for i := 0; i < len(t); i++ {
		t[i] /= bigR
	}
	return t
}

func lagrange(x int, n int) ([]int, int) {
	numerator := []int{1}
	for i := 0; i < n; i++ {
		if x == i {
			continue
		}
		numerator = polyMul(numerator, []int{-i, 1})
	}
	denominator := 1
	for i := 0; i < n; i++ {
		if x == i {
			continue
		}
		denominator *= x - i
	}
	return numerator, denominator
}

// (a0+a1x+a2x^2)*(b0+b1x+b2x^2)
func polyMul(p1 []int, p2 []int) []int {
	r := make([]int, len(p1)+len(p2)-1)
	for i := 0; i < len(p1); i++ {
		for j := 0; j < len(p2); j++ {
			r[i+j] += p1[i] * p2[j]
		}
	}
	return r
}

// (a0+a1x+a2x^2)+(b0+b1x+b2x^2)
func polyAdd(p1 []int, p2 []int) []int {
	if len(p1) > len(p2) {
		r := make([]int, len(p1))
		for i := 0; i < len(p2); i++ {
			r[i] = p1[i] + p2[i]
		}
		for i := len(p2); i < len(p1); i++ {
			r[i] = p1[i]
		}
		return r
	} else {
		r := make([]int, len(p2))
		for i := 0; i < len(p1); i++ {
			r[i] = p1[i] + p2[i]
		}
		for i := len(p1); i < len(p2); i++ {
			r[i] = p2[i]
		}
		return r
	}
}

func feldman(matrix [][]int) (int, []int) {
	// Compute D, D1
	d, coeff := determinant(matrix, len(matrix))
	g := d
	for i := 0; i < len(coeff); i++ {
		g = gcd(g, coeff[i])
	}
	d = d / g
	for i := 0; i < len(coeff); i++ {
		coeff[i] = coeff[i] / g
	}
	if d < 0 {
		d = -d
		for i := 0; i < len(coeff); i++ {
			coeff[i] = -coeff[i]
		}
	}
	return d, coeff
}

func determinant(matrix [][]int, order int) (int, []int) {
	value := 0
	coeff := make([]int, order)
	sign := 1
	if order == 1 {
		value = matrix[0][0]
		coeff[0] = 1
	} else {
		for i := 0; i < order; i++ {
			cofactor := laplace(matrix, i, 0, order)
			value += sign * matrix[i][0] * cofactor
			coeff[i] = sign * cofactor
			sign *= -1
		}
	}
	return value, coeff
}

func laplace(matrix [][]int, r int, c int, order int) int {
	result := 0
	cofactor := make([][]int, order)
	for i := 0; i < order; i++ {
		cofactor[i] = make([]int, order)
	}
	for i := 0; i < order; i++ {
		for j := 0; j < order; j++ {
			tmpi := i
			tmpj := j
			if i != r && j != c {
				if i > r {
					i--
				}
				if j > c {
					j--
				}
				cofactor[i][j] = matrix[tmpi][tmpj]
				i = tmpi
				j = tmpj
			}
		}
	}
	if order >= 2 {
		result, _ = determinant(cofactor, order-1)
	}
	return result
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	if padding == 0 {
		padding = blockSize
	}
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("empty array")
	}
	unPadding := int(data[length-1])
	if length-unPadding < 0 {
		return nil, errors.New("unpadding failed")
	}
	return data[:(length - unPadding)], nil
}

func gcd(a, b int) int {
	if b == 0 {
		return a
	}
	if b < 0 {
		b = -b
	}
	return gcd(b, a%b)
}

func lcm(a, b int) int {
	return a * b / gcd(a, b)
}

func abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

// To improve computation performance
func getEncryptionScaler(size int, threshold int) int {
	matrix := make([][]int, threshold) // size=threshold*threshold
	return searchDLCM(matrix, 1, 0, 0, size, threshold)
}

func searchDLCM(matrix [][]int, l, pos, offset, size, threshold int) int {
	if pos == threshold {
		d, coeff := feldman(matrix)
		g := d
		for i := 0; i < len(coeff); i++ {
			g = gcd(g, coeff[i])
		}
		d = d / g
		return abs(d)
	}
	for i := pos + offset; i < size-threshold+pos+1; i++ {
		row := make([]int, threshold)
		for j := 0; j < threshold; j++ {
			row[j] = int(math.Pow(float64(i+1), float64(j)))
		}
		matrix[pos] = row
		l = lcm(l, searchDLCM(matrix, l, pos+1, i-pos, size, threshold))
	}
	return l
}

func getCombs(m int, n int) [][]int {
	return searchCombs(make([]int, n), 0, 0, m, n)
}

func searchCombs(arr []int, pos, offset, m, n int) [][]int {
	results := make([][]int, 0)
	if pos == n {
		comb := make([]int, n)
		copy(comb, arr)
		results = append(results, comb)
		return results
	}
	for i := pos + offset; i < m; i++ {
		arr[pos] = i
		results = append(results, searchCombs(arr, pos+1, i-pos, m, n)...)
	}
	return results
}
