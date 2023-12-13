package tpke

import (
	"bytes"
	"errors"
	"math"
)

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
