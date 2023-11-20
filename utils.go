package tpke

func feldman(matrix [][]int) (int, []int) {
	// Compute D, D1
	return determinant(matrix, len(matrix))
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
