package rsa

import (
	"crypto/rand"
	"errors"
	"fmt"
)

func ShamirEncode(secret []byte, n, k byte) ([][]byte, error) {
	if n <= k {
		return nil, errors.New("crypt: minimum shares must be less than total shares")
	}

	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = append(shares[i], byte(i))
	}

	for _, x := range secret {
		poly, err := randPoly(int(k)-1, GaloisField(x))
		if err != nil {
			return nil, err
		}

		for x := byte(1); x <= n; x++ {
			result := GaloisField(0)
			for i := 1; i <= len(poly); i++ {
				result = result.Mul(GaloisField(x)).Add(poly[len(poly)-i])
			}

			fmt.Printf("Value at %d = %d\n", x, result)
			shares[x-1] = append(shares[x-1], byte(result))
		}
	}

	return shares, nil
}

func randPoly(degree int, constant GaloisField) ([]GaloisField, error) {
	poly := make([]GaloisField, degree+1)
	poly[0] = constant

	buffer := make([]byte, degree-1)
	if _, err := rand.Read(buffer); err != nil {
		return nil, err
	}

	for i := 1; i < degree; i++ {
		poly[i] = GaloisField(buffer[i-1])
	}

	for poly[degree] == 0 {
		buffer = make([]byte, 1)
		if _, err := rand.Read(buffer); err != nil {
			return nil, err
		}

		poly[degree] = GaloisField(buffer[0])
	}

	fmt.Println(poly)

	return poly, nil
}

func Decode(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("crypt: too few shares")
	}

	if len(shares[0]) < 2 {
		return nil, errors.New("crypt: invalid shares")
	}

	for _, share := range shares {
		if len(share) != len(shares[0]) {
			return nil, errors.New("crypt: invalid shares")
		}
	}

	xs := make([]GaloisField, len(shares))
	ys := make([]GaloisField, len(shares))
	secret := make([]byte, len(shares[0])-1)

	for i := range secret {
		for j, v := range shares {
			xs[j] = GaloisField(v[0] + 1)
			ys[j] = GaloisField(v[i+1])
		}

		result := GaloisField(0)
		for i := range shares {
			weight := ys[i]
			for j := range shares {
				if i != j {
					// weight *= xs[j] / (xs[j] - xs[i])
					weight = weight.Mul(xs[j].Div(xs[j].Sub(xs[i])))
				}
			}
			// result += weight
			result = result.Add(weight)
		}

		secret[i] = byte(result)
	}

	return secret, nil
}

const BASIS = 1 << 8
const ALPHA_POLY = 0b100011101

type GaloisField uint8

var expTable [BASIS]GaloisField
var logTable [BASIS]int

func init() {
	x := uint16(1)
	for i := 0; i < BASIS; i++ {
		expTable[i] = GaloisField(x)
		logTable[x] = i

		fmt.Printf("%2d: %8b\n", i, x)

		x <<= 1
		if x&BASIS != 0 {
			x ^= ALPHA_POLY
		}

		if x == 1 {
			fmt.Printf("THE ORDER OF THIS FIELD IS %d\n", i+1)
		}
	}

	// for i := GaloisField(1); int(i) < BASIS; i++ {
	// 	if GaloisExp(i.Log()) != i {
	// 		fmt.Printf("%d DOEST WORK RAHHHHHHHHHHHH\n", i)
	// 	}
	// }
}

func (x GaloisField) Log() int {
	return logTable[x]
}

func GaloisExp(i int) GaloisField {
	return expTable[(i%(BASIS-1)+(BASIS-1))%(BASIS-1)]
}

func (x GaloisField) Add(y GaloisField) GaloisField {
	return x ^ y
}

func (x GaloisField) Sub(y GaloisField) GaloisField {
	return x ^ y
}

func (x GaloisField) Pow(i int) GaloisField {
	return GaloisExp(i * x.Log())
}

func (x GaloisField) Mul(y GaloisField) GaloisField {
	if x == 0 || y == 0 {
		return 0
	}
	return GaloisExp(x.Log() + y.Log())
}

func (x GaloisField) Div(y GaloisField) GaloisField {
	if x == 0 {
		return 0
	} else if y == 0 {
		panic("GaloisField: division by 0")
	}
	return GaloisExp(x.Log() - y.Log())
}
