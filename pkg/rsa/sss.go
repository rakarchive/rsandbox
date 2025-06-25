package rsa

import (
	"crypto/rand"
	"errors"
)

func ShamirEncode(secret []byte, n, k byte) ([][]byte, error) {
	if n <= k {
		return nil, errors.New("crypt: minimum shares must be less than total shares")
	}

	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = append(shares[i], byte(i+1))
	}

	for _, x := range secret {
		poly, err := randPoly(int(k)-1, GaloisField(x))
		if err != nil {
			return nil, err
		}

		for x := byte(1); x <= n; x++ {
			// Evalutate the secret polynomial at x
			result := GaloisField(0)
			for i := 1; i <= len(poly); i++ {
				result = result.Mul(GaloisField(x)).Add(poly[len(poly)-i])
			}

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

	// Ensure the highest degree coefficient is non-zero, otherwise the
	// generated polynomial will have a degree lesser than the required one.
	for poly[degree] == 0 {
		buffer = make([]byte, 1)
		if _, err := rand.Read(buffer); err != nil {
			return nil, err
		}

		poly[degree] = GaloisField(buffer[0])
	}

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

	// Recover each byte of the secret one by one.
	for i := range secret {
		// We use Lagrangian interpolation to figure out the constant coefficient
		// of the secret polynomial, which is the required secret using the provided
		// shares.
		for j, v := range shares {
			xs[j] = GaloisField(v[0])   // First byte is the x-coordinate.
			ys[j] = GaloisField(v[i+1]) // Rest are the y-coordinates for each polynomial.
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

		// Constant coefficient found, save it.
		secret[i] = byte(result)
	}

	return secret, nil
}

const ADD_ORDER = 256
const MUL_ORDER = ADD_ORDER - 1

// A primitive polynomial of degree 8 with coefficients in GF(2). This means
// that α = x (mod P(x)) is a generator of the field GF(2^8).
const PRIMITIVE = 0b100011101

type GaloisField uint8

// Exponentiation and Logarithm tables with respect to a generator of the
// multiplicative group of GF(256).
var expTable [ADD_ORDER]GaloisField
var logTable [ADD_ORDER]int

func init() {
	x := GaloisField(1)
	for i := 0; i < ADD_ORDER; i++ {
		// α = x (mod P(x))
		// α^i = x <=> log_α x = i
		expTable[i] = GaloisField(x)
		logTable[x] = i

		// α = x (mod P(x)) is a generator of the Galois field. As such repeated
		// multiplication by x followed by (mod P(x)) will generate all non-zero
		// elements of GF(2^8).
		x = x.MulAlpha()
	}
}

func (x GaloisField) MulAlpha() GaloisField {
	// Raise x from GF(2)[X]/(P) to the more general GF(2)[X].
	x16 := uint16(x)

	// Multiplying by x is equivalent to moving all the coefficients to the next
	// degree term, which translates to a right shift due to the representation
	// of polynomials used here. Bits are set for every non-zero term in the
	// polynomial where the nth least significat bit represents the n-1th degree.
	x16 <<= 1

	// When reducing back to GF(2)[X]/(P), we must ensure that representation of
	// x is compatible with what is expected by GaloisField. Since the remainder
	// after Eucledian division by P(x) is no longer equal to the original
	// polynomial if the 8th degree coefficient is non-zero, we subtract P(x) to
	// get the actual remainder after division by P(x), which is the correct
	// representation of the polynomial in GF(2)[X]/(P).
	if x16&ADD_ORDER != 0 {
		x16 ^= PRIMITIVE
	}

	// Reduce x back down to GF(2)[X]/(P).
	return GaloisField(x16)
}

func (x GaloisField) Log() int {
	return logTable[x]
}

func GaloisExp(i int) GaloisField {
	// Ensure i is in the range [0, 256). If not, bring it into that range by
	// adding or subtracting 256 * k for some positive integer k (mod 256).
	i = (i%MUL_ORDER + MUL_ORDER) % MUL_ORDER
	return expTable[i]
}

func (x GaloisField) Add(y GaloisField) GaloisField {
	return x ^ y
}

func (x GaloisField) Sub(y GaloisField) GaloisField {
	return x ^ y
}

func (x GaloisField) Pow(i int) GaloisField {
	// (α^x)^i = α^xi
	return GaloisExp(i * x.Log())
}

func (x GaloisField) Mul(y GaloisField) GaloisField {
	if x == 0 || y == 0 {
		return 0
	}
	// α^(x + y) = α^x * α^y
	return GaloisExp(x.Log() + y.Log())
}

func (x GaloisField) Div(y GaloisField) GaloisField {
	if x == 0 {
		return 0
	} else if y == 0 {
		panic("GaloisField: division by 0")
	}

	// α^(x - y) = α^x / α^y
	return GaloisExp(x.Log() - y.Log())
}
