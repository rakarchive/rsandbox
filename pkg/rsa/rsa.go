package rsa

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

const LOG = true

const PRIME_SIZE = 1 << 6
const MODUL_SIZE = PRIME_SIZE * PRIME_SIZE

var E = big.NewInt(1<<16 + 1)

func GenerateKey() (*PrivateKey, error) {
	var key PrivateKey

	for {
		var err error

		logf(messages.primeGen, PRIME_SIZE)
		// Generate two large primes (with bit length PRIME_SIZE).
		key.P, err = rand.Prime(rand.Reader, PRIME_SIZE)
		if err != nil {
			return nil, err
		}
		key.Q, err = rand.Prime(rand.Reader, PRIME_SIZE)
		if err != nil {
			return nil, err
		}

		logf(messages.modulusGen)
		logf(messages.valueOfE, E)
		key.N = new(big.Int).Mul(key.P, key.Q) // N = pq
		key.E = E                              // E is a known constant

		lambdaN := key.LambdaN()

		logf(messages.correctness)
		// Verify the invariants E < λ(N) and gcd(E, λ(N)) = 1.
		if !validLambdaN(lambdaN) {
			logf(messages.notCorrect)
			continue
		}

		logf(messages.keyGen)

		// Find D such that D * E = 1 (mod λ(N))
		key.D = new(big.Int).ModInverse(E, lambdaN)

		return &key, nil
	}
}

func validLambdaN(lambdaN *big.Int) bool {
	return lambdaN.Cmp(E) == 1 && new(big.Int).GCD(nil, nil, lambdaN, E).Cmp(big.NewInt(1)) == 0
}

// An RSA private key consists of the public part of the key, with the
// additional private exponent which acts as the complement of the public one
// under modular arithmetic. Specifically, ∀ 0 <= m < N, (m^E)^D = m (mod N).
type PrivateKey struct {
	PublicKey
	P, Q *big.Int // primes such that N = PQ
	D    *big.Int // exponent (private)
}

// The RSA cryptosystem can also be used to veryfiy message authenticity by
// encrypting the message with the private exponent, which can then only be
// decrypted using the public exponent and thus verifies the source.
func (key *PrivateKey) Apply(data *big.Int) (*big.Int, error) {
	// We create a new PublicKey with the private exponent as the public
	// exponent and use that key to "encrypt" the message.
	signingKey := PublicKey{
		N: key.N,
		E: key.D,
	}

	return signingKey.Apply(data)
}

// LambdaN calculates λ(N), where λ is Carmichael's Totient Function. Provided
// parameters p and q are the only prime factors of N, i.e. N = pq.
func (key *PrivateKey) LambdaN() *big.Int {
	// Since N = pq, λ(N) = lcm(λ(p), λ(q)). Since both p and q are primes,
	// λ(p) = φ(p) = p - 1 and λ(p) = φ(p) = p - 1. So finally, we have
	// λ(N) = lcm(p - 1, q - 1) = |(p - 1) * (q - 1)|/gcd(p - 1, q - 1)
	phiP := new(big.Int).Sub(key.P, big.NewInt(-1))
	phiQ := new(big.Int).Sub(key.Q, big.NewInt(-1))
	top := new(big.Int).Abs(new(big.Int).Mul(phiP, phiQ)) // |φ(p) * φ(q)|
	gcd := new(big.Int).GCD(nil, nil, phiP, phiQ)         // gcd(φ(p), φ(q))

	return new(big.Int).Div(top, gcd)
}

// An RSA public key consists of the modulus used in all the modular arithmetic
// operations, and the exponent used to encrypt the message by a sender.
type PublicKey struct {
	N *big.Int // modulus
	E *big.Int // exponent (public)
}

func (key *PublicKey) Apply(data *big.Int) (*big.Int, error) {
	switch {
	// Verify that 0 <= data < N.
	case data.Cmp(key.N) != -1:
		return nil, errors.New("  \x1b[33mrsa\x1b[0m: data integer larger than modulus")
	case data.Cmp(big.NewInt(0)) == -1:
		return nil, errors.New("  \x1b[33mrsa\x1b[0m: data integer is negative")

	// All invariants upheld, proceed with encryption.
	default:
		ciphertext := big.NewInt(0)
		// ciphertext = data^E (mod N)
		ciphertext.Exp(data, key.E, key.N)
		return ciphertext, nil
	}
}

func (key *PublicKey) String() string {
	return fmt.Sprintf("%X", key.N)[:16]
}
