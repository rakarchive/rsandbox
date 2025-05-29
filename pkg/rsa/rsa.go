package rsa

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

const LOG = true

const PRIME_SIZE = 1 << 10
const MODUL_SIZE = PRIME_SIZE * PRIME_SIZE

var E = big.NewInt(1<<16 + 1)

func GenerateKey() (*PrivateKey, error) {
	var key PrivateKey

	for {
		if LOG {
			fmt.Printf("  \x1b[33mrsa\x1b[0m: Generating two \x1b[33m%d-bit primes\x1b[0m \x1b[33mp\x1b[0m and \x1b[33mq\x1b[0m...\n", PRIME_SIZE)
		}
		// Generate two large primes (with bit length PRIME_SIZE).
		p, err := rand.Prime(rand.Reader, PRIME_SIZE)
		if err != nil {
			return nil, err
		}
		q, err := rand.Prime(rand.Reader, PRIME_SIZE)
		if err != nil {
			return nil, err
		}

		if LOG {
			fmt.Println("  \x1b[33mrsa\x1b[0m: Calculating modulus \x1b[33mN = pq\x1b[0m...")
			fmt.Printf("  \x1b[33mrsa\x1b[0m: Using a value of \x1b[33mE = %s\x1b[0m...\n", E)
		}
		key.N = new(big.Int).Mul(p, q) // N = pq
		key.E = E                      // E is a known constant

		// Calculate λ(N), where λ is Carmichael's Totient Function. Since
		// N = pq, λ(N) = lcm(λ(p), λ(q)). Since both p and q are prime numbers,
		// λ(p) = φ(p) = p - 1 and λ(p) = φ(p) = p - 1. So finally, we have
		// λ(N) = lcm(p - 1, q - 1) = |(p - 1) * (q - 1)|/gcd(p - 1, q - 1)
		phiP := new(big.Int).Sub(p, big.NewInt(-1))
		phiQ := new(big.Int).Sub(q, big.NewInt(-1))
		top := new(big.Int).Abs(new(big.Int).Mul(phiP, phiQ)) // |φ(p) * φ(q)|
		gcd := new(big.Int).GCD(nil, nil, phiP, phiQ)         // gcd(φ(p), φ(q))
		lambdaN := new(big.Int).Div(top, gcd)                 // λ(N)

		if LOG {
			fmt.Println("  \x1b[33mrsa\x1b[0m: Verifying correctness: \x1b[33m1 < E < λ(N)\x1b[0m and \x1b[33mgcd(E, λ(N)) = 1\x1b[0m...")
		}
		// Verify the invariants E < λ(N) and gcd(E, λ(N)) = 1.
		if E.Cmp(lambdaN) != -1 ||
			new(big.Int).GCD(nil, nil, lambdaN, E).Cmp(big.NewInt(1)) != 0 {
			if LOG {
				fmt.Println("\x1b[31mrsa\x1b[0m: Verification failed. Retrying...")
			}
			continue
		}

		if LOG {
			fmt.Println("  \x1b[33mrsa\x1b[0m: Generating private key \x1b[33mD\x1b[0m from \x1b[33mDE = 1 (mod λ(N))\x1b[0m...")
		}
		// Find D such that D * E = 1 (mod λ(N))
		key.D = new(big.Int).ModInverse(E, lambdaN)

		return &key, nil
	}
}

// An RSA private key consists of the public part of the key, with the
// additional private exponent which acts as the complement of the public one
// under modular arithmetic. Specifically, ∀ 0 <= m < N, (m^E)^D = m (mod N).
type PrivateKey struct {
	PublicKey
	D *big.Int // exponent (private)
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
