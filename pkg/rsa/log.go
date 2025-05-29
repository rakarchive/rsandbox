package rsa

import "fmt"

var messages = struct {
	primeGen    string
	modulusGen  string
	valueOfE    string
	correctness string
	notCorrect  string
	keyGen      string
}{
	primeGen:    "\x1b[33mrsa\x1b[0m: Generating two \x1b[33m%d-bit primes\x1b[0m \x1b[33mp\x1b[0m and \x1b[33mq\x1b[0m...\n",
	modulusGen:  "\x1b[33mrsa\x1b[0m: Calculating modulus \x1b[33mN = pq\x1b[0m...\n",
	valueOfE:    "\x1b[33mrsa\x1b[0m: Using a value of \x1b[33mE = %s\x1b[0m...\n",
	correctness: "\x1b[33mrsa\x1b[0m: Verifying correctness: \x1b[33m1 < E < λ(N)\x1b[0m and \x1b[33mgcd(E, λ(N)) = 1\x1b[0m...\n",
	notCorrect:  "\x1b[31mrsa\x1b[0m: Verification failed. Retrying...",
	keyGen:      "\x1b[33mrsa\x1b[0m: Generating private key \x1b[33mD\x1b[0m from \x1b[33mDE = 1 (mod λ(N))\x1b[0m...\n",
}

func logf(form string, args ...any) {
	if LOG {
		fmt.Printf("  "+form, args...)
	}
}
