package main

import (
	"bufio"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/rakarchive/rsa/pkg/rsa"
)

type context struct {
	people map[string]*rsa.PrivateKey
}

func main() {
	context := context{
		people: make(map[string]*rsa.PrivateKey),
	}

	// Prerun some commands
	_ = context.RunCmd("help", "", true)
	_ = context.RunCmd("add", "Alice Bob", true)
	_ = context.RunCmd("list", "", true)
	_ = context.RunCmd("inspect", "Bob", true)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		prompt := scanner.Text()
		cmd, args, _ := strings.Cut(strings.Trim(prompt, " \t\n\r"), " ")
		switch err := context.RunCmd(cmd, args, false); err {
		case nil:
		case errorStop:
			return
		default:
			fmt.Printf("  \x1b[31msandbox\x1b[0m: %s\n", err)
		}
	}
}

var errorStop = errors.New("stop sandbox")

func (context *context) RunCmd(cmd, args string, auto bool) error {
	if !auto {
		fmt.Print("\x1b[1F\x1b[0K")
	}
	fmt.Printf("\x1b[32m%s\x1b[0m \x1b[33m%s\x1b[0m\n", cmd, args)

	switch cmd {
	case "help":
		fmt.Print("\x1b[33m")
		fmt.Println("  RSAndbox is a sandbox environment which allows playing around with")
		fmt.Println("  the RSA cryptosystem and its various elements such as key generation,")
		fmt.Println("  encryption and decryption, message signing and verification, etc.")
		fmt.Println("  The available commands are:")
		fmt.Println("\x1b[0m")
		fmt.Println("  \x1b[32mhelp\x1b[0m             For displaying this help message.")
		fmt.Println("  \x1b[32mlist\x1b[0m             List the available people and their keys.")
		fmt.Println("  \x1b[32madd\x1b[0m \x1b[33m<name>\x1b[0m       Generate a new key pair with the given name.")
		fmt.Println("  \x1b[32minspect\x1b[0m \x1b[33m<name>\x1b[0m   Inspect the key pair for the given person.")
		fmt.Println()
		fmt.Println("  \x1b[32mencrypt\x1b[0m \x1b[33m<name> <message>\x1b[0m   Applies the public key to the string.")
		fmt.Println("  \x1b[32mdecrypt\x1b[0m \x1b[33m<name> <message>\x1b[0m   Applies the private key to the ciphertext.")
		fmt.Println("  \x1b[32msign\x1b[0m \x1b[33m<name> <message>\x1b[0m      Applies the private key to the string.")
		fmt.Println("  \x1b[32mverify\x1b[0m \x1b[33m<name> <message>\x1b[0m    Applies the public key to the ciphertext.")
	case "list":
		i := 1
		for name, key := range context.people {
			fmt.Printf("  %2d. %-10s (\x1b[34m%s\x1b[0m)\n", i, name, key)
			i += 1
		}
	case "add":
		for _, name := range strings.Split(args, " ") {
			key, err := rsa.GenerateKey()
			if err != nil {
				fmt.Printf("  sandbox: %s\n", err)
				break
			}
			context.people[name] = key
			fmt.Printf("  \x1b[32msandbox\x1b[0m: added person \x1b[33m%s\x1b[0m with key \x1b[34m%s\x1b[0m\n", name, key)
		}
	case "quit", "exit":
		return errorStop
	case "inspect":
		key, found := context.people[args]
		if !found {
			return fmt.Errorf("no person named \x1b[31m%s\x1b[0m found", args)
		}

		fmt.Println("  \x1b[32mPublic data:\x1b[0m")
		fmt.Printf("    \x1b[32mN\x1b[0m    = %X\n", key.N)
		fmt.Printf("    \x1b[32mE\x1b[0m    = %X\n", key.E)

		fmt.Println("  \x1b[31mPrivate data:\x1b[0m")
		fmt.Printf("    \x1b[31mP\x1b[0m    = %X\n", key.P)
		fmt.Printf("    \x1b[31mQ\x1b[0m    = %X\n", key.Q)
		fmt.Printf("    \x1b[31mλ(N)\x1b[0m = %X\n", key.LambdaN())
		fmt.Printf("    \x1b[31mD\x1b[0m    = %X\n", key.D)

	case "encrypt":
		return context.rsaHelper(args, true, false)
	case "decrypt":
		return context.rsaHelper(args, false, true)
	case "sign":
		return context.rsaHelper(args, false, false)
	case "verify":
		return context.rsaHelper(args, true, true)

	case "attack(multiply)":
		keyName, rest, found := strings.Cut(args, " ")
		if !found {
			return errors.New("expected a key, a fraction, and a message")
		}

		fraction, messageStr, found := strings.Cut(rest, " ")
		if !found {
			return errors.New("expected a key, a fraction, and a message")
		}

		key, found := context.people[keyName]
		if !found {
			return fmt.Errorf("no person named \x1b[31m%s\x1b[0m found", keyName)
		}

		nStr, dStr, found := strings.Cut(fraction, "/")
		if !found {
			dStr = "1"
		}

		n, err := strconv.ParseInt(nStr, 10, 64)
		if err != nil {
			return err
		}
		d, err := strconv.ParseInt(dStr, 10, 64)
		if err != nil {
			return err
		}

		msg, ok := new(big.Int).SetString(messageStr, 16)
		if !ok {
			return fmt.Errorf("\"%s\" is not a valid number", messageStr)
		}

		nCoeff, err := key.PublicKey.Apply(big.NewInt(n))
		if err != nil {
			return err
		}
		dInv := new(big.Int).ModInverse(big.NewInt(d), key.N)
		dCoeff, err := key.PublicKey.Apply(dInv)
		if err != nil {
			return err
		}

		msg.Mul(msg, nCoeff)
		msg.Mul(msg, dCoeff)
		msg.Mod(msg, key.N)

		fmt.Printf("  %x\n", msg)

	case "key":
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter key name: ")
		name, err := reader.ReadString('\n')
		if err != nil {
			return err
		}

		name = strings.Trim(name, " \n\r\t")

		fmt.Print("Enter value of p: ")
		pStr, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		pStr = strings.Trim(pStr, " \n\r\t")
		fmt.Print("Enter value of q: ")
		qStr, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		qStr = strings.Trim(qStr, " \n\r\t")

		p, ok := new(big.Int).SetString(pStr, 10)
		if !ok {
			return fmt.Errorf("\"%s\" is not a valid number", pStr)
		}
		q, ok := new(big.Int).SetString(qStr, 10)
		if !ok {
			return fmt.Errorf("\"%s\" is not a valid number", qStr)
		}

		context.people[name], err = rsa.NewPrivateKey(p, q)
		if err != nil {
			return err
		}

	default:
		fmt.Print("\x1b[1F\x1b[0K")
		fmt.Printf("\x1b[31m%s %s\x1b[0m\n", cmd, args)
		return fmt.Errorf("unknown command %s", cmd)
	}
	return nil
}

func (context *context) rsaHelper(prompt string, publicKey, rawInput bool) error {
	keyOf, dataStr, _ := strings.Cut(prompt, " ")
	key, found := context.people[keyOf]
	if !found {
		return fmt.Errorf("no person named \x1b[31m%s\x1b[0m found", keyOf)
	}

	data := new(big.Int)
	if rawInput {
		_, ok := data.SetString(dataStr, 16)
		if !ok {
			return fmt.Errorf("couldn't parse raw input %s", dataStr)
		}
	} else {
		data.SetBytes([]byte(dataStr))
	}

	var err error
	applied := new(big.Int)

	if publicKey {
		applied, err = key.PublicKey.Apply(data)
	} else {
		applied, err = key.Apply(data)
	}
	if err != nil {
		return err
	}

	if rawInput {
		fmt.Printf("  %s\n", string(applied.Bytes()))
	}
	fmt.Printf("  %x\n", applied)

	return nil
}
