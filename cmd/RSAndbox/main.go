package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
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
	_ = context.RunCmd("add", "Alice Bob", true)
	_ = context.RunCmd("list", "", true)

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
		fmt.Println(`
  RSAndbox is a sandbox environment which allows playing around with the RSA
  cryptosystem and its various elements such as key generation, encryption and
  decryption, message signing and verification, etc. The available commands are:

  help           For displaying this help message.
  list           List the available people and their keys.
  add            Add a new person and generate a new key pair for them.`)
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
	default:
		fmt.Print("\x1b[1F\x1b[0K")
		fmt.Printf("\x1b[31m%s %s\x1b[0m\n", cmd, args)
		return fmt.Errorf("unknown command %s", cmd)
	}
	return nil
}
