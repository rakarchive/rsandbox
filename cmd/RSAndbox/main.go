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
	people []entity
}

type entity struct {
	name string
	key  *rsa.PrivateKey
}

func main() {
	context := context{
		people: make([]entity, 0),
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
		for i, entity := range context.people {
			fmt.Printf("  %2d. %-10s (\x1b[34m%s\x1b[0m)\n", i+1, entity.name, entity.key)
		}
	case "add":
		for _, name := range strings.Split(args, " ") {
			key, err := rsa.GenerateKey()
			if err != nil {
				fmt.Printf("  sandbox: %s\n", err)
				break
			}
			context.people = append(context.people, entity{name, key})
			fmt.Printf("  \x1b[32msandbox\x1b[0m: added person \x1b[33m%s\x1b[0m with key \x1b[34m%s\x1b[0m\n", name, key)
		}
	case "quit", "exit":
		return errorStop
	default:
		fmt.Print("\x1b[1F\x1b[0K")
		fmt.Printf("\x1b[31m%s %s\x1b[0m\n", cmd, args)
		return fmt.Errorf("unknown command %s", cmd)
	}
	return nil
}
