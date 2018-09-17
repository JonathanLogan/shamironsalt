package command

import (
	"fmt"

	flags "github.com/jessevdk/go-flags"
)

var parser = flags.NewNamedParser("shamironsalt", flags.Default)
var commandOutput []string
var usage = " "

// Command is the shamironsalt command
func Command(args []string) error {
	parser.Usage = usage
	_, err := parser.ParseArgs(args)
	return err
}

// Output prints the output of the command
func Output() {
	first := true
	for _, s := range commandOutput {
		if !first {
			fmt.Print("\n")
		}
		first = false
		fmt.Printf("%s", s)
	}
}
