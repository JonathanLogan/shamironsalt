// Package command implements the commands of shamironsalt
package command

import (
	"encoding/hex"
	"fmt"

	"github.com/JonathanLogan/shamironsalt/keymgt"
)

// GenKeyCommand options for this command
type GenKeyCommand struct {
	FileName string `short:"k" long:"keyfile" description:"output filename" value-name:"FILE" required:"true"`
	Display  bool   `short:"d" long:"display" description:"show the public key contained in -k FILE"`
	Password string `short:"p" long:"password" description:"set a password for the key" value-name:"PASSWORD"`
	AskPass  bool   `short:"a" long:"askpassword" description:"ask for the password"`
}

var genKeyCommand GenKeyCommand

// Execute this command
func (c *GenKeyCommand) Execute(args []string) error {
	var err error
	var pubkey string
	if c.AskPass {
		c.Password, err = AskPass("Password", 10, !c.Display)
		if err != nil {
			return err
		}
	}
	if c.Display {
		pubkey, err = ShowKey(c.FileName, c.Password)
	} else {
		pubkey, err = GenKey(c.FileName, c.Password)
	}
	if err == nil {
		commandOutput = append(commandOutput, fmt.Sprintf("%s\n", pubkey))
	}
	return err
}

func init() {
	_, err := parser.AddCommand("genkey",
		"Generate a key",
		"The genkey command creates a new key. Use -k FILE to write the output to FILE",
		&genKeyCommand)
	if err != nil {
		panic(err)
	}
}

// GenKey generates a key and writes it to the given file
func GenKey(filename, password string) (string, error) {
	keydata, pubkey, _, err := keymgt.GenerateKey([]byte(password), nil)
	if err != nil {
		return "", err
	}
	err = WriteFile(filename, keydata)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pubkey), nil
}

// ReadKey reads a keypair from file
func ReadKey(filename, password string) (pubkey, privkey []byte, err error) {
	data, err := ReadFile(filename)
	if err != nil {
		return
	}
	pubkey, privkey, _, err = keymgt.LoadKey(data, []byte(password))
	return
}

// ShowKey displays the public key as hex (as required by the tool)
func ShowKey(filename, password string) (pubkey string, err error) {
	rpubkey, _, err := ReadKey(filename, password)
	if err != nil {
		return
	}
	pubkey = hex.EncodeToString(rpubkey)
	return
}
