// shamironsalt implements Shamir's Secret Sharing with NaCl.
package main

import (
	"fmt"
	"os"

	"github.com/JonathanLogan/shamironsalt/command"
)

var intro = "\nIntroduction:\n" +
	"Shamir On Salt (version 0.1) is an implementation of shamir secret sharing combined with a share\n" +
	"exchange protocol based on NaCl.\n" +
	"The process is to have the parties generate a keypair (genkey), then to create a\n" +
	"share group definition, and then to share the secret via genshares.\n" +
	"When the secret needs to be reconstructed, one member of the share group generates\n" +
	"requests to the others by using genrequest. Each of the members is then able to (respond)\n" +
	"to the request so that the initiating member can (recover) the secret. Responses from \n" +
	"share group members must be concated into one file to be read.\n" +
	"All operations occur on files. With the exception of the key files, all files can (and must)\n" +
	" be shared with all members.\n" +
	"The format of a share group definition is publickey (hex encoded), number of shares, fake. \n" +
	"Each separated by space, one line per member. Fake can be either 0 or 1, or omitted.\n" +
	"1 will generate a fake that can be used to withdraw from a reconstruction.\n\n"

func main() {
	var args []string
	if len(os.Args) > 2 {
		args = os.Args
	} else {
		args = append(args, os.Args[0])
		if len(os.Args) > 1 {
			args = append(args, os.Args[1])
		} else {
			fmt.Println(intro)
		}
		args = append(args, "--help")
	}
	err := command.Command(args[1:])
	command.Output()
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
