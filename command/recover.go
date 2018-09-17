package command

// Recover:
// 	sos --recover --identity keyfile --responses responses.txt --secret secrets.txt --request request.txt
// 	Recover the secret from responses concerning request.txt.

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/JonathanLogan/shamironsalt/shares"
)

// RecoverCommand CLI params
type RecoverCommand struct {
	Shares    string `short:"S" long:"shares" description:"file containing shares from a previous genshare operation" value-name:"FILE" required:"true"`
	Identity  string `short:"i" long:"identity" description:"file containing keypair that is part of the share group" value-name:"FILE" required:"true"`
	Password  string `short:"p" long:"password" description:"optional password to decrypto keypair" value-name:"PASSWORD"`
	Responses string `short:"r" long:"responses" description:"File containing responses to a share request" value-name:"FILE" required:"true"`
	Verbose   []bool `short:"v" description:"be verbose. Repeat for more verbosity"`
	AskPass   bool   `short:"a" long:"askpassword" description:"ask for the password"`
}

var recoverCommand RecoverCommand

// Execute this command
func (c *RecoverCommand) Execute(args []string) error {
	var err error
	var out string
	if c.AskPass {
		c.Password, err = AskPass("Password", 10, false)
		if err != nil {
			return err
		}
	}
	out, err = Recover(c.Identity, c.Password, c.Shares, c.Responses, len(c.Verbose))
	commandOutput = append(commandOutput, out)
	return err
}

func init() {
	_, err := parser.AddCommand("recover",
		"Recover a secret from share request responses",
		"Takes one share message and a list of responses to recover the secret",
		&recoverCommand)
	if err != nil {
		panic(err)
	}
}

// Recover recovers the secret from Sharefile and Responsefile
func Recover(IdentityFile, Password, ShareFile, ResponseFile string, verbosity int) (string, error) {
	var out, pubkey []byte
	pubk, privk, err := ReadKey(IdentityFile, Password)
	if err != nil {
		return "", err
	}
	myShares, err := ReadFile(ShareFile)
	if err != nil {
		return "", err
	}
	myResponses, err := ReadFile(ResponseFile)
	if err != nil {
		return "", err
	}
	messagesReconstruct, err := shares.DecodeShareMessageFromList(pubk, privk, myShares)
	if err != nil {
		return "", err
	}
	out = printVerbose(out, verbosity, 3, fmt.Sprintf("My PubKey: %s", hex.EncodeToString(pubk)))
	out = printVerbose(out, verbosity, 2, fmt.Sprintf("Share configuration:"))
	out = printVerbose(out, verbosity, 2, fmt.Sprintf("\tSecretShare ID: %s", hex.EncodeToString(messagesReconstruct.CommonMessageHeader.SigPubKeyHash)))
	out = printVerbose(out, verbosity, 2, fmt.Sprintf("\tComment: %s", string(messagesReconstruct.CommonMessageHeader.Comment)))

	out = printVerbose(out, verbosity, 1, fmt.Sprintf("Adding responses:"))
	i := 0
	for _, s := range bytes.Split(myResponses, []byte("\n")) {
		if len(s) > 1 {
			i++
			pubkey, err = messagesReconstruct.InsertShareReplies(s, pubk, privk)
			if err == nil {
				out = printVerbose(out, verbosity, 1, fmt.Sprintf("\tAdded response %d: %s", i, hex.EncodeToString(pubkey)))
			} else {
				out = printVerbose(out, verbosity, 1, fmt.Sprintf("\tResponse %d (%s) failed: %s", i, hex.EncodeToString(pubkey), err))
			}
		}
	}

	out = printVerbose(out, verbosity, 2, fmt.Sprintf("Recovery Parameters:"))
	out = printVerbose(out, verbosity, 2, fmt.Sprintf("\tThreshhold: %d", messagesReconstruct.EncryptedCommonHeader.Threshhold))
	out = printVerbose(out, verbosity, 2, fmt.Sprintf("\tMembers participating: %d", len(messagesReconstruct.MemberMessages)))
	sharecount := 0
	for _, m := range messagesReconstruct.MemberMessages {
		sharecount = sharecount + len(m.Shares)
	}
	out = printVerbose(out, verbosity, 2, fmt.Sprintf("\tShares available: %d", sharecount))
	secret, err := messagesReconstruct.Combine()
	if err != nil {
		return "", err
	}
	out = printVerbose(out, verbosity, 1, fmt.Sprintf("Recovered secret: %s", string(secret)))
	if verbosity == 0 {
		out = printVerbose(out, verbosity, 0, fmt.Sprintf("%s", string(secret)))
	}
	return string(out), nil
}
