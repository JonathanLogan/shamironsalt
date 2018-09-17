package command

// Respond:
// 	sos --genresponse --secrets secret.txt --identity keyfile --request request
// 	Generate a response message to request for identity keyfile, read from secrets
// 	Demands confirmation.
// 	--batch (assume yes)
// 	--show  show data only
// 	--fake add fakes instead of true shares

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/JonathanLogan/shamironsalt/shares"
)

// RespondRequestCommand CLI params
type RespondRequestCommand struct {
	Shares   string `short:"S" long:"shares" description:"file containing shares from a previous genshare operation" value-name:"FILE" required:"true"`
	Request  string `short:"r" long:"request" description:"file containing the share request" value-name:"FILE" required:"true"`
	Identity string `short:"i" long:"identity" description:"file containing keypair that is part of the share group" value-name:"FILE" required:"true"`
	Password string `short:"p" long:"password" description:"optional password to decrypto keypair" value-name:"PASSWORD"`
	AskPass  bool   `short:"a" long:"askpassword" description:"ask for the password"`
	// Optional
	Display   bool   `short:"d" long:"display" description:"display information about request. Overrides -o"`
	FileName  string `short:"o" long:"outfile" description:"write response to FILE. Otherwise only information about the request is displayed" value-name:"FILE" default:"__NOSUCHFILE"`
	Fake      bool   `short:"F" long:"fake" descrition:"answer with a fake"`
	AddShares int    `short:"R" long:"replyshares" description:"reply with NUMBER shares" value-name:"NUMBER" default:"255"`
	Verbose   []bool `short:"v" description:"be verbose. Repeat for more verbosity"`
}

var respondRequestCommand RespondRequestCommand

// Execute this command
func (c *RespondRequestCommand) Execute(args []string) error {
	var err error
	var out string
	if c.AskPass {
		c.Password, err = AskPass("Password", 10, false)
		if err != nil {
			return err
		}
	}
	if c.Display || c.FileName == "" || c.FileName == "__NOSUCHFILE" {
		// display only
		out, err = DisplayRequest(c.Identity, c.Password, c.Request, c.Shares, len(c.Verbose))
	} else {
		// Generate response
		if c.AddShares <= 0 {
			c.AddShares = 255
		}
		out, err = RespondRequest(c.Identity, c.Password, c.Request, c.Shares, c.FileName, c.AddShares, c.Fake, len(c.Verbose))
	}
	commandOutput = append(commandOutput, out)
	return err
}

func init() {
	_, err := parser.AddCommand("respond",
		"Respond to a share request",
		"Unless -o is given, display information about the request. If -o is given, produce a response",
		&respondRequestCommand)
	if err != nil {
		panic(err)
	}
}

// DisplayRequest displays information about the request
func DisplayRequest(IdentityFile, Password, RequestFile, SharesFile string, verbosity int) (string, error) {
	var out []byte
	pubk, privk, err := ReadKey(IdentityFile, Password)
	if err != nil {
		return "", err
	}
	request, err := ReadFile(RequestFile)
	if err != nil {
		return "", err
	}
	myShares, err := ReadFile(SharesFile)
	if err != nil {
		return "", err
	}
	myData, senderPubK, err := shares.VerifyShareRequestFromList(pubk, privk, request, myShares)
	if err != nil {
		return "", err
	}
	out = printVerbose(out, verbosity, 2, fmt.Sprintf("Sender PubKey: %s", hex.EncodeToString(senderPubK)))
	out = printVerbose(out, verbosity, 2, fmt.Sprintf("My PubKey: %s", hex.EncodeToString(pubk)))
	out = printVerbose(out, verbosity, 1, fmt.Sprintf("Share configuration:"))
	out = printVerbose(out, verbosity, 1, fmt.Sprintf("\tSecretShare ID: %s", hex.EncodeToString(myData.CommonMessageHeader.SigPubKeyHash)))
	out = printVerbose(out, verbosity, 1, fmt.Sprintf("\tComment: %s", string(myData.CommonMessageHeader.Comment)))
	out = printVerbose(out, verbosity, 1, fmt.Sprintf("\tShares: %d", len(myData.MemberMessages[0].Shares)))
	if myData.MemberMessages[0].Fake == nil {
		out = printVerbose(out, verbosity, 1, fmt.Sprintf("\tFake available: false"))
	} else {
		out = printVerbose(out, verbosity, 1, fmt.Sprintf("\tFake available: true"))
	}
	if bytes.Equal(senderPubK, pubk) {
		out = printVerbose(out, verbosity, 1, fmt.Sprintf("\tWILL NOT PRODUCE RESPONSE!"))
	}
	return string(out), nil
}

// RespondRequest displays information about the request
func RespondRequest(IdentityFile, Password, RequestFile, SharesFile, ResponseFile string, NumShares int, Fake bool, verbosity int) (string, error) {
	var out []byte
	pubk, privk, err := ReadKey(IdentityFile, Password)
	if err != nil {
		return "", err
	}
	request, err := ReadFile(RequestFile)
	if err != nil {
		return "", err
	}
	myShares, err := ReadFile(SharesFile)
	if err != nil {
		return "", err
	}
	myData, senderPubK, err := shares.VerifyShareRequestFromList(pubk, privk, request, myShares)
	if err != nil {
		return "", err
	}
	if bytes.Equal(senderPubK, pubk) {
		return "", errors.New("Will not respond to self")
	}
	out = printVerbose(out, verbosity, 2, fmt.Sprintf("Sender PubKey: %s", hex.EncodeToString(senderPubK)))
	out = printVerbose(out, verbosity, 2, fmt.Sprintf("My PubKey: %s", hex.EncodeToString(pubk)))
	out = printVerbose(out, verbosity, 3, fmt.Sprintf("Share configuration:"))
	out = printVerbose(out, verbosity, 3, fmt.Sprintf("\tSecretShare ID: %s", hex.EncodeToString(myData.CommonMessageHeader.SigPubKeyHash)))
	out = printVerbose(out, verbosity, 3, fmt.Sprintf("\tComment: %s", string(myData.CommonMessageHeader.Comment)))
	out = printVerbose(out, verbosity, 3, fmt.Sprintf("\tShares: %d", len(myData.MemberMessages[0].Shares)))
	if myData.MemberMessages[0].Fake == nil {
		out = printVerbose(out, verbosity, 3, fmt.Sprintf("\tFake available: false"))
	} else {
		out = printVerbose(out, verbosity, 3, fmt.Sprintf("\tFake available: true"))
	}
	if NumShares > len(myData.MemberMessages[0].Shares) {
		NumShares = len(myData.MemberMessages[0].Shares)
	}
	sharemessage, err := myData.GenShareReply(senderPubK, NumShares, Fake)
	if err != nil {
		return "", err
	}
	err = WriteFile(ResponseFile, sharemessage)
	if err != nil {
		return "", err
	}
	out = printVerbose(out, verbosity, 1, fmt.Sprintf("Response content:"))
	out = printVerbose(out, verbosity, 2, fmt.Sprintf("\tSecretShare ID: %s", hex.EncodeToString(myData.CommonMessageHeader.SigPubKeyHash)))
	if Fake {
		out = printVerbose(out, verbosity, 1, fmt.Sprintf("\tContains only one fake share!"))
	} else {
		out = printVerbose(out, verbosity, 1, fmt.Sprintf("\tShares: %d", NumShares))
	}

	return string(out), nil
}

//
