package command

// Request:
// 	sos --genrequests --recipients recipients.txt --identity keyfile --out requests
// 	Generate requests for shares. Reads key from keyfile and recipients. generates
// 	message to each recipient including self written to requests

import (
	"github.com/JonathanLogan/shamironsalt/shares"
)

// GenRequestCommand options for this command
type GenRequestCommand struct {
	FileName string `short:"o" long:"outfile" description:"output filename to write the requests to" value-name:"FILE" required:"true"`
	Shares   string `short:"S" long:"shares" description:"file containing shares from a previous genshare operation" value-name:"FILE" required:"true"`
	Identity string `short:"i" long:"identity" description:"file containing keypair that is part of the share group" value-name:"FILE" required:"true"`
	Password string `short:"p" long:"password" description:"optional password to decrypto keypair" value-name:"PASSWORD"`
	AskPass  bool   `short:"a" long:"askpassword" description:"ask for the password"`
}

var genRequestCommand GenRequestCommand

// Execute this command
func (c *GenRequestCommand) Execute(args []string) error {
	var err error
	if c.AskPass {
		c.Password, err = AskPass("Password", 10, false)
		if err != nil {
			return err
		}
	}
	out, err := GenShareRequests(c.FileName, c.Shares, c.Identity, c.Password, 0)
	commandOutput = append(commandOutput, out)
	return err
}

func init() {
	_, err := parser.AddCommand("genrequest",
		"Generate share request",
		"The genrequest command generates requests for shares",
		&genRequestCommand)
	if err != nil {
		panic(err)
	}
}

// GenShareRequests creates share requestsion in output from shares
func GenShareRequests(outputFile, shareFile, identityFile, password string, verbosity int) (string, error) {
	//ShareRequestMessagesList, err := GenShareRequestMessages(ShareMessagesList, pub[:], priv[:])
	pubk, privk, err := ReadKey(identityFile, password)
	if err != nil {
		return "", err
	}
	myShares, err := ReadFile(shareFile)
	if err != nil {
		return "", err
	}
	shareRequests, err := shares.GenShareRequestMessages(myShares, pubk, privk)
	if err != nil {
		return "", err
	}
	err = WriteFile(outputFile, shareRequests)
	if err != nil {
		return "", err
	}
	return "", nil
}
