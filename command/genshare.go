package command

// Construct shares:
// 	echo secret | sos genshares --recipients recipients.txt --threshold 30 --out shares
// 	Share secret into shares with a threshold of 30. Recipients are read from recipients.txt
// 	Outputs shares on stdout or write to --out

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/JonathanLogan/shamironsalt/shares"
)

// GenSharesCommand options for this command
type GenSharesCommand struct {
	FileName   string `short:"o" long:"outfile" description:"output filename to write the shares to" value-name:"FILE" required:"true"`
	Recipients string `short:"r" long:"recipients" description:"recipient definition, one recipient public key per line, optional followed by number of shares and number of fakes" value-name:"FILE" required:"true"`
	Threshold  int    `short:"t" long:"threshhold" description:"number of shares required for reconstruction" required:"true"`
	Comment    string `short:"c" long:"comment" description:"comment to describe the secret" value-name:"COMMENT" required:"true"`
	Secret     string `short:"s" long:"secret" description:"the secret to be shared. If not given it is read from STDIN" value-name:"SECRET"`
	AskSecret  bool   `short:"a" long:"asksecret" description:"ask for the secret"`
	Verbose    []bool `short:"v" description:"be verbose. Repeat for more verbosity"`
}

var genSharesCommand GenSharesCommand

// Execute this command
func (c *GenSharesCommand) Execute(args []string) error {
	var err error
	var secret string
	if c.AskSecret {
		c.Secret, err = AskPass("Secret", 10, true)
		if err != nil {
			return err
		}
	} else if len(c.Secret) > 0 {
		secret = c.Secret
	} else {
		secret, err = AskPass("", 10, false)
		if err != nil {
			return err
		}
	}
	out, err := GenShares(secret, c.Comment, c.Recipients, c.FileName, c.Threshold, len(c.Verbose))
	commandOutput = append(commandOutput, out)
	return err
}

func init() {
	_, err := parser.AddCommand("genshares",
		"Generate shares",
		"The genshare command creates a list of new shares written to the -g FILE",
		&genSharesCommand)
	if err != nil {
		panic(err)
	}
}

// ParseRecipientsFile parses a recipient file and returns a list of share group members
func ParseRecipientsFile(recipientsFile string) ([]shares.ShareMember, error) {
	var outShares []shares.ShareMember
	out, err := ReadFile(recipientsFile)
	if err != nil {
		return nil, err
	}
	_ = out
	for _, line := range bytes.Split(out, []byte("\n")) {
		share := shares.ShareMember{}
		parts := bytes.Split(line, []byte(" "))
		if len(parts) >= 1 {
			if len(parts[0]) < 64 {
				continue
			}
			tstring, err := hex.DecodeString(string(parts[0]))
			if err != nil {
				return nil, err
			}
			share.PublicKey = []byte(tstring)
		}
		if len(parts) >= 2 {
			share.NumShares, _ = strconv.Atoi(string(parts[1]))
		}
		if len(parts) >= 3 {
			tint, _ := strconv.Atoi(string(parts[2]))
			if tint > 0 {
				share.HasFake = true
			}
		}
		outShares = append(outShares, share)
		_ = share
	}
	return outShares, nil
}

// GenShares reads recipientsFile, adds secret and recipients to the share definition and creates shares in output
func GenShares(secret, comment, recipientsFile, outputFile string, threshhold int, verbosity int) (string, error) {
	var verboseOutput []byte
	myShares, err := ParseRecipientsFile(recipientsFile)
	if err != nil {
		return "", err
	}
	config, err := shares.New([]byte(secret), []byte(comment), threshhold)
	if err != nil {
		return "", err
	}
	err = config.VerifyInit()
	if err != nil {
		return "", err
	}

	for _, share := range myShares {
		err = config.AddMember(share.PublicKey, share.NumShares, share.HasFake)
		if err != nil {
			verboseOutput = printVerbose(verboseOutput, verbosity, 1, fmt.Sprintf("Recipient add failed: %s %s", string(share.PublicKey), err))
			return "", err
		}
		verboseOutput = printVerbose(verboseOutput, verbosity, 3, fmt.Sprintf("Recipient added: Pubkey:%s Shares: %d Fake: %v", hex.EncodeToString(share.PublicKey), share.NumShares, share.HasFake))
	}

	verboseOutput = printVerbose(verboseOutput, verbosity, 1, fmt.Sprintf("Share group configuration:"))
	verboseOutput = printVerbose(verboseOutput, verbosity, 1, fmt.Sprintf("\tSecretShare: %s", hex.EncodeToString(config.SigKeyPublicHash)))
	verboseOutput = printVerbose(verboseOutput, verbosity, 2, fmt.Sprintf("\tComment: %s", string(config.Comment)))
	verboseOutput = printVerbose(verboseOutput, verbosity, 2, fmt.Sprintf("\tMembers: %d", len(config.Members)))
	verboseOutput = printVerbose(verboseOutput, verbosity, 2, fmt.Sprintf("\tThreshold: %d", config.Threshhold))
	verboseOutput = printVerbose(verboseOutput, verbosity, 2, fmt.Sprintf("\tMax per Member: %d", config.MaxShare))
	verboseOutput = printVerbose(verboseOutput, verbosity, 2, fmt.Sprintf("\tShares: %d", config.ShareCount))
	verboseOutput = printVerbose(verboseOutput, verbosity, 2, fmt.Sprintf("\tFakes: %d", config.FakeCount))

	err = config.Verify()
	if err != nil {
		return "", err
	}
	messagelist, err := config.GenerateMessages()
	if err != nil {
		return "", err
	}
	messages, err := messagelist.GenerateShareMessageList()
	if err != nil {
		return "", err
	}
	err = WriteFile(outputFile, messages)
	if err != nil {
		return "", err
	}

	return string(verboseOutput), nil
}
