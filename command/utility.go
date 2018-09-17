package command

import (
	"errors"
	"fmt"
	"os"
	"strings"

	//	"code.google.com/p/gopass"
	"github.com/mewbak/gopass"
)

// WriteFile writes data into filename if filename does not exist
func WriteFile(filename string, data []byte) error {
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_EXCL|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(data)
	if err != nil {
		return err
	}
	err = file.Sync()
	if err != nil {
		return err
	}

	return nil
}

// ReadFile reads all content from filename and returns it
func ReadFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	if size == 0 {
		return nil, errors.New("Empty file")
	}
	data := make([]byte, size)
	n, err := file.Read(data)
	if err != nil {
		return nil, err
	}
	if int64(n) != size {
		return nil, errors.New("File changed while reading")
	}
	return data, nil
}

// PrintError prints an error to stderr
func PrintError(format string, a ...interface{}) error {
	_, err := fmt.Fprintf(os.Stderr, format, a...)
	return err
}

func printVerbose(out []byte, verbosity, level int, message string) []byte {
	if verbosity >= level {
		out = append(out, []byte(message+"\n")...)
	}
	return out
}

//  code.google.com/p/gopass  GetPass(prompt string) (passwd string, err error)

// AskPass asks for a password of minlength and confirms by double entry
func AskPass(prompt string, minlength int, confirm bool) (string, error) {
	var prompt1, prompt2 string
	if len(prompt) > 0 {
		prompt1 = prompt + ": "
		prompt2 = prompt + " (repeat): "
	}
	pass, err := gopass.GetPass(prompt1)
	if err != nil {
		return "", err
	}
	if confirm {
		if len(pass) < minlength {
			return "", errors.New("Password: Too short")
		}
		pass2, err := gopass.GetPass(prompt2)
		if err != nil {
			return "", err
		}
		pass = strings.TrimSpace(pass)
		pass2 = strings.TrimSpace(pass2)
		if pass != pass2 {
			return "", errors.New("Password: Inputs do not match")
		}
	}
	return strings.TrimSpace(pass), nil
}
