package command

import (
	"os"
	"strconv"
	"testing"
	"time"

	flags "github.com/jessevdk/go-flags"
)

func Test_CommandGenKey_Generate(t *testing.T) {
	parser.Options = flags.HelpFlag | flags.PassDoubleDash
	file := "/tmp/shamironsalt.command.genkey" + strconv.Itoa(int(time.Now().Unix()))
	defer os.Remove(file)
	args := []string{
		"genkey",
		"-k", file,
	}
	genKeyCommand = GenKeyCommand{}
	err := Command(args)
	if err != nil {
		t.Errorf("Genkey returned error: %s", err)
	}
	err = Command(args)
	if err == nil {
		t.Errorf("Genkey must fail on existing file")
	}

	args = []string{
		"genkey",
		"-d",
		"-k", file,
	}
	genKeyCommand = GenKeyCommand{}
	err = Command(args)
	if err != nil {
		t.Errorf("Genkey read returned error: %s", err)
	}
	if commandOutput[0] != commandOutput[1] {
		t.Errorf("Genkey reread failed")
	}
	args = []string{
		"genkey",
	}
	genKeyCommand = GenKeyCommand{}
	err = Command(args)
	if err == nil {
		t.Errorf("Genkey must fail if no file is given")
	}
	args = []string{
		"genkey",
		"-d",
		"-k", file + "x",
	}
	genKeyCommand = GenKeyCommand{}
	err = Command(args)
	if err == nil {
		t.Errorf("Genkey display must fail on non-existing file")
	}
	defer os.Remove(file + ".password")
	commandOutput = nil
	args = []string{
		"genkey",
		"-k", file + ".password",
		"-p", "Password",
	}
	genKeyCommand = GenKeyCommand{}
	err = Command(args)
	if err != nil {
		t.Errorf("Genkey with password failed: %s", err)
	}
	args = []string{
		"genkey",
		"-k", file + ".password",
		"-p", "Password",
		"-d",
	}
	genKeyCommand = GenKeyCommand{}
	err = Command(args)
	if err != nil {
		t.Errorf("Genkey display with password failed: %s", err)
	}
	if commandOutput[0] != commandOutput[1] {
		t.Errorf("Genkey reread with password failed")
	}
	args = []string{
		"shamironsalt",
		"genkey",
		"-k", file + ".password",
		"-d",
	}
	genKeyCommand = GenKeyCommand{}
	err = Command(args)
	if err == nil {
		t.Errorf("Genkey display with missing password MUST fail")
	}
}

func Test_CommandGenShares(t *testing.T) {
	file := "/tmp/shamironsalt.Test_CommandParseRecipientsFile." + strconv.Itoa(int(time.Now().Unix()))
	defer os.Remove(file)
	pk1, err := GenKey(file+".pkey1", "")
	defer os.Remove(file + ".pkey1")
	if err != nil {
		t.Errorf("ParseRecipientsFile keygen failed: %s", err)
	}
	pk2, err := GenKey(file+".pkey2", "")
	defer os.Remove(file + ".pkey2")
	if err != nil {
		t.Errorf("ParseRecipientsFile keygen failed: %s", err)
	}
	pk3, err := GenKey(file+".pkey3", "")
	defer os.Remove(file + ".pkey3")
	if err != nil {
		t.Errorf("ParseRecipientsFile keygen failed: %s", err)
	}
	outData := []byte(pk1 + " 2 0\n" + pk2 + " 2\n" + pk3 + " 3 1")
	err = WriteFile(file, outData)
	if err != nil {
		t.Errorf("ParseRecipientsFile failed: %s", err)
	}
	args := []string{
		"genshares",
		"-r", file,
		"-o", file + ".output",
		"-t", "4",
		"-c", "Some irrelevant comment",
		"-vvvv",
		"-s", "SomeSuperSecret",
	}
	defer os.Remove(file + ".output")
	genSharesCommand = GenSharesCommand{}
	err = Command(args)
	if err != nil {
		t.Errorf("Genshares failed: %s", err)
	}
}

func Test_CommandGenRequests(t *testing.T) {
	file := "/tmp/shamironsalt.Test_CommandGenRequests." + strconv.Itoa(int(time.Now().Unix()))
	defer os.Remove(file)
	pk1, err := GenKey(file+".pkey1", "")
	defer os.Remove(file + ".pkey1")
	if err != nil {
		t.Errorf("ParseRecipientsFile keygen failed: %s", err)
	}
	pk2, err := GenKey(file+".pkey2", "")
	defer os.Remove(file + ".pkey2")
	if err != nil {
		t.Errorf("ParseRecipientsFile keygen failed: %s", err)
	}
	pk3, err := GenKey(file+".pkey3", "")
	defer os.Remove(file + ".pkey3")
	if err != nil {
		t.Errorf("ParseRecipientsFile keygen failed: %s", err)
	}
	outData := []byte(pk1 + " 2 0\n" + pk2 + " 2\n" + pk3 + " 3 1")
	err = WriteFile(file, outData)
	if err != nil {
		t.Errorf("ParseRecipientsFile failed: %s", err)
	}
	args := []string{
		"genshares",
		"-r", file,
		"-o", file + ".output",
		"-t", "4",
		"-c", "Some irrelevant comment",
		"-vvvv",
		"-s", "SomeSuperSecret",
	}
	defer os.Remove(file + ".output")
	genSharesCommand = GenSharesCommand{}
	err = Command(args)
	if err != nil {
		t.Errorf("Genshares failed: %s", err)
	}
	// Generate requests
	args = []string{
		"genrequest",
		"-o", file + ".requests",
		"-S", file + ".output",
		"-i", file + ".pkey3",
	}
	defer os.Remove(file + ".requests")
	genRequestCommand = GenRequestCommand{}
	err = Command(args)
	if err != nil {
		t.Errorf("Genrequest failed: %s", err)
	}
}

func Test_CommandRespondRequests(t *testing.T) {
	file := "/tmp/shamironsalt.Test_CommandRespondRequests." + strconv.Itoa(int(time.Now().Unix()))
	defer os.Remove(file)
	pk1, err := GenKey(file+".pkey1", "")
	defer os.Remove(file + ".pkey1")
	if err != nil {
		t.Errorf("ParseRecipientsFile keygen failed: %s", err)
	}
	pk2, err := GenKey(file+".pkey2", "")
	defer os.Remove(file + ".pkey2")
	if err != nil {
		t.Errorf("ParseRecipientsFile keygen failed: %s", err)
	}
	pk3, err := GenKey(file+".pkey3", "")
	defer os.Remove(file + ".pkey3")
	if err != nil {
		t.Errorf("ParseRecipientsFile keygen failed: %s", err)
	}
	outData := []byte(pk1 + " 2 0\n" + pk2 + " 2\n" + pk3 + " 3 1")
	err = WriteFile(file, outData)
	if err != nil {
		t.Errorf("ParseRecipientsFile failed: %s", err)
	}
	args := []string{
		"genshares",
		"-r", file,
		"-o", file + ".output",
		"-t", "4",
		"-c", "Some irrelevant comment",
		"-vvvv",
		"-s", "SomeSuperSecret",
	}
	defer os.Remove(file + ".output")
	genSharesCommand = GenSharesCommand{}
	err = Command(args)
	if err != nil {
		t.Errorf("Genshares failed: %s", err)
	}
	// Generate requests
	args = []string{
		"genrequest",
		"-o", file + ".requests",
		"-S", file + ".output",
		"-i", file + ".pkey3",
	}
	defer os.Remove(file + ".requests")
	genRequestCommand = GenRequestCommand{}
	err = Command(args)
	if err != nil {
		t.Errorf("Genrequest failed: %s", err)
	}
	// Generate response
	args = []string{
		"respond",
		"-r", file + ".requests", // Request
		"-S", file + ".output", // Shares
		"-i", file + ".pkey2", // Identity
		"-o", file + ".response", // Generated response
		"-vv",
	}
	defer os.Remove(file + ".response")
	commandOutput = nil
	respondRequestCommand = RespondRequestCommand{}
	err = Command(args)
	if err != nil {
		t.Errorf("Response failed: %s", err)
	}
	//Output()
}

func Test_CommandRecover(t *testing.T) {
	file := "/tmp/shamironsalt.Test_CommandRecover." + strconv.Itoa(int(time.Now().Unix()))
	defer os.Remove(file)
	pk1, err := GenKey(file+".pkey1", "")
	defer os.Remove(file + ".pkey1")
	if err != nil {
		t.Errorf("ParseRecipientsFile keygen failed: %s", err)
	}
	pk2, err := GenKey(file+".pkey2", "")
	defer os.Remove(file + ".pkey2")
	if err != nil {
		t.Errorf("ParseRecipientsFile keygen failed: %s", err)
	}
	pk3, err := GenKey(file+".pkey3", "")
	defer os.Remove(file + ".pkey3")
	if err != nil {
		t.Errorf("ParseRecipientsFile keygen failed: %s", err)
	}
	outData := []byte(pk1 + " 2 0\n" + pk2 + " 2\n" + pk3 + " 3 1")
	err = WriteFile(file, outData)
	if err != nil {
		t.Errorf("ParseRecipientsFile failed: %s", err)
	}
	args := []string{
		"genshares",
		"-r", file,
		"-o", file + ".output",
		"-t", "4",
		"-c", "Some irrelevant comment",
		"-vvvv",
		"-s", "SomeSuperSecret",
	}
	defer os.Remove(file + ".output")
	genSharesCommand = GenSharesCommand{}
	err = Command(args)
	if err != nil {
		t.Errorf("Genshares failed: %s", err)
	}
	// Generate requests
	args = []string{
		"genrequest",
		"-o", file + ".requests",
		"-S", file + ".output",
		"-i", file + ".pkey3",
	}
	defer os.Remove(file + ".requests")
	genRequestCommand = GenRequestCommand{}
	err = Command(args)
	if err != nil {
		t.Errorf("Genrequest failed: %s", err)
	}
	// Generate response
	args = []string{
		"respond",
		"-r", file + ".requests", // Request
		"-S", file + ".output", // Shares
		"-i", file + ".pkey2", // Identity
		"-o", file + ".response", // Generated response
		"-vv",
	}
	defer os.Remove(file + ".response")
	commandOutput = nil
	respondRequestCommand = RespondRequestCommand{}
	err = Command(args)
	if err != nil {
		t.Errorf("Response failed: %s", err)
	}
	// Generate response
	args = []string{
		"respond",
		"-r", file + ".requests", // Request
		"-S", file + ".output", // Shares
		"-i", file + ".pkey1", // Identity
		"-o", file + ".response1", // Generated response
		"-vv",
	}
	defer os.Remove(file + ".response1")
	commandOutput = nil
	respondRequestCommand = RespondRequestCommand{}
	err = Command(args)
	if err != nil {
		t.Errorf("Response failed: %s", err)
	}
	r1, _ := ReadFile(file + ".response1")
	r2, _ := ReadFile(file + ".response")
	r1 = append(r1, r2...)
	ResponseListFile := file + ".allresponses"
	WriteFile(ResponseListFile, r1)
	defer os.Remove(ResponseListFile)
	// Recover secret
	args = []string{
		"recover",
		"-r", file + ".allresponses", // Request
		"-S", file + ".output", // Shares
		"-i", file + ".pkey3", // Identity
		"-vv",
	}
	commandOutput = nil
	recoverCommand = RecoverCommand{}
	err = Command(args)
	if err != nil {
		t.Errorf("Recover failed: %s", err)
	}
	//Output()
}
