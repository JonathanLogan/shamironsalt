package command

import (
	"encoding/hex"
	"os"
	"strconv"
	"testing"
	"time"
)

func Test_GenShareRequests(t *testing.T) {
	file := "/tmp/shamironsalt.Test_GenShareRequests." + strconv.Itoa(int(time.Now().Unix()))
	defer os.Remove(file)

	//func GenShareRequests(output, shares, identity, password string, verbosity int) ([]byte, error) {
	pub, _ := hex.DecodeString("f597813ef9699d0e35c959c4dcd5fc9992a71b538cf55125eff5a646ba62723b")
	priv, _ := hex.DecodeString("ed9fc44733dd842400e271c5f0710fdd507666061f2901c281d8e5733e72ac26")
	pub1, _ := hex.DecodeString("b546098710147f9acfc957e9ca2a6d58c4dae0be122125f8f900e2391de96f0e")
	priv1, _ := hex.DecodeString("661af1a4ef288c52b3b65676909cf7c3d99c8daffa77abc574774ad6421d3dab")
	pub2, _ := hex.DecodeString("fabdb52d8f74f6ef4938393f0d5429e619c9bf8329faf1332027c740b3a4204d")
	priv2, _ := hex.DecodeString("7128a04ca0dd76aa57f0f0d68bef5195b768d4b82f4490188e7cbd6915ca5eec")
	fileKey := file + ".pkey1"
	GenKey(fileKey, "")
	pub3, priv3, _ := ReadKey(fileKey, "")
	defer os.Remove(fileKey)
	_, _, _, _, _, _, _ = pub, priv, pub1, priv1, pub2, priv2, priv3
	fileRecipient := file + ".recipients"
	fileShares := file + ".shares"
	defer os.Remove(fileRecipient)
	defer os.Remove(fileShares)
	data := []byte(hex.EncodeToString(pub) + " 2\n" + hex.EncodeToString(pub1) + " 2 1\n" + hex.EncodeToString(pub2) + " 1 1\n" + hex.EncodeToString(pub3) + " 1")
	WriteFile(fileRecipient, data)
	_, err := GenShares("SuperSecret", "No comment", fileRecipient, fileShares, 3, 0)
	if err != nil {
		t.Fatalf("Test setup failed: %s", err)
	}
	fileOutput := file + ".requests"
	defer os.Remove(fileOutput)
	out, err := GenShareRequests(fileOutput, fileShares, fileKey, "", 4)
	if err != nil {
		t.Errorf("GenShareRequests failed: %s", err)
	}
	_ = out
}
