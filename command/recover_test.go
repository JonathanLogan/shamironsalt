package command

import (
	"encoding/hex"
	"os"
	"strconv"
	"testing"
	"time"
)

func Test_Recover(t *testing.T) {
	file := "/tmp/shamironsalt.Test_Recover." + strconv.Itoa(int(time.Now().Unix()))
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
	fileKey1 := file + ".pkey2"
	defer os.Remove(fileKey1)
	GenKey(fileKey1, "")
	pub4, priv4, _ := ReadKey(fileKey1, "")
	fileKey2 := file + ".pkey3"
	GenKey(fileKey2, "")
	pub5, priv5, _ := ReadKey(fileKey2, "")
	defer os.Remove(fileKey2)
	_, _, _, _, _, _, _, _, _, _, _ = pub, priv, pub1, priv1, pub2, priv2, priv3, pub4, priv4, pub5, priv5
	fileRecipient := file + ".recipients"
	fileShares := file + ".shares"
	defer os.Remove(fileRecipient)
	defer os.Remove(fileShares)
	data := []byte(hex.EncodeToString(pub) + " 2\n" + hex.EncodeToString(pub1) +
		" 2 1\n" + hex.EncodeToString(pub2) + " 2 1\n" + hex.EncodeToString(pub3) + " 2\n" +
		hex.EncodeToString(pub4) + " 2 1\n" +
		hex.EncodeToString(pub5) + " 2 1\n")
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
	out, err = DisplayRequest(fileKey1, "", fileOutput, fileShares, 0)
	if err != nil {
		t.Errorf("DisplayRequest failed: %s", err)
	}
	ResponseFile := file + ".responsetoshare1"
	defer os.Remove(ResponseFile)
	out, err = RespondRequest(fileKey1, "", fileOutput, fileShares, ResponseFile, 5, false, 0)
	if err != nil {
		t.Errorf("RespondRequest failed: %s", err)
	}
	ResponseFile2 := file + ".responsetoshare2"
	defer os.Remove(ResponseFile2)
	out, err = RespondRequest(fileKey2, "", fileOutput, fileShares, ResponseFile2, 5, false, 0)
	if err != nil {
		t.Errorf("RespondRequest failed: %s", err)
	}
	r1, _ := ReadFile(ResponseFile)
	r2, _ := ReadFile(ResponseFile2)
	r1 = append(r1, r2...)
	ResponseList := file + ".allresponses"
	WriteFile(ResponseList, r1)
	defer os.Remove(ResponseList)
	out, err = Recover(fileKey, "", fileShares, ResponseList, 0)
	if err != nil {
		t.Errorf("Recover failed: %s", err)
	}
	_ = out
}
