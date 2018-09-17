package command

import (
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
)

func Test_ParseRecipientsFile(t *testing.T) {
	file := "/tmp/shamironsalt.Test_ParseRecipientsFile." + strconv.Itoa(int(time.Now().Unix()))
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
	out, err := ParseRecipientsFile(file)
	if err != nil {
		t.Errorf("ParseRecipientsFile failed: %s", err)
	}
	if len(out) != 3 {
		t.Fatalf("Not all entries parsed")
	}
	if out[0].NumShares != 2 {
		t.Errorf("NumShares not recognized")
	}
	if out[2].NumShares != 3 {
		t.Errorf("NumShares 2 not recognized")
	}
	if out[0].HasFake != false {
		t.Errorf("HasFake 0 not recognized")
	}
	if out[2].HasFake != true {
		t.Errorf("HasFake 2 not recognized")
	}
	defer os.Remove(file + ".shares")
	op, err := GenShares("supersecret", "My comment", file, file+".shares", 4, 0)
	if err != nil {
		t.Errorf("GenShares failed: %s", err)
	}
	fmt.Print(op)
	_ = out
}
