package command

import (
	"os"
	"strconv"
	"testing"
	"time"
)

func Test_GenKey(t *testing.T) {
	file := "/tmp/shamironsalt.genkey.write." + strconv.Itoa(int(time.Now().Unix()))
	defer os.Remove(file)
	_, err := GenKey(file, "")
	if err != nil {
		t.Errorf("Error creating key: %s", err)
	}
}

func Test_ReadKey(t *testing.T) {
	file := "/tmp/shamironsalt.readkey.write." + strconv.Itoa(int(time.Now().Unix()))
	defer os.Remove(file)
	_, err := GenKey(file, "")
	if err != nil {
		t.Errorf("Error creating key: %s", err)
	}
	pubkey, privkey, err := ReadKey(file, "")
	if err != nil {
		t.Errorf("Error reading key: %s", err)
	}
	_, _ = pubkey, privkey
}

func Test_ReadKeyWithPassword(t *testing.T) {
	file := "/tmp/shamironsalt.readkeyWithPW.write." + strconv.Itoa(int(time.Now().Unix()))
	defer os.Remove(file)
	_, err := GenKey(file, "secret password")
	if err != nil {
		t.Errorf("Error creating key: %s", err)
	}
	pubkey, privkey, err := ReadKey(file, "secret password")
	if err != nil {
		t.Errorf("Error reading key: %s", err)
	}
	pubkey, privkey, err = ReadKey(file, "")
	if err == nil {
		t.Errorf("Error reading key: must fail without password")
	}
	_, _ = pubkey, privkey
}

func Test_ShowKey(t *testing.T) {
	file := "/tmp/shamironsalt.showkey." + strconv.Itoa(int(time.Now().Unix()))
	defer os.Remove(file)
	_, err := GenKey(file, "")
	if err != nil {
		t.Errorf("Error creating key: %s", err)
	}
	hex, err := ShowKey(file, "")
	if err != nil {
		t.Errorf("Error reading key: %s", err)
	}
	if len(hex) < 64 {
		t.Error("No key read")
	}
}
