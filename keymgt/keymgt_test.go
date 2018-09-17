package keymgt

import (
	"bytes"
	"testing"
)

func Test_GenerateKey(t *testing.T) {
	extradata := []byte("This is additional data")
	keyfile, pubkeyx, privkeyx, err := GenerateKey(nil, extradata)
	if err != nil {
		t.Errorf("Key generation error: %s", err)
	}
	pubkey, privkey, extradatax, err := LoadKey(keyfile, nil)
	if err != nil {
		t.Errorf("Key load failed: %s", err)
	}
	if !bytes.Equal(pubkeyx, pubkey) {
		t.Error("Decoding public key failed")
	}
	if !bytes.Equal(privkeyx, privkey) {
		t.Error("Decoding private key failed")
	}
	if !bytes.Equal(extradata, extradatax) {
		t.Error("Decoding extra data failed")
	}
}

func Test_GenerateKeyPass(t *testing.T) {
	extradata := []byte("This is additional data")
	password := []byte("SuperSecretPassword")
	badpassword := []byte("AttackerPassword")
	keyfile, pubkeyx, privkeyx, err := GenerateKey(password, extradata)
	if err != nil {
		t.Errorf("Key generation error: %s", err)
	}
	pubkey, privkey, extradatax, err := LoadKey(keyfile, password)
	if err != nil {
		t.Errorf("Key load failed: %s", err)
	}
	if !bytes.Equal(pubkeyx, pubkey) {
		t.Error("Decoding public key failed")
	}
	if !bytes.Equal(privkeyx, privkey) {
		t.Error("Decoding private key failed")
	}
	if !bytes.Equal(extradata, extradatax) {
		t.Error("Decoding extra data failed")
	}
	pubkey, privkey, extradatax, err = LoadKey(keyfile, badpassword)
	if err == nil {
		t.Error("Wrong password must fail")
	}
	pubkey, privkey, extradatax, err = LoadKey(keyfile, nil)
	if err == nil {
		t.Error("Empty password must fail")
	}
}
