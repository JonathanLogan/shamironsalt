package naclwrapper

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/JonathanLogan/shamironsalt/bytepack"

	"golang.org/x/crypto/nacl/box"
)

func Test_Encrypt(t *testing.T) {
	tdata := []byte("This is a test message +++ This is a test message")
	spub, spriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	box, err := Encrypt(tdata, nil, (*spub)[:], (*spriv)[:])
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	//fmt.Println(box)
	data, err := Decrypt(box, (*spub)[:], (*spriv)[:])
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	if !bytes.Equal(data, tdata) {
		t.Error("Error: Decryption fails")
	}
}

func Test_EncryptForeign(t *testing.T) {
	tdata := []byte("This is a test message +++ This is a test message")
	spub, spriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	rpub, rpriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	box, err := Encrypt(tdata, (*rpub)[:], (*spub)[:], (*spriv)[:])
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	data, err := Decrypt(box, (*spub)[:], (*spriv)[:])
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	if !bytes.Equal(data, tdata) {
		t.Error("Error: Decryption fails")
	}
	data, err = Decrypt(box, (*rpub)[:], (*rpriv)[:])
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	if !bytes.Equal(data, tdata) {
		t.Error("Error: Decryption fails")
	}
	_ = rpriv
}

func Test_EncryptPack(t *testing.T) {
	var output []byte
	tdata := []byte("This is a test message +++ This is a test message")
	spub, spriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	box, err := EncryptPack(tdata, nil, (*spub)[:], (*spriv)[:])
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	fields, _ := bytepack.UnpackAll(box)
	output = append(output, fields[1]...)
	output = append(output, fields[2]...)
	output = append(output, fields[3]...)
	output = append(output, fields[4]...)
	data, err := Decrypt(output, (*spub)[:], (*spriv)[:])
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	if !bytes.Equal(data, tdata) {
		t.Error("Error: Decryption fails")
	}
}

func Test_DecryptPack(t *testing.T) {
	tdata := []byte("This is a test message +++ This is a test message")
	spub, spriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	box, err := EncryptPack(tdata, nil, (*spub)[:], (*spriv)[:])
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	data, err := DecryptPack(box, (*spub)[:], (*spriv)[:])
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	if !bytes.Equal(data, tdata) {
		t.Error("Error: Decryption fails")
	}
}

func Test_EncryptSelf(t *testing.T) {
	tdata := []byte("This is a test message +++ This is a test message")
	spub, spriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	_, err = EncryptPack(tdata, (*spub)[:], (*spub)[:], (*spriv)[:])
	if err == nil {
		t.Fatalf("May not encrypt to self!")
	}
}
