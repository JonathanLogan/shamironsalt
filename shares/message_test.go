package shares

import (
	"bytes"
	"fmt"
	"testing"
)

func Test_SplitCombine(t *testing.T) {
	sconf, err := New([]byte("I am a big bad secret"), []byte("Do not reveal my secret"), 4)
	if err != nil {
		t.Fatalf("Configuration failed: %s", err)
	}
	err = sconf.AddMember([]byte("12345678901234567890123456789012"), 3, true)
	if err != nil {
		t.Errorf("Adding member failed: %s", err)
	}
	sconf.AddMember([]byte("22345678901234567890123456789012"), 3, false)
	sconf.Verify()
	sconf.generateFakes()
	sconf.generateShares()

	messages, err := sconf.GenerateMessages()
	if err != nil {
		t.Errorf("Message generation failed: %s", err)
	}
	secret, err := messages.Combine()
	if err != nil {
		t.Errorf("Message combine failed: %s", err)
	}
	if !bytes.Equal([]byte("I am a big bad secret"), secret) {
		t.Error("Message did not recover secret")
	}
	fmt.Print("")
}

func Test_Sign(t *testing.T) {
	sconf, err := New([]byte("I am a big bad secret"), []byte("Do not reveal my secret"), 4)
	if err != nil {
		t.Fatalf("Configuration failed: %s", err)
	}
	//signShare(publicKey, share []byte) (*SignedShare, error)
	signedShare, err := sconf.signShare([]byte("PublicKey"), []byte("Share"))
	if err != nil {
		t.Errorf("Signature failed: %s", err)
	}
	ok, err := sconf.verifyShare(*signedShare)
	if !ok {
		t.Error("Signature verification failed")
	}
	signedShare2, err := parseSignedShare(signedShare.Encoded)
	if err != nil {
		t.Errorf("Signature decoding failed: %s", err)
	}
	ok, err = sconf.verifyShare(*signedShare2)
	if !ok {
		t.Error("Signature verification failed after decoding")
	}
	signedShare.R[2] = byte(0)
	signedShare.R[3] = byte(0)
	ok, err = sconf.verifyShare(*signedShare)
	if ok {
		t.Error("Signature verification MUST fail")
	}
	_ = signedShare
}

func Test_MessageInit(t *testing.T) {
	sconf, err := New([]byte("I am a big bad secret"), []byte("Do not reveal my secret"), 4)
	if err != nil {
		t.Fatalf("Configuration failed: %s", err)
	}
	err = sconf.AddMember([]byte("12345678901234567890123456789012"), 3, true)
	if err != nil {
		t.Errorf("Adding member failed: %s", err)
	}
	sconf.AddMember([]byte("22345678901234567890123456789012"), 3, false)
	messages, err := sconf.GenerateMessages()
	if err != nil {
		t.Errorf("Message generation failed: %s", err)
	}
	mblock, err := NewMessageBlock(messages.EncryptedCommonHeader.Threshhold, messages.EncryptedCommonHeader.SecretHash, messages.EncryptedCommonHeader.SigkeyPublicByte)
	if err != nil {
		t.Errorf("Messageblock init failed: %s", err)
	}
	_ = mblock
}

func Test_LoadCombine(t *testing.T) {
	sconf, err := New([]byte("I am a big bad secret"), []byte("Do not reveal my secret"), 4)
	if err != nil {
		t.Fatalf("Configuration failed: %s", err)
	}
	err = sconf.AddMember([]byte("12345678901234567890123456789012"), 3, true)
	if err != nil {
		t.Errorf("Adding member failed: %s", err)
	}
	sconf.AddMember([]byte("22345678901234567890123456789012"), 3, false)
	messages, err := sconf.GenerateMessages()
	if err != nil {
		t.Errorf("Message generation failed: %s", err)
	}
	mblock, err := NewMessageBlock(messages.EncryptedCommonHeader.Threshhold, messages.EncryptedCommonHeader.SecretHash, messages.EncryptedCommonHeader.SigkeyPublicByte)
	if err != nil {
		t.Errorf("Messageblock init failed: %s", err)
	}
	for _, v := range messages.MemberMessages {
		for _, s := range v.Shares {
			err := mblock.LoadShare(s.Encoded, false)
			if err != nil {
				t.Errorf("Could not load share: %s", err)
			}
		}
	}
	secret, err := mblock.Combine()
	if err != nil {
		t.Errorf("Combine failed: %s", err)
	}
	if !bytes.Equal([]byte("I am a big bad secret"), secret) {
		t.Error("Message did not recover secret")
	}
}
