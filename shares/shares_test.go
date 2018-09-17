package shares

import (
	"testing"
)

func Test_padSecret(t *testing.T) {
	s := padSecret(make([]byte, 25))
	if len(s) != 255 {
		t.Error("Secret padding failed for 25")
	}
	s = padSecret(make([]byte, 255))
	if len(s) == 255 {
		t.Error("Secret padding failed for 255")
	}
	s = padSecret(make([]byte, 249))
	if len(s) != 255 {
		t.Error("Secret padding failed for 249")
	}
}

func Test_New(t *testing.T) {
	sconf, err := New([]byte("I am a big bad secret"), []byte("Do not reveal my secret"), 10)
	if err != nil {
		t.Fatalf("Configuration failed: %s", err)
	}
	_ = sconf
}

func Test_Add(t *testing.T) {
	sconf, err := New([]byte("I am a big bad secret"), []byte("Do not reveal my secret"), 4)
	if err != nil {
		t.Fatalf("Configuration failed: %s", err)
	}
	err = sconf.AddMember([]byte("12345678901234567890123456789012"), 3, true)
	if err != nil {
		t.Errorf("Adding member failed: %s", err)
	}
	err = sconf.AddMember([]byte("22345678901234567890123456789012"), 3, true)
	err = sconf.Verify()
	if err != nil {
		t.Errorf("Adding member verification failed: %s", err)
	}
}

func Test_Generate(t *testing.T) {
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
	if len(sconf.Fakes[0]) != 255 {
		t.Errorf("Fake wrong size")
	}
	if len(sconf.Fakes) != sconf.FakeCount {
		t.Errorf("Fake count wrong")
	}
	sconf.generateShares()
	if len(sconf.Shares) != sconf.ShareCount {
		t.Errorf("Share count wrong")
	}
	if len(sconf.Shares[0]) != len(sconf.PaddedSecret)+1 {
		t.Errorf("Share length wrong")
	}
}
