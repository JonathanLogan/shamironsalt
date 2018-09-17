// Package keymgt implements trivial binary encoding for nacl public/private keys
package keymgt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/JonathanLogan/shamironsalt/bytepack"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

var (
	hasNoPassword = []byte{byte(0)}
	hasPassword   = []byte{byte(1)}
	// ErrMissingField is returned when fields are missing
	ErrMissingField = errors.New("keymgt: missing fields")
	// ErrMissingPassword is returned if no needed password was given
	ErrMissingPassword = errors.New("keymgt: no password when one was needed")
	// ErrWrongPassword is returned if the private key cannot be decrypted
	ErrWrongPassword = errors.New("keymgt: wrong password")
)

const (
	// SaltField is the salt used for encryption
	SaltField = iota + 1
	// PasswordFlagField shows if a password is set
	PasswordFlagField
	// MyPublicKey is my public key
	MyPublicKey
	// CryptPublicKey is the public key for encryption
	CryptPublicKey
	// Nonce is the nonce for NaCL encryption
	Nonce
	// NaCLBox is the encrypted data
	NaCLBox
	// PrivateKey is the private key
	PrivateKey
	// ExtraData is additional data added to the secret part
	ExtraData
)

// Create keypair
// Load keypair
//GenKeyPair (optional encrypt privkey)
//	PrivKey2 = Hash(Password,PWSalt)
//	PWSalt,HasPassword,Pubkey1,Pubkey2,Nonce,NaCL(privkey1)

func pwHash(pwsalt, password []byte) *[32]byte {
	t := make([]byte, len(password)+32)
	t = append(t, pwsalt...)
	t = append(t, password...)
	x := sha256.Sum256(t)
	return &x
}

// SaveKey stores a keypair, optionally encrypted with a password
func SaveKey(pubkey, privkey, password, extradata []byte) (keyfile, mpubkey, mprivkey []byte, err error) {
	var hasPass, out, secretdata []byte
	spriv := new([32]byte)
	spub := new([32]byte)

	mpubkey = pubkey
	mprivkey = privkey
	pwsalt := new([32]byte)
	_, err = io.ReadFull(rand.Reader, pwsalt[:])
	if err != nil {
		return
	}
	if password == nil || len(password) == 0 {
		hasPass = hasNoPassword
		spriv = pwsalt
	} else {
		hasPass = hasPassword
		spriv = pwHash(pwsalt[:], password)
	}
	curve25519.ScalarBaseMult(spub, spriv)
	nonce := new([24]byte)
	rand.Read(nonce[:])
	secretdata, _ = bytepack.Pack(secretdata, privkey, PrivateKey)
	if extradata != nil && len(extradata) > 0 {
		secretdata, _ = bytepack.Pack(secretdata, extradata, ExtraData)
	}
	tpubkey := new([32]byte)
	copy(tpubkey[:], pubkey)
	out = box.Seal(out, secretdata, nonce, tpubkey, spriv)
	keyfile, _ = bytepack.Pack(keyfile, pwsalt[:], SaltField)
	keyfile, _ = bytepack.Pack(keyfile, hasPass[:], PasswordFlagField)
	keyfile, _ = bytepack.Pack(keyfile, pubkey, MyPublicKey)
	keyfile, _ = bytepack.Pack(keyfile, spub[:], CryptPublicKey)
	keyfile, _ = bytepack.Pack(keyfile, nonce[:], Nonce)
	keyfile, _ = bytepack.Pack(keyfile, out[:], NaCLBox)
	return
}

// GenerateKey returns a keyfile, optionally encrypted by password. Extradata can be appended
func GenerateKey(password, extradata []byte) (keyfile, mpubkey, mprivkey []byte, err error) {
	pubkey, privkey, err := box.GenerateKey(rand.Reader) // Keypair
	if err != nil {
		return
	}
	return SaveKey(pubkey[:], privkey[:], password, extradata)
}

// LoadKey returns public and private keys from keyfile, decrypts with password if necessary
func LoadKey(keyfile, password []byte) (pubkey, privkey, extradata []byte, err error) {
	var fields map[int][]byte
	var out []byte
	nonce := new([24]byte)
	spriv := new([32]byte)
	rpub := new([32]byte)
	fields, err = bytepack.UnpackAll(keyfile)
	if err != nil {
		return
	}
	if !bytepack.VerifyFields(fields, []int{SaltField, PasswordFlagField, MyPublicKey, CryptPublicKey, Nonce, NaCLBox}) {
		err = ErrMissingField
		return
	}
	if bytes.Equal(fields[PasswordFlagField], hasNoPassword) {
		copy(spriv[:], fields[SaltField])
	} else if password == nil || len(password) == 0 {
		err = ErrMissingPassword
		return
	} else {
		spriv = pwHash(fields[SaltField], password)
	}
	copy(nonce[:], fields[Nonce])
	copy(rpub[:], fields[MyPublicKey])
	pubkey = fields[MyPublicKey]
	xdata, ok := box.Open(out, fields[NaCLBox], nonce, rpub, spriv)
	if !ok {
		err = ErrWrongPassword
		return
	}
	secretfields, err := bytepack.UnpackAll(xdata)
	if err != nil {
		return
	}
	if !bytepack.VerifyFields(secretfields, []int{PrivateKey}) {
		err = ErrMissingField
		return
	}
	privkey = secretfields[PrivateKey]
	if bytepack.VerifyFields(secretfields, []int{ExtraData}) {
		extradata = secretfields[ExtraData]
		return
	}
	extradata = nil
	return
}
