// Package naclwrapper implements easy to use NaCL encryption/decryption wrappers including binary packing/unpacking
package naclwrapper

import (
	"bytes"
	"crypto/rand"
	"errors"

	"github.com/JonathanLogan/shamironsalt/bytepack"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	// RecipientPublicKey is the field marker for the recipient's public key
	RecipientPublicKey = iota + 1
	// SenderPublicKey is the field marker for the senders's public key
	SenderPublicKey
	// Nonce is the field marker for the NaCL nonce
	Nonce
	// NaCLBox is the field marker for the NaCL encrypted message
	NaCLBox
)

var (
	// ErrMissingKey is returned when neither sender nor recipient keys are given
	ErrMissingKey = errors.New("nacl wrapper: either sender or recipient key must be given")
	// ErrMissingPrivate is returned when no private key has been given
	ErrMissingPrivate = errors.New("nacl wrapper: no private key given")
	// ErrDataShort is returned if the packet could not containe a message
	ErrDataShort = errors.New("nacl wrapper: data short")
	// ErrNotRecipient is returned if the packet is not addressed to the private key
	ErrNotRecipient = errors.New("nacl wrapper: not addressed to recipient")
	// ErrDecryptFailed is returned if the packet could not been decrypted
	ErrDecryptFailed = errors.New("nacl wrapper: could not decrypt")
	// ErrFieldMissing is returned if the packed message is missing a field
	ErrFieldMissing = errors.New("nacl wrapper: missing field")
	// ErrEncryptToSelf is returned if both keys are the same
	ErrEncryptToSelf = errors.New("nacl wrapper: will not encrypt to self")
)

// NaCLKeyPair contains a NaCL key
type NaCLKeyPair struct {
	PublicKey  []byte // Public key
	PrivateKey []byte // Private key
}

func keysPrepare(rpubkey, spubkey, sprivkey []byte) (*[32]byte, *[32]byte, *[32]byte, error) {
	spriv := new([32]byte)
	spub := new([32]byte)
	rpub := new([32]byte)
	var err error
	if sprivkey == nil {
		spub, spriv, err = box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
	} else if spubkey == nil {
		copy(spriv[:], sprivkey[:32])
		curve25519.ScalarBaseMult(spub, spriv)
	} else {
		copy(spriv[:], sprivkey[:32])
		copy(spub[:], spubkey[:32])
	}
	if rpubkey == nil {
		rpub, _, err = box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
	} else {
		copy(rpub[:], rpubkey[:32])
	}
	return rpub, spub, spriv, nil
}

// Encrypt data with given keys. If any of the keys is not given it will be generated. At least
// one of rpubkey or sprivkey MUST be present (otherwise it would be an encryption that cannot
// be decrypted anymore)
func Encrypt(data []byte, rpubkey, spubkey, sprivkey []byte) ([]byte, error) {
	var out, output []byte
	if rpubkey == nil && sprivkey == nil {
		return nil, ErrMissingKey
	}
	rpub, spub, spriv, err := keysPrepare(rpubkey, spubkey, sprivkey)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(rpub[:], spub[:]) {
		return nil, ErrEncryptToSelf
	}
	nonce := new([24]byte)
	rand.Read(nonce[:])
	out = box.Seal(out, data, nonce, rpub, spriv)
	output = append(output, rpub[:]...)
	output = append(output, spub[:]...)
	output = append(output, nonce[:]...)
	output = append(output, out[:]...)
	return output, nil
}

// Decrypt data with rprivkey. Rpubkey can be nil, it will be automatically generated
func Decrypt(data []byte, rpubkey, rprivkey []byte) ([]byte, error) {
	var out []byte
	nonce := new([24]byte)
	rpub := new([32]byte)
	rpriv := new([32]byte)
	spub := new([32]byte)
	if rprivkey == nil {
		return nil, ErrMissingPrivate
	}
	copy(rpriv[:], rprivkey)
	if len(data) < (32 + 32 + 24 + box.Overhead) {
		return nil, ErrDataShort
	}
	if rpubkey == nil {
		curve25519.ScalarBaseMult(spub, rpriv)
	} else {
		copy(spub[:], rpubkey)
	}
	if bytes.Equal((*spub)[:], data[0:32]) {
		copy(rpub[:], data[32:64])
	} else if bytes.Equal((*spub)[:], data[32:64]) {
		copy(rpub[:], data[0:32])
	} else {
		return nil, ErrNotRecipient
	}
	copy(nonce[:], data[64:88])
	out, ok := box.Open(out, data[88:], nonce, rpub, rpriv)
	if !ok {
		return nil, ErrDecryptFailed
	}
	return out, nil
}

// EncryptPack creates an encrypted bytepack
func EncryptPack(data []byte, rpubkey, spubkey, sprivkey []byte) ([]byte, error) {
	var out []byte
	if rpubkey == nil && sprivkey == nil {
		return nil, ErrMissingKey
	}
	rpub, spub, spriv, err := keysPrepare(rpubkey, spubkey, sprivkey)
	if err != nil {
		return nil, err
	}
	nonce := new([24]byte)
	rand.Read(nonce[:])
	if bytes.Equal(rpub[:], spub[:]) {
		return nil, ErrEncryptToSelf
	}
	out = box.Seal(out, data, nonce, rpub, spriv)
	x, _ := bytepack.Pack(nil, rpub[:], RecipientPublicKey)
	x, _ = bytepack.Pack(x, spub[:], SenderPublicKey)
	x, _ = bytepack.Pack(x, nonce[:], Nonce)
	x, _ = bytepack.Pack(x, out[:], NaCLBox)
	return x, nil
}

// DecryptPack decrypts an encrypted bytepack
func DecryptPack(data []byte, rpubkey, rprivkey []byte) ([]byte, error) {
	var out []byte
	nonce := new([24]byte)
	rpub := new([32]byte)
	rpriv := new([32]byte)
	spub := new([32]byte)
	if rprivkey == nil {
		return nil, ErrMissingPrivate
	}
	copy(rpriv[:], rprivkey)
	if len(data) < (32 + 32 + 24 + box.Overhead) {
		return nil, ErrDataShort
	}
	if rpubkey == nil {
		curve25519.ScalarBaseMult(spub, rpriv)
	} else {
		copy(spub[:], rpubkey)
	}
	fields, err := bytepack.UnpackAll(data)
	if err != nil {
		return nil, err
	}
	if !bytepack.VerifyFields(fields, []int{RecipientPublicKey, SenderPublicKey, Nonce, NaCLBox}) {
		return nil, ErrFieldMissing
	}
	if bytes.Equal((*spub)[:], fields[RecipientPublicKey]) {
		copy(rpub[:], fields[SenderPublicKey])
	} else if bytes.Equal((*spub)[:], fields[SenderPublicKey]) {
		copy(rpub[:], fields[RecipientPublicKey])
	} else {
		return nil, ErrNotRecipient
	}
	copy(nonce[:], fields[Nonce])
	out, ok := box.Open(out, fields[NaCLBox], nonce, rpub, rpriv)
	if !ok {
		return nil, ErrDecryptFailed
	}
	return out, nil
}
