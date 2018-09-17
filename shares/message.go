package shares

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"

	"github.com/JonathanLogan/shamironsalt/bytepack"
	"github.com/JonathanLogan/shamironsalt/naclwrapper"

	"github.com/codahale/sss"
)

// MessageBlock defines all fields needed in message generation
type MessageBlock struct {
	// Message generation
	SigPublicKey          *ecdsa.PublicKey         // Public key for signature verification
	EncryptKey            *naclwrapper.NaCLKeyPair // Keypair for NaCL-Encryption
	MemberMessages        []ShareMemberMessage     // The generated member messages
	KnownMembers          map[[32]byte]bool        // known members
	CommonMessageHeader   *CommonMessageHeader
	EncryptedCommonHeader *EncryptedCommonHeader
}

// SignedShare is a signed share
type SignedShare struct {
	Content   []byte // Share|Pubkey, bytepack encoded
	PublicKey []byte // Member public key
	Share     []byte // Share
	R         []byte // R of Signature
	S         []byte // S of Signature
	Encoded   []byte // The encoded SignShare
}

// ShareMemberMessage is a single message to be sent (specific parts only)
type ShareMemberMessage struct {
	PublicKey []byte        // Public key of the member
	Shares    []SignedShare // Shares. Share|nonce|signature
	Fake      *SignedShare  // Fake, if any. Fake|nonce|signature
	Padding   []byte
}

// CommonMessageHeader is the public header of a message
type CommonMessageHeader struct {
	Comment       []byte // The comment
	SigPubKeyHash []byte // The hash of the signature public key
	Encoded       []byte // Header encoded
}

// EncryptedCommonHeader is the encrypted header that is common to all messages
type EncryptedCommonHeader struct {
	MemberSecret     []byte // secret to verify membership in sharing group
	CommentHash      []byte // hash of comment
	SigkeyPublicByte []byte // encoded public key
	SecretHash       []byte // Hash of the secret
	Threshhold       byte   // Minimum number of shares required to reconstruct secret
	Encoded          []byte // The EncryptedCommonHeader bytepack encoded
}

type ecdsaPublicKeyWrap struct {
	pubkey *ecdsa.PublicKey
}

// parseSignedShare parses an encoded, signed share
func parseSignedShare(signedShare []byte) (*SignedShare, error) {
	fields, err := bytepack.UnpackAll(signedShare)
	if err != nil {
		return nil, err
	}
	if ok := bytepack.VerifyFields(fields, []int{PublicKeyField, ShareRawField, RField, SField}); !ok {
		return nil, ErrSignatureDecode
	}
	decodedShare := new(SignedShare)
	decodedShare.R = fields[RField]
	decodedShare.S = fields[SField]
	decodedShare.Encoded = signedShare
	decodedShare.PublicKey = fields[PublicKeyField]
	decodedShare.Share = fields[ShareRawField]
	decodedShare.Content, _ = bytepack.Pack(decodedShare.Content, decodedShare.PublicKey, PublicKeyField)
	decodedShare.Content, _ = bytepack.Pack(decodedShare.Content, decodedShare.Share, ShareRawField)
	return decodedShare, nil
}

func (sc *ShareConfig) verifyShare(signedShare SignedShare) (bool, error) {
	var k ecdsaPublicKeyWrap
	k.pubkey = &sc.SigkeyPublic
	return k.verifyShare(signedShare)
}

func (messages *MessageBlock) verifyShare(signedShare SignedShare) (bool, error) {
	var k ecdsaPublicKeyWrap
	k.pubkey = messages.SigPublicKey
	return k.verifyShare(signedShare)
}

// verifyShare verifies a signed share
func (pubkey *ecdsaPublicKeyWrap) verifyShare(signedShare SignedShare) (bool, error) {
	var err error
	if len(signedShare.Content) == 0 {
		signedShare.Content, _ = bytepack.Pack(signedShare.Content, signedShare.PublicKey, PublicKeyField)
		signedShare.Content, err = bytepack.Pack(signedShare.Content, signedShare.Share, ShareRawField)
		if err != nil {
			return false, err
		}
	}
	hash := sha256.Sum256(signedShare.Content)
	r := new(big.Int)
	s := new(big.Int)
	r = r.SetBytes(signedShare.R)
	s = s.SetBytes(signedShare.S)
	return ecdsa.Verify(pubkey.pubkey, hash[:], r, s), nil
}

// signShare signs a share
func (sc *ShareConfig) signShare(publicKey, share []byte) (*SignedShare, error) {
	var signedShare SignedShare
	var err error
	signedShare.PublicKey = publicKey
	signedShare.Share = share
	signedShare.Content, _ = bytepack.Pack(signedShare.Content, signedShare.PublicKey, PublicKeyField)
	signedShare.Content, err = bytepack.Pack(signedShare.Content, signedShare.Share, ShareRawField)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(signedShare.Content)
	r, s, err := ecdsa.Sign(rand.Reader, sc.SigkeyPrivate, hash[:])
	if err != nil {
		return nil, err
	}
	signedShare.R = r.Bytes()
	signedShare.S = s.Bytes()
	signedShare.Encoded = signedShare.Content
	signedShare.Encoded, _ = bytepack.Pack(signedShare.Encoded, signedShare.R, RField)
	signedShare.Encoded, _ = bytepack.Pack(signedShare.Encoded, signedShare.S, SField)
	return &signedShare, nil
}

// generateMessage generates a single message for a key
func (sc *ShareConfig) generateMessage(pubkey [32]byte) (*ShareMemberMessage, error) {
	var fake []byte
	var err error
	var siglen, parts int
	var smm ShareMemberMessage
	mc := sc.Members[pubkey]
	smm.PublicKey = mc.PublicKey
	if mc.HasFake {
		fake, sc.Fakes = sc.Fakes[len(sc.Fakes)-1], sc.Fakes[:len(sc.Fakes)-1]
		smm.Fake, err = sc.signShare(mc.PublicKey, fake)
		if err != nil {
			return nil, err
		}
		siglen = len(smm.Fake.Encoded)
		parts++
	} else {
		smm.Fake = nil
	}
	for i := 0; i < mc.NumShares; i++ {
		var share []byte
		share, sc.Shares = sc.Shares[len(sc.Shares)-1], sc.Shares[:len(sc.Shares)-1]
		signedShare, err := sc.signShare(mc.PublicKey, share)
		if err != nil {
			return nil, err
		}
		if siglen == 0 {
			siglen = len(signedShare.Encoded)
		}
		smm.Shares = append(smm.Shares, *signedShare)
		parts++
	}
	if sc.TotalLen == 1 {
		sc.TotalLen = siglen*sc.MaxShareWithFake + 1 // update totallength
		smm.Padding = make([]byte, 1)
	} else {
		mylength := siglen * parts
		padlength := sc.TotalLen - mylength
		if padlength <= 1 {
			padlength = 1
		}
		smm.Padding = make([]byte, padlength)
	}
	rand.Read(smm.Padding)
	return &smm, nil
}

// GenerateMessages generates the messages to the members
func (sc *ShareConfig) GenerateMessages() (*MessageBlock, error) {
	var messages MessageBlock
	err := sc.Verify()
	if err != nil {
		return nil, err
	}
	sc.generateFakes()
	err = sc.generateShares()
	if err != nil {
		return nil, err
	}
	membermessage, err := sc.generateMessage(sc.MaxMember)
	if err != nil {
		return nil, err
	}
	messages.MemberMessages = append(messages.MemberMessages, *membermessage)
	for k := range sc.Members {
		if !bytes.Equal(k[:], sc.MaxMember[:]) {
			membermessage, err := sc.generateMessage(k)
			if err != nil {
				return nil, err
			}
			messages.MemberMessages = append(messages.MemberMessages, *membermessage)
		}
	}
	messages.CommonMessageHeader = new(CommonMessageHeader)
	messages.CommonMessageHeader.Comment = sc.Comment
	messages.CommonMessageHeader.SigPubKeyHash = sc.SigKeyPublicHash

	messages.CommonMessageHeader.Encoded, _ = bytepack.Pack(messages.CommonMessageHeader.Encoded, messages.CommonMessageHeader.Comment, CommentField)
	messages.CommonMessageHeader.Encoded, _ = bytepack.Pack(messages.CommonMessageHeader.Encoded, messages.CommonMessageHeader.SigPubKeyHash, SigKeyPublicHashField)

	messages.EncryptedCommonHeader = new(EncryptedCommonHeader)
	messages.EncryptedCommonHeader.MemberSecret = sc.MemberSecret
	messages.EncryptedCommonHeader.CommentHash = sc.CommentHash
	messages.EncryptedCommonHeader.SigkeyPublicByte = sc.SigkeyPublicByte
	messages.EncryptedCommonHeader.SecretHash = sc.SecretHash
	messages.EncryptedCommonHeader.Threshhold = byte(sc.Threshhold)

	messages.EncryptedCommonHeader.Encoded, _ = bytepack.Pack(messages.EncryptedCommonHeader.Encoded, messages.EncryptedCommonHeader.MemberSecret, MemberSecretField)
	messages.EncryptedCommonHeader.Encoded, _ = bytepack.Pack(messages.EncryptedCommonHeader.Encoded, messages.EncryptedCommonHeader.CommentHash, CommentHashField)
	messages.EncryptedCommonHeader.Encoded, _ = bytepack.Pack(messages.EncryptedCommonHeader.Encoded, messages.EncryptedCommonHeader.SigkeyPublicByte, SigkeyPublicByteField)
	messages.EncryptedCommonHeader.Encoded, _ = bytepack.Pack(messages.EncryptedCommonHeader.Encoded, messages.EncryptedCommonHeader.SecretHash, SecretHashField)
	tTreshHold := make([]byte, 1)
	tTreshHold[0] = messages.EncryptedCommonHeader.Threshhold
	messages.EncryptedCommonHeader.Encoded, _ = bytepack.Pack(messages.EncryptedCommonHeader.Encoded, tTreshHold, ThreshholdField)
	messages.SigPublicKey = &sc.SigkeyPublic
	return &messages, nil
}

// Combine combines the shares and returns the secret
func (messages *MessageBlock) Combine() ([]byte, error) {
	shares := make(map[byte][]byte)
	for _, member := range messages.MemberMessages {
		for _, mshare := range member.Shares {
			shares[mshare.Share[0]] = mshare.Share[1:]
		}
	}
	if len(shares) < int(messages.EncryptedCommonHeader.Threshhold) {
		return nil, ErrTooFewSharesToRecover
	}
	secret := sss.Combine(shares)
	SecretHash := sha512.Sum512(secret)
	if !bytes.Equal(SecretHash[:], messages.EncryptedCommonHeader.SecretHash) {
		return nil, ErrSecretNotRecovered
	}
	secretDecoded, _, marker, err := bytepack.Unpack(secret)
	if err != nil {
		return nil, err
	}
	if marker != SecretField {
		return nil, ErrSecretNotRecovered
	}
	return secretDecoded, nil
}

// NewMessageBlock initializes the data for a new combine run
func NewMessageBlock(Threshhold byte, SecretHash, SigPubKey []byte) (*MessageBlock, error) {
	var messages MessageBlock
	messages.EncryptedCommonHeader = new(EncryptedCommonHeader)
	messages.EncryptedCommonHeader.Threshhold = Threshhold
	messages.EncryptedCommonHeader.SecretHash = SecretHash

	fields, err := bytepack.UnpackAll(SigPubKey)
	if err != nil {
		return nil, err
	}
	if !bytepack.VerifyFields(fields, []int{PublicKeyXField, PublicKeyYField}) {
		return nil, ErrCannotDecode
	}
	messages.SigPublicKey = &ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X:     new(big.Int),
		Y:     new(big.Int),
	}
	messages.SigPublicKey.X = messages.SigPublicKey.X.SetBytes(fields[PublicKeyXField])
	messages.SigPublicKey.Y = messages.SigPublicKey.Y.SetBytes(fields[PublicKeyYField])
	messages.CommonMessageHeader = new(CommonMessageHeader)
	messages.KnownMembers = make(map[[32]byte]bool)
	return &messages, nil
}

// LoadShare loads a share into the MessageBlock, verifying the signature
func (messages *MessageBlock) LoadShare(share []byte, duplicateCheck bool) error {
	var smm ShareMemberMessage
	var pubKey [32]byte
	decoded, err := parseSignedShare(share)
	if err != nil {
		return err
	}
	if len(decoded.PublicKey) < 32 {
		return ErrCannotDecode
	}
	ok, err := messages.verifyShare(*decoded)
	if !ok {
		return ErrSignatureVerify
	}
	if duplicateCheck {
		copy(pubKey[:], decoded.PublicKey[0:32])
		if _, exists := messages.KnownMembers[pubKey]; exists {
			return ErrDuplicateMember
		}
		messages.KnownMembers[pubKey] = true
	}
	smm.PublicKey = decoded.PublicKey
	smm.Shares = append(smm.Shares, *decoded)
	messages.MemberMessages = append(messages.MemberMessages, smm)
	return nil
}

// LoadShares loads a share into the MessageBlock, verifying the signature
func (messages *MessageBlock) LoadShares(shares [][]byte, duplicateCheck bool) ([]byte, error) {
	var smm ShareMemberMessage
	var pubKey [32]byte
	decoded, err := parseSignedShare(shares[0])
	if err != nil {
		return nil, err
	}
	if len(decoded.PublicKey) < 32 {
		return nil, ErrCannotDecode
	}
	ok, err := messages.verifyShare(*decoded)
	if !ok {
		return nil, ErrSignatureVerify
	}

	if duplicateCheck {
		copy(pubKey[:], decoded.PublicKey[0:32])
		if messages.KnownMembers == nil {
			messages.KnownMembers = make(map[[32]byte]bool)
		}
		if _, exists := messages.KnownMembers[pubKey]; exists {
			return nil, ErrDuplicateMember
		}
		messages.KnownMembers[pubKey] = true
	}

	smm.PublicKey = decoded.PublicKey
	for _, share := range shares {
		decoded, err := parseSignedShare(share)
		if err != nil {
			return nil, err
		}
		if len(decoded.PublicKey) < 32 {
			return nil, ErrCannotDecode
		}
		if !bytes.Equal(pubKey[:], decoded.PublicKey[0:32]) {
			return nil, ErrMixedPubKeys
		}
		ok, err := messages.verifyShare(*decoded)
		if !ok {
			return nil, ErrSignatureVerify
		}
		smm.Shares = append(smm.Shares, *decoded)
	}

	messages.MemberMessages = append(messages.MemberMessages, smm)
	return decoded.PublicKey, nil
}
