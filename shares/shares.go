// Package shares implements signed&encrypted share groups
package shares

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"errors"

	"github.com/JonathanLogan/shamironsalt/bytepack"

	"github.com/codahale/sss"
)

const (
	// PublicKeyXField field marker for public key X part
	PublicKeyXField = iota + 1
	// PublicKeyYField field marker for public key Y part
	PublicKeyYField
	// SecretField is the secret when padded
	SecretField
	// ShareField stores a share in a signature
	ShareField
	// RField is the R of a signature
	RField
	// SField is the S of a signature
	SField
	// NonceField is the Nonce for the signature
	NonceField
	// ShareRawField is the raw share in a signature
	ShareRawField
	// PublicKeyField is the public key in a signature
	PublicKeyField
	// CommentField contains the comment
	CommentField
	// SigKeyPublicHashField contains the hash of the ecdsa pubkey
	SigKeyPublicHashField
	// CommentHashField contains the hash of the comment
	CommentHashField
	// SigkeyPublicByteField contains the ecdsa pubkey
	SigkeyPublicByteField
	// SecretHashField contains the hash of the secret
	SecretHashField
	// ThreshholdField contains the threshold
	ThreshholdField
	// MemberSecretField contains the secret that identifies share group members
	MemberSecretField
	// ---------------

	// MessageHeaderField contains either the encrypted or public header
	MessageHeaderField
	// NaclMessageField contains a NaCL encrypted message
	NaclMessageField
	// NumSharesField identifies how many shares are contained in the message
	NumSharesField
	// ShareMessageField contains one or more shares
	ShareMessageField
	// EncodedShare is a single encoded share
	EncodedShare
	// FakeMessageField contains a fake share, if any
	FakeMessageField
	// PaddingField is the padding
	PaddingField
	// SpecificContentField contains per-recipient data
	SpecificContentField
	// CommonContentField contains global data
	CommonContentField
	// HMACField contains an HMAC
	HMACField
	// MessageTypeField contains the message type of the message
	MessageTypeField
)

var (
	// ErrConfig is returned when the configuration is wrong
	ErrConfig = errors.New("Shares: Bad config")
	// ErrSecretShort is returned when the secret is too short (<10 bytes)
	ErrSecretShort = errors.New("Shares: Secret is smaller than 10 bytes")
	// ErrSecretLong is returned when the secret is too long (>255-3-3 == 249 bytes)
	ErrSecretLong = errors.New("Shares: Secret is bigger than 248 bytes")
	// ErrCommentShort is returned when the comment is too short (<4 bytes)
	ErrCommentShort = errors.New("Shares: Comment is smaller than 4 bytes")
	// ErrCommentLong is returned when the comment is too long (max 1024 byte)
	ErrCommentLong = errors.New("Shares: Comment is longer than 1024 bytes")
	// ErrThresholdSmall is returned when the threshold is too small (<3)
	ErrThresholdSmall = errors.New("Shares: Threshold is smaller than 3")
	// ErrThresholdBig is returned when the threshold is too big >253
	ErrThresholdBig = errors.New("Shares: Threshold is bigger than 253")
	// ErrThresholdExceed is returned when the Threshold cannot be fullfilled by the shares
	ErrThresholdExceed = errors.New("Shares: Threshold bigger than number of shares")
	// ErrSharesOverThreshold is returned when a member gets >= Threshold shares
	ErrSharesOverThreshold = errors.New("Shares: Member can reveal secret alone, increase Threshold or assign less Shares")
	// ErrTooManyShares is returned when the total number of shares > 254
	ErrTooManyShares = errors.New("Shares: Cannot produce more than 254 shares")
	// ErrTooFewShares is returned if <3 shares are to be generated
	ErrTooFewShares = errors.New("Shares: Need to generate at least 4 shares")
	// ErrDuplicateMember is returned if trying to add the same member twice to the share group
	ErrDuplicateMember = errors.New("Shares: Duplicate member")
	// ErrNegativeShares is returned if trying to add negative shares
	ErrNegativeShares = errors.New("Shares: Negative shares")
	// ErrTooFewMembers is returned if <2 members are in the group
	ErrTooFewMembers = errors.New("Shares: Need at least two members")
	// ErrSignatureDecode is returned if an encoded signature cannot be decoded
	ErrSignatureDecode = errors.New("Shares: Cannot decode signed share")
	// ErrTooFewSharesToRecover is returned if not enough shares are available to recover the secret
	ErrTooFewSharesToRecover = errors.New("Shares: Cannot recover secret, too few shares known")
	// ErrSecretNotRecovered is returned when the secret could not been recovered
	ErrSecretNotRecovered = errors.New("Shares: Secret not recovered")
	// ErrCannotConvert is returned if type conversion fails
	ErrCannotConvert = errors.New("Shares: Cannot convert type")
	// ErrCannotDecode is returned if type decoding fails
	ErrCannotDecode = errors.New("Shares: Cannot decode type")
	// ErrSignatureVerify is returned if signature verification failed
	ErrSignatureVerify = errors.New("Shares: Signature could not be verified")
	// ErrPubkeyNotMatching is returned when a wrong public key is present
	ErrPubkeyNotMatching = errors.New("Shares: Public Key mismatch")
	// ErrNotFound is returned if no matching entry in the list could be found
	ErrNotFound = errors.New("Shares: No entry found")
	// ErrHMAC is returned if the hmac does not verify
	ErrHMAC = errors.New("Shares: HMAC failure")
	// ErrNoFakes is returned if a fake was requested but not available
	ErrNoFakes = errors.New("Shares: No fake available")
	// ErrBadMessageType is returned if trying to parse a message of a different type
	ErrBadMessageType = errors.New("Shares: Unexpected message type")
	// ErrMixedPubKeys is returned if a single share response contains mixed senders
	ErrMixedPubKeys = errors.New("Shares: Mixed public keys")
)

// ShareConfig is the configuration for a single sharing operations
type ShareConfig struct {
	// Defined during New:
	Threshhold       int               // Minimum number of shares required to reconstruct secret
	Secret           []byte            // The secret to be shared
	PaddedSecret     []byte            // The padded secret (to be shared)
	SecretHash       []byte            // Hash of the secret
	SigkeyPrivate    *ecdsa.PrivateKey // Private key for signature
	SigkeyPublic     ecdsa.PublicKey   //  public key
	SigkeyPublicByte []byte            // encoded public key
	SigKeyPublicHash []byte            // Hash of signature public key
	Comment          []byte            // Sharing comment
	CommentHash      []byte            // hash of comment
	MemberSecret     []byte            // secret to verify membership in sharing group
	// Defined by added members:
	ShareCount       int                      // Total number of shares
	FakeCount        int                      // Total number of fakes to create
	MaxShare         int                      // Maximum number of shares one member will get
	MaxShareWithFake int                      // Maximum number of shares including fakes
	MaxMember        [32]byte                 // Public key with the maximum size
	Members          map[[32]byte]ShareMember // Members of the sharing group, index is the pubkey of the member
	Shares           [][]byte                 // The shares of the secret
	Fakes            [][]byte                 // Fake shares
	TotalLen         int                      // Total length of a message, calculated from maximum message on generation
	// Message generation
	MemberMessages        []ShareMemberMessage // The generated member messages
	CommonMessageHeader   *CommonMessageHeader
	EncryptedCommonHeader *EncryptedCommonHeader
}

// ShareMember is a single member of the sharing group
type ShareMember struct {
	PublicKey []byte // Public key of the member
	NumShares int    // Number of shares to give to this member
	HasFake   bool   // Generate a fake share for this member
}

// padSecret padds the secret to be 255 bytes
func padSecret(secret []byte) []byte {
	var ret []byte
	ret, _ = bytepack.Pack(ret, secret, SecretField)
	if len(ret) < 255 {
		pad := make([]byte, 255-len(ret))
		rand.Read(pad)
		ret = append(ret, pad...)
	}
	return ret
}

// New returns a new ShareConfig
func New(Secret, Comment []byte, Threshhold int) (*ShareConfig, error) {
	sc := new(ShareConfig)
	sc.Threshhold = Threshhold
	sc.Secret = Secret
	sc.PaddedSecret = padSecret(Secret)
	SecretHash := sha512.Sum512(sc.PaddedSecret)
	sc.SecretHash = SecretHash[:]
	sc.Comment = Comment
	// Generate CommentHash
	commentHash := sha512.Sum512(Comment)
	sc.CommentHash = commentHash[:]
	// Verify input
	err := sc.VerifyInit()
	if err != nil {
		return nil, err
	}
	// Generate SigKey
	SigkeyPrivate, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sc.SigkeyPrivate = SigkeyPrivate
	// Generate SigKeyPublic
	sc.SigkeyPublic = sc.SigkeyPrivate.PublicKey
	// Generate SigkeyPublicByte
	sc.SigkeyPublicByte, err = bytepack.Pack(sc.SigkeyPublicByte, sc.SigkeyPublic.X.Bytes(), PublicKeyXField)
	if err != nil {
		return nil, err
	}
	sc.SigkeyPublicByte, err = bytepack.Pack(sc.SigkeyPublicByte, sc.SigkeyPublic.Y.Bytes(), PublicKeyYField)
	if err != nil {
		return nil, err
	}
	SigKeyPublicHash := sha512.Sum512(sc.SigkeyPublicByte)
	// Generate SigKeyPublicHash
	sc.SigKeyPublicHash = SigKeyPublicHash[:]
	// Generate MemberSecret
	MemberSecret := make([]byte, 32)
	rand.Read(MemberSecret)
	sc.MemberSecret = MemberSecret[:]
	sc.Members = make(map[[32]byte]ShareMember)
	sc.Shares = make([][]byte, 0, 2)
	sc.Fakes = make([][]byte, 0)
	return sc, nil
}

// VerifyInit verifies the ShareConfig struct for validity
func (sc *ShareConfig) VerifyInit() error {
	if len(sc.Secret) < 10 {
		return ErrSecretShort
	}
	if len(sc.Secret) > 248 {
		return ErrSecretLong
	}
	if len(sc.Comment) < 4 {
		return ErrCommentShort
	}
	if len(sc.Comment) > 1024 {
		return ErrCommentLong
	}
	if sc.Threshhold < 3 {
		return ErrThresholdSmall
	}
	if sc.Threshhold > 253 {
		return ErrThresholdBig
	}
	return nil
}

// Verify verifies the ShareConfig struct and members for validity
func (sc *ShareConfig) Verify() error {
	err := sc.VerifyInit()
	if err != nil {
		return err
	}
	if sc.Threshhold > sc.ShareCount {
		return ErrThresholdExceed
	}
	if sc.Threshhold <= sc.MaxShare {
		return ErrSharesOverThreshold
	}
	if sc.ShareCount > 254 {
		return ErrTooManyShares
	}
	if sc.ShareCount < 3 {
		return ErrTooFewShares
	}
	if len(sc.Members) < 2 {
		return ErrTooFewMembers
	}
	sc.TotalLen = 1
	return nil
}

// AddMember adds a new member to the group. Updates ShareConfig
func (sc *ShareConfig) AddMember(PublicKey []byte, NumShares int, HasFake bool) error {
	// If Shares == 0 and AddFake ==true, only add a fake
	var pci [32]byte
	copy(pci[:], PublicKey[0:32])
	if _, exists := sc.Members[pci]; exists {
		return ErrDuplicateMember
	}
	if NumShares < 0 {
		return ErrNegativeShares
	}
	if NumShares >= sc.Threshhold {
		return ErrSharesOverThreshold
	}
	sc.Members[pci] = ShareMember{PublicKey: PublicKey, NumShares: NumShares, HasFake: HasFake}
	totalshares := NumShares
	if HasFake {
		sc.FakeCount++
		totalshares++
	}
	if NumShares > 0 {
		sc.ShareCount = sc.ShareCount + NumShares
	}
	if NumShares > sc.MaxShare {
		sc.MaxShare = NumShares
	}
	if totalshares > sc.MaxShareWithFake {
		sc.MaxShareWithFake = totalshares
		sc.MaxMember = pci
	}
	return nil
}

// GenerateShares generates all shares
func (sc *ShareConfig) generateShares() error {
	// Split the given secret into N shares of which K are required to recover the
	// secret. Returns a map of share IDs (1-255) to shares.
	//func Split(n, k byte, secret []byte) (map[byte][]byte, error)
	shares, err := sss.Split(byte(sc.ShareCount), byte(sc.Threshhold), sc.PaddedSecret)
	if err != nil {
		return err
	}
	for k, v := range shares {
		share := make([]byte, 1, len(v)+1)
		share[0] = k
		share = append(share, v...)
		sc.Shares = append(sc.Shares, share)
	}
	return nil
}

// GenerateFakes generates all fakes
func (sc *ShareConfig) generateFakes() {
	for i := 0; i < sc.FakeCount; i++ {
		fake := make([]byte, len(sc.PaddedSecret))
		rand.Read(fake)
		sc.Fakes = append(sc.Fakes, fake)
	}
}
