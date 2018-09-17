package shares

import (
	"crypto/rand"

	"github.com/JonathanLogan/shamironsalt/bytepack"

	//"shamironsalt/keymgt"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strconv"
	"time"

	"github.com/JonathanLogan/shamironsalt/naclwrapper"

	"golang.org/x/crypto/nacl/box"
)

const (
	// ShareMessageType signals a message containing shares after splitting
	ShareMessageType = iota + 1
	// ShareRequestType signals a message reqesting shares
	ShareRequestType
	// ShareResponseType signals a message containing shares for combination
	ShareResponseType
)

// ShareRequest is a received share request message
type ShareRequest struct {
	content         []byte // The content without mac
	nonce           []byte
	mac             []byte
	sigPubkey       []byte // Identifies the secret share group
	senderPubkey    []byte // Reply to this
	recipientPubkey []byte // This is me
}

// EncodeShareMessage generates a single encoded share message
func (messages *MessageBlock) encodeShareMessage(smm ShareMemberMessage) ([]byte, error) {
	var p, q, enc, hdr, hdrbase []byte
	var err error
	//p, _ = bytepack.Pack(p, messages.CommonMessageHeader.Encoded, MessageHeaderField)
	NumShares := make([]byte, 1)
	NumShares[0] = byte(len(smm.Shares))
	p, _ = bytepack.Pack(p, NumShares, NumSharesField)
	for _, s := range smm.Shares {
		q, _ = bytepack.Pack(q, s.Encoded, EncodedShare)
	}
	p, _ = bytepack.Pack(p, q, ShareMessageField)
	if smm.Fake != nil {
		p, _ = bytepack.Pack(p, smm.Fake.Encoded, FakeMessageField)
	}
	p, _ = bytepack.Pack(p, smm.Padding, PaddingField)
	messageType := make([]byte, 1)
	messageType[0] = ShareMessageType
	enc, _ = bytepack.Pack(enc, messageType[:], MessageTypeField)
	enc, _ = bytepack.Pack(enc, messages.EncryptedCommonHeader.Encoded, CommonContentField)
	enc, _ = bytepack.Pack(enc, p, SpecificContentField)
	if messages.EncryptKey == nil {
		messages.EncryptKey = new(naclwrapper.NaCLKeyPair)
		pub, priv, err := box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		messages.EncryptKey.PublicKey = pub[:]
		messages.EncryptKey.PrivateKey = priv[:]
	}
	encrypted, err := naclwrapper.EncryptPack(enc, smm.PublicKey, messages.EncryptKey.PublicKey, messages.EncryptKey.PrivateKey)
	if err != nil {
		return nil, err
	}
	// Hex
	hdrbase, _ = bytepack.Pack(hdrbase, messages.CommonMessageHeader.Encoded, MessageHeaderField)
	hdrbase, _ = bytepack.Pack(hdrbase, encrypted, NaclMessageField)

	hdr = append(hdr, []byte(hex.EncodeToString(smm.PublicKey))...)
	hdr = append(hdr, byte(' '))
	hdr = append(hdr, []byte(hex.EncodeToString(messages.EncryptedCommonHeader.SigkeyPublicByte))...)
	hdr = append(hdr, byte(' '))
	hdr = append(hdr, []byte(base64.StdEncoding.EncodeToString(hdrbase))...)
	return hdr, nil
}

// GenerateShareMessageList generates all share messages for the group
func (messages *MessageBlock) GenerateShareMessageList() ([]byte, error) {
	var output []byte
	for _, v := range messages.MemberMessages {
		msg, err := messages.encodeShareMessage(v)
		if err != nil {
			return nil, err
		}
		output = append(output, msg...)
		output = append(output, byte('\n'))
	}
	return output, nil
}

// DecodeShareMessage decode a share message, taking into account that some fields might be missing
func DecodeShareMessage(pubkey, privkey, msg []byte) (*MessageBlock, error) {
	var content []byte
	var shares [][]byte
	var pKeyX [32]byte
	partst := bytes.Split(msg, []byte(" "))
	if len(partst) != 3 {
		return nil, ErrCannotDecode
	}
	content, err := base64.StdEncoding.DecodeString(string(partst[2]))
	if err != nil {
		return nil, err
	}
	fields0, err := bytepack.UnpackAll(content)
	if err != nil {
		return nil, err
	}
	ok := bytepack.VerifyFields(fields0, []int{MessageHeaderField, NaclMessageField})
	if !ok {
		return nil, ErrCannotDecode
	}
	fields1, err := bytepack.UnpackAll(fields0[MessageHeaderField])
	if err != nil {
		return nil, err
	}
	ok = bytepack.VerifyFields(fields1, []int{CommentField, SigKeyPublicHashField})
	if !ok {
		return nil, ErrCannotDecode
	}
	decodedMessage, err := naclwrapper.DecryptPack(fields0[NaclMessageField], pubkey, privkey)
	if err != nil {
		return nil, err
	}
	fields2, err := bytepack.UnpackAll(decodedMessage)
	if err != nil {
		return nil, err
	}
	ok = bytepack.VerifyFields(fields2, []int{SpecificContentField, CommonContentField, MessageTypeField})
	if !ok {
		return nil, ErrCannotDecode
	}
	if fields2[MessageTypeField][0] != ShareMessageType {
		return nil, ErrBadMessageType
	}
	fields3, err := bytepack.UnpackAll(fields2[CommonContentField])
	if err != nil {
		return nil, err
	}
	ok = bytepack.VerifyFields(fields3, []int{MemberSecretField, CommentHashField, SigkeyPublicByteField, SecretHashField, ThreshholdField})
	if !ok {
		return nil, ErrCannotDecode
	}
	fields4, err := bytepack.UnpackAll(fields2[SpecificContentField])
	if err != nil {
		return nil, err
	}
	ok = bytepack.VerifyFields(fields4, []int{NumSharesField, ShareMessageField})
	if !ok {
		return nil, ErrCannotDecode
	}
	numShares := int(fields4[NumSharesField][0])
	preShares := fields4[ShareMessageField]
	for i := 0; i < numShares; i++ {
		var xshare []byte
		var marker int
		xshare, preShares, marker, err = bytepack.Unpack(preShares)
		if marker != EncodedShare {
			return nil, ErrCannotDecode
		}
		shares = append(shares, xshare)
	}
	mb := new(MessageBlock)
	mb.CommonMessageHeader = new(CommonMessageHeader)
	mb.CommonMessageHeader.Comment = fields1[CommentField]
	mb.CommonMessageHeader.SigPubKeyHash = fields1[SigKeyPublicHashField]
	mb.CommonMessageHeader.Encoded = fields0[MessageHeaderField]
	mb.EncryptedCommonHeader = new(EncryptedCommonHeader)
	mb.EncryptedCommonHeader.MemberSecret = fields3[MemberSecretField]
	mb.EncryptedCommonHeader.CommentHash = fields3[CommentHashField]
	mb.EncryptedCommonHeader.SigkeyPublicByte = fields3[SigkeyPublicByteField]
	mb.EncryptedCommonHeader.SecretHash = fields3[SecretHashField]
	mb.EncryptedCommonHeader.Threshhold = fields3[ThreshholdField][0]
	mb.EncryptedCommonHeader.Encoded = fields2[CommonContentField]
	mb.MemberMessages = make([]ShareMemberMessage, 1)
	mb.MemberMessages[0].PublicKey = pubkey
	if bytepack.VerifyFields(fields4, []int{FakeMessageField}) {
		fake, err := parseSignedShare(fields4[FakeMessageField])
		if err != nil {
			return nil, err
		}
		mb.MemberMessages[0].Fake = fake
	}

	fields, err := bytepack.UnpackAll(fields3[SigkeyPublicByteField])
	if err != nil {
		return nil, err
	}
	if !bytepack.VerifyFields(fields, []int{PublicKeyXField, PublicKeyYField}) {
		return nil, ErrCannotDecode
	}

	mb.SigPublicKey = &ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X:     new(big.Int),
		Y:     new(big.Int),
	}
	mb.SigPublicKey.X = mb.SigPublicKey.X.SetBytes(fields[PublicKeyXField])
	mb.SigPublicKey.Y = mb.SigPublicKey.Y.SetBytes(fields[PublicKeyYField])
	copy(pKeyX[:], pubkey[0:32])
	for _, s := range shares {
		decoded, err := parseSignedShare(s)
		if err != nil {
			return nil, err
		}
		ok, err := mb.verifyShare(*decoded)
		if !ok {
			return nil, ErrSignatureVerify
		}
		if !bytes.Equal(decoded.PublicKey, pubkey) {
			return nil, ErrPubkeyNotMatching
		}
		mb.MemberMessages[0].Shares = append(mb.MemberMessages[0].Shares, *decoded)
	}
	return mb, nil
}

// calcHmac calculates a sha512 hmac
func calcHmac(message, key []byte) []byte {
	m := hmac.New(sha512.New, key)
	m.Write(message)
	return m.Sum(nil)
}

// GenShareRequestTemplate constructs a share request out of a single share message and the corresponding private key
func (messages *MessageBlock) GenShareRequestTemplate(pubkey, privkey []byte) []byte {
	var content []byte
	now := []byte(strconv.Itoa(int(time.Now().Unix())))
	content, _ = bytepack.Pack(content, now, NonceField)
	content, _ = bytepack.Pack(content, messages.EncryptedCommonHeader.SigkeyPublicByte, SigkeyPublicByteField)
	content, _ = bytepack.Pack(content, pubkey, PublicKeyField)
	mac := calcHmac(content, messages.EncryptedCommonHeader.MemberSecret)
	content, _ = bytepack.Pack(content, mac, HMACField)
	messageType := make([]byte, 1)
	messageType[0] = ShareRequestType
	content, _ = bytepack.Pack(content, messageType[:], MessageTypeField)
	return content
}

// GenShareRequestMessage encodes and encrypts a ShareRequestTemplate for a single public key
func GenShareRequestMessage(content, sigkeybytes, receivePub, sendPub, sendPriv []byte) ([]byte, error) {
	var ret []byte
	enc, err := naclwrapper.EncryptPack(content, receivePub, sendPub, sendPriv)
	if err != nil {
		return nil, err
	}
	ret = append(ret, hex.EncodeToString(receivePub)...)
	ret = append(ret, byte(' '))
	ret = append(ret, hex.EncodeToString(sigkeybytes)...)
	ret = append(ret, byte(' '))
	ret = append(ret, []byte(base64.StdEncoding.EncodeToString(enc))...)
	ret = append(ret, byte('\n'))
	return ret, nil
}

// GenShareRequestMessages encodes and encrypts all ShareRequestTemplates
func GenShareRequestMessages(msgList, pubkey, privkey []byte) (messages []byte, err error) {
	var mb *MessageBlock
	var pklist [][]byte
	var secPub []byte
	pkhex := []byte(hex.EncodeToString(pubkey))
	lines := bytes.Split(msgList, []byte("\n"))
	for _, line := range lines {
		var err error
		parts := bytes.Split(line, []byte(" "))
		if len(line) < 10 {
			continue
		}
		if secPub == nil {
			secPub = parts[1]
		}
		if bytes.Equal(parts[1], secPub) { // First secret sigkey will dominate
			pkt, _ := hex.DecodeString(string(parts[0]))
			if len(pkt) > 10 {
				if mb == nil && bytes.Equal(parts[0], pkhex) { // Load myself
					mb, err = DecodeShareMessage(pubkey, privkey, line)
					if err != nil {
						return nil, err
					}
				} else {
					pklist = append(pklist, pkt) // Don't create a request for myself
				}
			}
		}
	}
	if mb == nil {
		return nil, ErrNotFound
	}
	srmt := mb.GenShareRequestTemplate(pubkey, privkey)
	for _, rpubkey := range pklist {
		if bytes.Equal(rpubkey, pubkey) {
			continue
		}
		srmm, err := GenShareRequestMessage(srmt, secPub, rpubkey, pubkey, privkey)
		if err != nil {
			return nil, err
		}
		messages = append(messages, srmm...)
	}
	return messages, nil
}

func decryptShareMessage(pubkey, privkey, message []byte) (*ShareRequest, error) {
	parts := bytes.Split(message, []byte(" "))
	enc, err := base64.StdEncoding.DecodeString(string(parts[len(parts)-1]))
	if err != nil {
		return nil, err
	}
	dec, err := naclwrapper.DecryptPack(enc, pubkey, privkey)
	if err != nil {
		return nil, err
	}
	fields, err := bytepack.UnpackAll(dec)
	if err != nil {
		return nil, err
	}
	if !bytepack.VerifyFields(fields, []int{NonceField, SigkeyPublicByteField, PublicKeyField, HMACField, MessageTypeField}) {
		return nil, ErrCannotDecode
	}
	if fields[MessageTypeField][0] != ShareRequestType {
		return nil, ErrBadMessageType
	}
	sr := new(ShareRequest)
	sr.nonce = fields[NonceField]
	sr.mac = fields[HMACField]
	sr.sigPubkey = fields[SigkeyPublicByteField]
	sr.senderPubkey = fields[PublicKeyField]
	sr.recipientPubkey = pubkey
	sr.content, _ = bytepack.Pack(sr.content, sr.nonce, NonceField)
	sr.content, _ = bytepack.Pack(sr.content, sr.sigPubkey, SigkeyPublicByteField)
	sr.content, _ = bytepack.Pack(sr.content, sr.senderPubkey, PublicKeyField)
	return sr, nil
}

// VerifyShareRequest decrypts, decodes and validates a ShareRequestMessage.
// Returns the corresponding messageblock (includes shares), public key of sender
func VerifyShareRequest(pubkey, privkey, message, myshares []byte) (*MessageBlock, []byte, error) {
	sr, err := decryptShareMessage(pubkey, privkey, message)
	if err != nil {
		return nil, nil, err
	}

	shareEntries := bytes.Split(myshares, []byte("\n"))
	for _, shareEntry := range shareEntries {
		mb, err := DecodeShareMessage(pubkey, privkey, shareEntry)
		if err != nil {
			continue
		}
		if bytes.Equal(mb.EncryptedCommonHeader.SigkeyPublicByte, sr.sigPubkey) {
			// verify MAC
			mac := calcHmac(sr.content, mb.EncryptedCommonHeader.MemberSecret)
			if !hmac.Equal(mac, sr.mac) {
				return nil, nil, ErrHMAC
			}
			return mb, sr.senderPubkey, nil
		}
	}
	return nil, nil, ErrNotFound
}

// GenShareReply constructs,encodes and encrypts a share reply based on public key,
func (messages *MessageBlock) GenShareReply(recipientPubKey []byte, numShares int, fake bool) ([]byte, error) {
	var addedShares, shareLen, padLen int
	var returnShares [][]byte
	var p, q, retMessage []byte
	if int(messages.EncryptedCommonHeader.Threshhold) > numShares {
		numShares = int(messages.EncryptedCommonHeader.Threshhold)
	}
	if fake == true && messages.MemberMessages[0].Fake != nil {
		addedShares = 1
		returnShares = append(returnShares, messages.MemberMessages[0].Fake.Encoded)
		shareLen = len(returnShares) + 6
	} else if fake == true {
		return nil, ErrNoFakes
	} else {
		for _, share := range messages.MemberMessages[0].Shares {
			if shareLen == 0 {
				shareLen = len(share.Encoded) + 6
			}
			if addedShares < numShares {
				returnShares = append(returnShares, share.Encoded)
				addedShares++
			}
		}
	}
	if addedShares == 0 {
		return nil, ErrNotFound
	}
	messageType := make([]byte, 1)
	messageType[0] = ShareResponseType
	p, _ = bytepack.Pack(p, messageType[:], MessageTypeField)
	NumShares := make([]byte, 1)
	NumShares[0] = byte(addedShares)
	p, _ = bytepack.Pack(p, NumShares, NumSharesField)
	for _, share := range returnShares {
		q, _ = bytepack.Pack(q, share, EncodedShare)
	}
	p, _ = bytepack.Pack(p, q, ShareMessageField)
	trueLen := len(q)
	shareLen = shareLen * int(messages.EncryptedCommonHeader.Threshhold)
	padLen = 1
	if shareLen > trueLen {
		padLen = shareLen - trueLen
	}
	padding := make([]byte, padLen)
	rand.Read(padding)
	p, _ = bytepack.Pack(p, padding, PaddingField)
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	encrypted, err := naclwrapper.EncryptPack(p, recipientPubKey, pub[:], priv[:])
	if err != nil {
		return nil, err
	}
	retMessage = append(retMessage, hex.EncodeToString(messages.EncryptedCommonHeader.SigkeyPublicByte)...)
	retMessage = append(retMessage, byte(' '))
	retMessage = append(retMessage, []byte(base64.StdEncoding.EncodeToString(encrypted))...)
	retMessage = append(retMessage, byte('\n'))
	return retMessage, nil
}

func (messages *MessageBlock) insertShareReply(shareReply, pub, priv []byte) ([]byte, error) {
	var shares [][]byte
	var pubkey []byte
	parts := bytes.Split(shareReply, []byte(" "))
	message := parts[len(parts)-1]
	content, err := base64.StdEncoding.DecodeString(string(message))
	if err != nil {
		return nil, err
	}
	decrypted, err := naclwrapper.DecryptPack(content, pub, priv)
	if err != nil {
		return nil, err
	}
	fields, err := bytepack.UnpackAll(decrypted)
	if err != nil {
		return nil, err
	}
	if !bytepack.VerifyFields(fields, []int{PaddingField, NumSharesField, ShareMessageField, MessageTypeField}) {
		return nil, ErrCannotDecode
	}
	if fields[MessageTypeField][0] != ShareResponseType {
		return nil, ErrBadMessageType
	}
	for i := 0; i < int(fields[NumSharesField][0]); i++ {
		var marker int
		var xshare []byte
		xshare, fields[ShareMessageField], marker, err = bytepack.Unpack(fields[ShareMessageField])
		if marker != EncodedShare {
			return nil, ErrCannotDecode
		}
		shares = append(shares, xshare)
	}
	if len(shares) > 0 {
		// add shares to messageblock
		var err error
		pubkey, err = messages.LoadShares(shares, true)
		if err != nil {
			return nil, err
		}
	}
	return pubkey, nil
}

// InsertShareReplies loads ShareReply messages, decrypts them, and adds the shares to the message block
func (messages *MessageBlock) InsertShareReplies(shareReplies, pub, priv []byte) ([]byte, error) {
	var pubkey []byte
	added := 0
	for _, shareReply := range bytes.Split(shareReplies, []byte("\n")) {
		var err error
		pubkey, err = messages.insertShareReply(shareReply, pub, priv)
		if err == nil {
			added++
		}
	}
	if added == 0 {
		return nil, ErrNotFound
	}
	return pubkey, nil
}

// ------- Helper functions ----------

// DecodeShareMessageFromList decode a share message from a list, taking into account that some fields might be missing
func DecodeShareMessageFromList(pubkey, privkey, messageList []byte) (*MessageBlock, error) {
	var mb *MessageBlock
	var err error
	for _, message := range bytes.Split(messageList, []byte("\n")) {
		mb, err = DecodeShareMessage(pubkey, privkey, message)
		if err == nil {
			break
		}
	}
	if mb == nil {
		return nil, ErrNotFound
	}
	return mb, nil
}

// VerifyShareRequestFromList decrypts, decodes and validates a ShareRequestMessage from a List.
// Returns the corresponding messageblock (includes shares), public key of sender
func VerifyShareRequestFromList(pubkey, privkey, messageList, myshares []byte) (*MessageBlock, []byte, error) {
	var mb *MessageBlock
	var err error
	var senderPubKey []byte
	for _, message := range bytes.Split(messageList, []byte("\n")) {
		mb, senderPubKey, err = VerifyShareRequest(pubkey, privkey, message, myshares)
		if err == nil {
			break
		}
	}
	if mb == nil {
		return nil, nil, ErrNotFound
	}
	return mb, senderPubKey, nil

}

// InsertShareReply decrypts, decodes and loads a share reply based on public key,
// share request and share message
// Add message types!

// DecodeShareMessage (self)
// InsertShareReply
// Combine
