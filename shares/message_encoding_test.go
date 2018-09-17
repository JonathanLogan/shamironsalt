package shares

import (
	"bytes"
	//"crypto/rand"
	"fmt"
	//"golang.org/x/crypto/nacl/box"
	//"math/big"
	"encoding/hex"
	"testing"
)

func Test_ShareMessageEncode(t *testing.T) {
	pub, _ := hex.DecodeString("f597813ef9699d0e35c959c4dcd5fc9992a71b538cf55125eff5a646ba62723b")
	priv, _ := hex.DecodeString("ed9fc44733dd842400e271c5f0710fdd507666061f2901c281d8e5733e72ac26")
	pub1, _ := hex.DecodeString("b546098710147f9acfc957e9ca2a6d58c4dae0be122125f8f900e2391de96f0e")
	priv1, _ := hex.DecodeString("661af1a4ef288c52b3b65676909cf7c3d99c8daffa77abc574774ad6421d3dab")
	pub2, _ := hex.DecodeString("fabdb52d8f74f6ef4938393f0d5429e619c9bf8329faf1332027c740b3a4204d")
	priv2, _ := hex.DecodeString("7128a04ca0dd76aa57f0f0d68bef5195b768d4b82f4490188e7cbd6915ca5eec")
	_, _, _, _, _, _ = pub, priv, pub1, priv1, pub2, priv2
	sconf, err := New([]byte("I am a big bad secret"), []byte("Do not reveal my secret"), 4)
	if err != nil {
		t.Fatalf("Configuration failed: %s", err)
	}
	err = sconf.AddMember(pub[:], 3, true)
	if err != nil {
		t.Errorf("Adding member failed: %s", err)
	}
	sconf.AddMember(pub1[:], 3, false)
	messages, err := sconf.GenerateMessages()
	if err != nil {
		t.Errorf("Message generation failed: %s", err)
	}
	for _, v := range messages.MemberMessages {
		msg, err := messages.encodeShareMessage(v)
		if err != nil {
			t.Errorf("Message creating failed: %s", err)
		}
		_ = msg
	}
}

func Test_GenerateShareMessageList(t *testing.T) {
	pub, _ := hex.DecodeString("f597813ef9699d0e35c959c4dcd5fc9992a71b538cf55125eff5a646ba62723b")
	priv, _ := hex.DecodeString("ed9fc44733dd842400e271c5f0710fdd507666061f2901c281d8e5733e72ac26")
	pub1, _ := hex.DecodeString("b546098710147f9acfc957e9ca2a6d58c4dae0be122125f8f900e2391de96f0e")
	priv1, _ := hex.DecodeString("661af1a4ef288c52b3b65676909cf7c3d99c8daffa77abc574774ad6421d3dab")
	pub2, _ := hex.DecodeString("fabdb52d8f74f6ef4938393f0d5429e619c9bf8329faf1332027c740b3a4204d")
	priv2, _ := hex.DecodeString("7128a04ca0dd76aa57f0f0d68bef5195b768d4b82f4490188e7cbd6915ca5eec")
	_, _, _, _, _, _ = pub, priv, pub1, priv1, pub2, priv2
	sconf, err := New([]byte("I am a big bad secret"), []byte("Do not reveal my secret"), 4)
	if err != nil {
		t.Fatalf("Configuration failed: %s", err)
	}
	err = sconf.AddMember(pub[:], 3, true)
	if err != nil {
		t.Errorf("Adding member failed: %s", err)
	}
	sconf.AddMember(pub1[:], 3, false)
	messages, err := sconf.GenerateMessages()
	if err != nil {
		t.Errorf("Message generation failed: %s", err)
	}
	msg, err := messages.GenerateShareMessageList()
	if err != nil {
		t.Errorf("Message encoding failed: %s", err)
	}
	_ = msg
}

func Test_DecodeShareMessage(t *testing.T) {
	pub, _ := hex.DecodeString("f597813ef9699d0e35c959c4dcd5fc9992a71b538cf55125eff5a646ba62723b")
	priv, _ := hex.DecodeString("ed9fc44733dd842400e271c5f0710fdd507666061f2901c281d8e5733e72ac26")
	pub1, _ := hex.DecodeString("b546098710147f9acfc957e9ca2a6d58c4dae0be122125f8f900e2391de96f0e")
	priv1, _ := hex.DecodeString("661af1a4ef288c52b3b65676909cf7c3d99c8daffa77abc574774ad6421d3dab")
	pub2, _ := hex.DecodeString("fabdb52d8f74f6ef4938393f0d5429e619c9bf8329faf1332027c740b3a4204d")
	priv2, _ := hex.DecodeString("7128a04ca0dd76aa57f0f0d68bef5195b768d4b82f4490188e7cbd6915ca5eec")
	_, _, _, _, _, _ = pub, priv, pub1, priv1, pub2, priv2

	sconf, err := New([]byte("I am a big bad secret"), []byte("Do not reveal my secret"), 4)
	if err != nil {
		t.Fatalf("Configuration failed: %s", err)
	}

	err = sconf.AddMember(pub[:], 3, true)
	if err != nil {
		t.Errorf("Adding member failed: %s", err)
	}

	sconf.AddMember(pub1[:], 3, false)
	sconf.AddMember(pub2[:], 3, false)
	messages, err := sconf.GenerateMessages()
	if err != nil {
		t.Errorf("Message generation failed: %s", err)
	}
	msg, err := messages.encodeShareMessage(messages.MemberMessages[0])
	if err != nil {
		t.Errorf("Message creating failed: %s", err)
	}
	parts := bytes.Split(msg, []byte(" "))
	var pk, sk []byte
	if bytes.Equal(parts[0], []byte(hex.EncodeToString(pub[:]))) {
		pk, sk = pub, priv
	}
	if bytes.Equal(parts[0], []byte(hex.EncodeToString(pub1[:]))) {
		pk, sk = pub1, priv1
	}
	if bytes.Equal(parts[0], []byte(hex.EncodeToString(pub2[:]))) {
		pk, sk = pub2, priv2
	}
	data, err := DecodeShareMessage(pk[:], sk[:], msg)
	if err != nil {
		if err == ErrSignatureDecode {
			fmt.Println("Error Y007")
		} else {
			fmt.Println("Entry:    ", string(msg))
			fmt.Println("In entry: ", hex.EncodeToString(parts[0]))
			fmt.Println("Chosen:   ", hex.EncodeToString(pk[:]))
			fmt.Println("Pub:      ", hex.EncodeToString(pub[:]))
			fmt.Println("Pub1:     ", hex.EncodeToString(pub1[:]))
		}
		t.Fatalf("Message decode failed: %s", err)
	}
	if messages.SigPublicKey.X.Cmp(data.SigPublicKey.X) != 0 {
		t.Errorf("Message decode failed: SigPublicKey.X")
	}
	if messages.SigPublicKey.Y.Cmp(data.SigPublicKey.Y) != 0 {
		t.Errorf("Message decode failed: SigPublicKey.Y")
	}
	if !bytes.Equal(data.CommonMessageHeader.SigPubKeyHash, messages.CommonMessageHeader.SigPubKeyHash) {
		t.Errorf("Message decode failed: SigPubKeyHash")
	}
	if !bytes.Equal(data.CommonMessageHeader.Comment, messages.CommonMessageHeader.Comment) {
		t.Errorf("Message decode failed: Comment")
	}
	if !bytes.Equal(data.CommonMessageHeader.Encoded, messages.CommonMessageHeader.Encoded) {
		t.Errorf("Message decode failed: Encoded")
	}
	if !bytes.Equal(data.EncryptedCommonHeader.MemberSecret, messages.EncryptedCommonHeader.MemberSecret) {
		t.Errorf("Message decode failed: MemberSecret")
	}
	if !bytes.Equal(data.EncryptedCommonHeader.CommentHash, messages.EncryptedCommonHeader.CommentHash) {
		t.Errorf("Message decode failed: CommentHash")
	}
	if !bytes.Equal(data.EncryptedCommonHeader.SigkeyPublicByte, messages.EncryptedCommonHeader.SigkeyPublicByte) {
		t.Errorf("Message decode failed: SigkeyPublicByte")
	}
	if !bytes.Equal(data.EncryptedCommonHeader.SecretHash, messages.EncryptedCommonHeader.SecretHash) {
		t.Errorf("Message decode failed: SecretHash")
	}
	if !bytes.Equal(data.EncryptedCommonHeader.Encoded, messages.EncryptedCommonHeader.Encoded) {
		t.Errorf("Message decode failed: Encoded")
	}
	if data.EncryptedCommonHeader.Threshhold != messages.EncryptedCommonHeader.Threshhold {
		t.Errorf("Message decode failed: Threshhold")
	}
	if len(data.MemberMessages[0].Shares) == 0 {
		t.Errorf("Message decode failed: Could not load shares")
	}
	msg, err = messages.encodeShareMessage(messages.MemberMessages[1])
	if err != nil {
		t.Errorf("Message creating failed: %s", err)
	}
	parts = bytes.Split(msg, []byte(" "))
	if bytes.Equal(parts[0], []byte(hex.EncodeToString(pub[:]))) {
		pk, sk = pub, priv
	}
	if bytes.Equal(parts[0], []byte(hex.EncodeToString(pub1[:]))) {
		pk, sk = pub1, priv1
	}
	if bytes.Equal(parts[0], []byte(hex.EncodeToString(pub2[:]))) {
		pk, sk = pub2, priv2
	}
	data, err = DecodeShareMessage(pk[:], sk[:], msg)
	if err != nil {
		if err == ErrSignatureDecode {
			fmt.Println("Error Y007")
		} else {
			fmt.Println("Entry:    ", string(msg))
			fmt.Println("In entry: ", hex.EncodeToString(parts[0]))
			fmt.Println("Chosen:   ", hex.EncodeToString(pk[:]))
			fmt.Println("Pub:      ", hex.EncodeToString(pub[:]))
			fmt.Println("Pub1:     ", hex.EncodeToString(pub1[:]))
		}
		t.Fatalf("Message decode failed: %s", err)
	}
	if messages.SigPublicKey.X.Cmp(data.SigPublicKey.X) != 0 {
		t.Errorf("Message decode failed: SigPublicKey.X")
	}
	if messages.SigPublicKey.Y.Cmp(data.SigPublicKey.Y) != 0 {
		t.Errorf("Message decode failed: SigPublicKey.Y")
	}
	if !bytes.Equal(data.CommonMessageHeader.SigPubKeyHash, messages.CommonMessageHeader.SigPubKeyHash) {
		t.Errorf("Message decode failed: SigPubKeyHash")
	}
	if !bytes.Equal(data.CommonMessageHeader.Comment, messages.CommonMessageHeader.Comment) {
		t.Errorf("Message decode failed: Comment")
	}
	if !bytes.Equal(data.CommonMessageHeader.Encoded, messages.CommonMessageHeader.Encoded) {
		t.Errorf("Message decode failed: Encoded")
	}
	if !bytes.Equal(data.EncryptedCommonHeader.MemberSecret, messages.EncryptedCommonHeader.MemberSecret) {
		t.Errorf("Message decode failed: MemberSecret")
	}
	if !bytes.Equal(data.EncryptedCommonHeader.CommentHash, messages.EncryptedCommonHeader.CommentHash) {
		t.Errorf("Message decode failed: CommentHash")
	}
	if !bytes.Equal(data.EncryptedCommonHeader.SigkeyPublicByte, messages.EncryptedCommonHeader.SigkeyPublicByte) {
		t.Errorf("Message decode failed: SigkeyPublicByte")
	}
	if !bytes.Equal(data.EncryptedCommonHeader.SecretHash, messages.EncryptedCommonHeader.SecretHash) {
		t.Errorf("Message decode failed: SecretHash")
	}
	if !bytes.Equal(data.EncryptedCommonHeader.Encoded, messages.EncryptedCommonHeader.Encoded) {
		t.Errorf("Message decode failed: Encoded")
	}
	if data.EncryptedCommonHeader.Threshhold != messages.EncryptedCommonHeader.Threshhold {
		t.Errorf("Message decode failed: Threshhold")
	}
	if len(data.MemberMessages[0].Shares) == 0 {
		t.Errorf("Message decode failed: Could not load shares")
	}
}

func Test_GenShareRequestMessages(t *testing.T) {
	pub, _ := hex.DecodeString("f597813ef9699d0e35c959c4dcd5fc9992a71b538cf55125eff5a646ba62723b")
	priv, _ := hex.DecodeString("ed9fc44733dd842400e271c5f0710fdd507666061f2901c281d8e5733e72ac26")
	pub1, _ := hex.DecodeString("b546098710147f9acfc957e9ca2a6d58c4dae0be122125f8f900e2391de96f0e")
	priv1, _ := hex.DecodeString("661af1a4ef288c52b3b65676909cf7c3d99c8daffa77abc574774ad6421d3dab")
	pub2, _ := hex.DecodeString("fabdb52d8f74f6ef4938393f0d5429e619c9bf8329faf1332027c740b3a4204d")
	priv2, _ := hex.DecodeString("7128a04ca0dd76aa57f0f0d68bef5195b768d4b82f4490188e7cbd6915ca5eec")
	_, _, _, _, _, _ = pub, priv, pub1, priv1, pub2, priv2
	sconf, err := New([]byte("I am a big bad secret"), []byte("Do not reveal my secret"), 4)
	if err != nil {
		t.Fatalf("Configuration failed: %s", err)
	}
	err = sconf.AddMember(pub[:], 3, true)
	if err != nil {
		t.Errorf("Adding member failed: %s", err)
	}
	sconf.AddMember(pub1[:], 3, false)
	sconf.AddMember(pub2[:], 3, false)
	messages, err := sconf.GenerateMessages()
	if err != nil {
		t.Errorf("Message generation failed: %s", err)
	}
	ShareMessagesList, err := messages.GenerateShareMessageList()
	if err != nil {
		t.Errorf("Message creating failed: %s", err)
	}
	ShareRequestMessagesList, err := GenShareRequestMessages(ShareMessagesList, pub[:], priv[:])
	if err != nil {
		t.Errorf("Share request message list creating failed: %s", err)
	}
	_, _ = ShareRequestMessagesList, ShareMessagesList
}

func Test_decryptShareMessage(t *testing.T) {
	pub, _ := hex.DecodeString("f597813ef9699d0e35c959c4dcd5fc9992a71b538cf55125eff5a646ba62723b")
	priv, _ := hex.DecodeString("ed9fc44733dd842400e271c5f0710fdd507666061f2901c281d8e5733e72ac26")
	pub1, _ := hex.DecodeString("b546098710147f9acfc957e9ca2a6d58c4dae0be122125f8f900e2391de96f0e")
	priv1, _ := hex.DecodeString("661af1a4ef288c52b3b65676909cf7c3d99c8daffa77abc574774ad6421d3dab")
	pub2, _ := hex.DecodeString("fabdb52d8f74f6ef4938393f0d5429e619c9bf8329faf1332027c740b3a4204d")
	priv2, _ := hex.DecodeString("7128a04ca0dd76aa57f0f0d68bef5195b768d4b82f4490188e7cbd6915ca5eec")
	_, _, _, _, _, _ = pub, priv, pub1, priv1, pub2, priv2
	sconf, err := New([]byte("I am a big bad secret"), []byte("Do not reveal my secret"), 4)
	if err != nil {
		t.Fatalf("Configuration failed: %s", err)
	}
	err = sconf.AddMember(pub[:], 3, true)
	if err != nil {
		t.Errorf("Adding member failed: %s", err)
	}
	sconf.AddMember(pub1[:], 3, false)
	sconf.AddMember(pub2[:], 3, false)
	messages, err := sconf.GenerateMessages()
	if err != nil {
		t.Errorf("Message generation failed: %s", err)
	}
	ShareMessagesList, err := messages.GenerateShareMessageList()
	if err != nil {
		t.Errorf("Message creating failed: %s", err)
	}
	ShareRequestMessagesList, err := GenShareRequestMessages(ShareMessagesList, pub[:], priv[:])
	if err != nil {
		t.Errorf("Share request message list creating failed: %s", err)
	}
	shareRequests := bytes.Split(ShareRequestMessagesList, []byte("\n"))
	_, err = decryptShareMessage(pub1[:], priv1[:], shareRequests[0])
	if err != nil {
		_, err = decryptShareMessage(pub[:], priv[:], shareRequests[0])
		if err != nil {
			_, err = decryptShareMessage(pub2[:], priv2[:], shareRequests[0])
			if err != nil {
				t.Errorf("Share request message decode failed: %s", err)
			}
		}
	}
}

func Test_VerifyShareRequest(t *testing.T) {
	pub, _ := hex.DecodeString("f597813ef9699d0e35c959c4dcd5fc9992a71b538cf55125eff5a646ba62723b")
	priv, _ := hex.DecodeString("ed9fc44733dd842400e271c5f0710fdd507666061f2901c281d8e5733e72ac26")
	pub1, _ := hex.DecodeString("b546098710147f9acfc957e9ca2a6d58c4dae0be122125f8f900e2391de96f0e")
	priv1, _ := hex.DecodeString("661af1a4ef288c52b3b65676909cf7c3d99c8daffa77abc574774ad6421d3dab")
	pub2, _ := hex.DecodeString("fabdb52d8f74f6ef4938393f0d5429e619c9bf8329faf1332027c740b3a4204d")
	priv2, _ := hex.DecodeString("7128a04ca0dd76aa57f0f0d68bef5195b768d4b82f4490188e7cbd6915ca5eec")
	_, _, _, _, _, _ = pub, priv, pub1, priv1, pub2, priv2
	sconf, err := New([]byte("I am a big bad secret"), []byte("Do not reveal my secret"), 4)
	if err != nil {
		t.Fatalf("Configuration failed: %s", err)
	}
	err = sconf.AddMember(pub[:], 3, true)
	if err != nil {
		t.Errorf("Adding member failed: %s", err)
	}
	sconf.AddMember(pub1[:], 3, false)
	sconf.AddMember(pub2[:], 3, false)
	messages, err := sconf.GenerateMessages()
	if err != nil {
		t.Errorf("Message generation failed: %s", err)
	}
	ShareMessagesList, err := messages.GenerateShareMessageList()
	if err != nil {
		t.Errorf("Message creating failed: %s", err)
	}
	ShareRequestMessagesList, err := GenShareRequestMessages(ShareMessagesList, pub[:], priv[:])
	if err != nil {
		t.Errorf("Share request message list creating failed: %s", err)
	}
	shareRequests := bytes.Split(ShareRequestMessagesList, []byte("\n"))
	myshares, spub, err := VerifyShareRequest(pub1[:], priv1[:], shareRequests[0], ShareMessagesList)
	if err != nil {
		myshares, spub, err = VerifyShareRequest(pub[:], priv[:], shareRequests[0], ShareMessagesList)
		if err != nil {
			myshares, spub, err = VerifyShareRequest(pub2[:], priv2[:], shareRequests[0], ShareMessagesList)
			if err != nil {
				t.Errorf("Share request message verify failed: %s", err)
			}
		}
	}
	if !bytes.Equal(pub, spub) {
		t.Error("Bad sender")
	}
	_ = myshares
}

func Test_GenShareReply(t *testing.T) {
	pub, _ := hex.DecodeString("f597813ef9699d0e35c959c4dcd5fc9992a71b538cf55125eff5a646ba62723b")
	priv, _ := hex.DecodeString("ed9fc44733dd842400e271c5f0710fdd507666061f2901c281d8e5733e72ac26")
	pub1, _ := hex.DecodeString("b546098710147f9acfc957e9ca2a6d58c4dae0be122125f8f900e2391de96f0e")
	priv1, _ := hex.DecodeString("661af1a4ef288c52b3b65676909cf7c3d99c8daffa77abc574774ad6421d3dab")
	pub2, _ := hex.DecodeString("fabdb52d8f74f6ef4938393f0d5429e619c9bf8329faf1332027c740b3a4204d")
	priv2, _ := hex.DecodeString("7128a04ca0dd76aa57f0f0d68bef5195b768d4b82f4490188e7cbd6915ca5eec")
	_, _, _, _, _, _ = pub, priv, pub1, priv1, pub2, priv2
	sconf, err := New([]byte("I am a big bad secret"), []byte("Do not reveal my secret"), 4)
	if err != nil {
		t.Fatalf("Configuration failed: %s", err)
	}
	err = sconf.AddMember(pub[:], 3, true)
	if err != nil {
		t.Errorf("Adding member failed: %s", err)
	}
	sconf.AddMember(pub1[:], 3, false)
	sconf.AddMember(pub2[:], 3, false)
	messages, err := sconf.GenerateMessages()
	if err != nil {
		t.Errorf("Message generation failed: %s", err)
	}
	ShareMessagesList, err := messages.GenerateShareMessageList()
	if err != nil {
		t.Errorf("Message creating failed: %s", err)
	}
	ShareRequestMessagesList, err := GenShareRequestMessages(ShareMessagesList, pub[:], priv[:])
	if err != nil {
		t.Errorf("Share request message list creating failed: %s", err)
	}
	shareRequests := bytes.Split(ShareRequestMessagesList, []byte("\n"))
	myshares, spub, err := VerifyShareRequest(pub1[:], priv1[:], shareRequests[0], ShareMessagesList)
	if err != nil {
		myshares, spub, err = VerifyShareRequest(pub[:], priv[:], shareRequests[0], ShareMessagesList)
		if err != nil {
			myshares, spub, err = VerifyShareRequest(pub2[:], priv2[:], shareRequests[0], ShareMessagesList)
			if err != nil {
				t.Errorf("Share request message verify failed: %s", err)
			}
		}
	}
	if !bytes.Equal(pub, spub) {
		t.Error("Bad sender")
	}
	sharemessage, err := myshares.GenShareReply(spub, 1, false)
	if err != nil {
		t.Errorf("Share reply creation failed: %s", err)
	}
	_ = sharemessage
}

func Test_InsertShareReplies(t *testing.T) {
	pub, _ := hex.DecodeString("f597813ef9699d0e35c959c4dcd5fc9992a71b538cf55125eff5a646ba62723b")
	priv, _ := hex.DecodeString("ed9fc44733dd842400e271c5f0710fdd507666061f2901c281d8e5733e72ac26")
	pub1, _ := hex.DecodeString("b546098710147f9acfc957e9ca2a6d58c4dae0be122125f8f900e2391de96f0e")
	priv1, _ := hex.DecodeString("661af1a4ef288c52b3b65676909cf7c3d99c8daffa77abc574774ad6421d3dab")
	pub2, _ := hex.DecodeString("fabdb52d8f74f6ef4938393f0d5429e619c9bf8329faf1332027c740b3a4204d")
	priv2, _ := hex.DecodeString("7128a04ca0dd76aa57f0f0d68bef5195b768d4b82f4490188e7cbd6915ca5eec")
	_, _, _, _, _, _ = pub, priv, pub1, priv1, pub2, priv2
	sconf, err := New([]byte("I am a big bad secret"), []byte("Do not reveal my secret"), 4)
	if err != nil {
		t.Fatalf("Configuration failed: %s", err)
	}
	err = sconf.AddMember(pub[:], 3, true)
	if err != nil {
		t.Errorf("Adding member failed: %s", err)
	}
	sconf.AddMember(pub1[:], 3, false)
	sconf.AddMember(pub2[:], 3, false)
	messages, err := sconf.GenerateMessages()
	if err != nil {
		t.Errorf("Message generation failed: %s", err)
	}
	ShareMessagesList, err := messages.GenerateShareMessageList()
	if err != nil {
		t.Errorf("Message creating failed: %s", err)
	}
	ShareRequestMessagesList, err := GenShareRequestMessages(ShareMessagesList, pub[:], priv[:])
	if err != nil {
		t.Errorf("Share request message list creating failed: %s", err)
	}
	shareRequests := bytes.Split(ShareRequestMessagesList, []byte("\n"))
	myshares, spub, err := VerifyShareRequest(pub1[:], priv1[:], shareRequests[0], ShareMessagesList)
	if err != nil {
		myshares, spub, err = VerifyShareRequest(pub[:], priv[:], shareRequests[0], ShareMessagesList)
		if err != nil {
			myshares, spub, err = VerifyShareRequest(pub2[:], priv2[:], shareRequests[0], ShareMessagesList)
			if err != nil {
				t.Errorf("Share request message verify failed: %s", err)
			}
		}
	}
	if !bytes.Equal(pub, spub) {
		t.Error("Bad sender")
	}
	sharemessage, err := myshares.GenShareReply(spub, 1, false)
	if err != nil {
		t.Errorf("Share reply creation failed: %s", err)
	}
	var messagesReconstruct *MessageBlock
	for _, message := range bytes.Split(ShareMessagesList, []byte("\n")) {
		messagesReconstruct, err = DecodeShareMessage(pub[:], priv[:], message)
		if err == nil {
			break
		}
	}
	if messagesReconstruct == nil {
		t.Fatalf("Init reconstruct failed")
	}
	_, err = messagesReconstruct.InsertShareReplies(sharemessage, pub[:], priv[:])
	if err != nil {
		t.Errorf("Share reply insert failed: %s", err)
	}
	if len(messagesReconstruct.MemberMessages) < 2 {
		t.Errorf("Nothing inserted")
	}
	if len(messagesReconstruct.MemberMessages[0].Shares) < 1 {
		t.Errorf("No shares loaded")
	}
}

func Test_Complete(t *testing.T) {
	secret := []byte("I am a big bad secret")
	pub, _ := hex.DecodeString("f597813ef9699d0e35c959c4dcd5fc9992a71b538cf55125eff5a646ba62723b")
	priv, _ := hex.DecodeString("ed9fc44733dd842400e271c5f0710fdd507666061f2901c281d8e5733e72ac26")
	pub1, _ := hex.DecodeString("b546098710147f9acfc957e9ca2a6d58c4dae0be122125f8f900e2391de96f0e")
	priv1, _ := hex.DecodeString("661af1a4ef288c52b3b65676909cf7c3d99c8daffa77abc574774ad6421d3dab")
	pub2, _ := hex.DecodeString("fabdb52d8f74f6ef4938393f0d5429e619c9bf8329faf1332027c740b3a4204d")
	priv2, _ := hex.DecodeString("7128a04ca0dd76aa57f0f0d68bef5195b768d4b82f4490188e7cbd6915ca5eec")
	_, _, _, _, _, _ = pub, priv, pub1, priv1, pub2, priv2
	sconf, err := New(secret, []byte("Do not reveal my secret"), 4)
	if err != nil {
		t.Fatalf("Configuration failed: %s", err)
	}
	err = sconf.AddMember(pub[:], 3, false)
	if err != nil {
		t.Fatalf("Adding member failed: %s", err)
	}
	sconf.AddMember(pub1[:], 3, false)
	sconf.AddMember(pub2[:], 3, false)
	messages, err := sconf.GenerateMessages()
	if err != nil {
		t.Fatalf("Message generation failed: %s", err)
	}
	ShareMessagesList, err := messages.GenerateShareMessageList()
	if err != nil {
		t.Fatalf("Message creating failed: %s", err)
	}
	ShareRequestMessagesList, err := GenShareRequestMessages(ShareMessagesList, pub[:], priv[:])
	if err != nil {
		t.Fatalf("Share request message list creating failed: %s", err)
	}

	myshares1, spub1, err := VerifyShareRequestFromList(pub1[:], priv1[:], ShareRequestMessagesList, ShareMessagesList)
	if err != nil {
		t.Fatalf("VerifyShareRequestFromList failed: %s", err)
	}
	sharemessage1, err := myshares1.GenShareReply(spub1, 1, false)
	if err != nil {
		t.Errorf("Share reply creation failed: %s", err)
	}

	myshares2, spub2, err := VerifyShareRequestFromList(pub2[:], priv2[:], ShareRequestMessagesList, ShareMessagesList)
	if err != nil {
		t.Fatalf("VerifyShareRequestFromList failed: %s", err)
	}
	sharemessage2, err := myshares2.GenShareReply(spub2, 1, false)
	if err != nil {
		t.Errorf("Share reply creation failed: %s", err)
	}
	messagesReconstruct, err := DecodeShareMessageFromList(pub[:], priv[:], ShareMessagesList)
	if err != nil {
		t.Fatalf("Init reconstruct failed: %s", err)
	}

	_, err = messagesReconstruct.InsertShareReplies(sharemessage1, pub[:], priv[:])
	if err != nil {
		t.Errorf("Share reply insert failed: %s", err)
	}
	if len(messagesReconstruct.MemberMessages) < 2 {
		t.Errorf("Nothing inserted")
	}
	if len(messagesReconstruct.MemberMessages[1].Shares) < 1 {
		t.Errorf("No shares loaded")
	}
	_, err = messagesReconstruct.InsertShareReplies(sharemessage2, pub[:], priv[:])
	if err != nil {
		t.Errorf("Share reply insert failed: %s", err)
	}
	if len(messagesReconstruct.MemberMessages) < 3 {
		t.Errorf("Nothing inserted")
	}
	if len(messagesReconstruct.MemberMessages[2].Shares) < 1 {
		t.Errorf("No shares loaded")
	}
	recSecret, err := messagesReconstruct.Combine()
	if err != nil {
		t.Errorf("Share combine failed: %s", err)
	}
	if !bytes.Equal(secret, recSecret) {
		t.Error("Secret corrupt")
	}
}
