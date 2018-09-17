Shamir on Salt
===============
is shamir secret sharing with a NaCL secured protocol for share group member communication.

This allows you to share a secret over a group of N members so that at least K members have to come together to reconstruct it. 
Shamironsalt supports giving more than one share to members, so that some members are more equal than others.

Binary can be found at Files, "Shamir on Salt", bin: shamironsalt.linux64


Usage
-----
$ shamironsalt 

Introduction:
Shamir On Salt is an implementation of shamir secret sharing combined with a share
exchange protocol based on NaCl.
The process is to have the parties generate a keypair (genkey), then to create a
share group definition, and then to share the secret via genshares.
When the secret needs to be reconstructed, one member of the share group generates
requests to the others by using genrequest. Each of the members is then able to (respond)
to the request so that the initiating member can (recover) the secret. Responses from 
share group members must be concated into one file to be read.
All operations occur on files. With the exception of the key files, all files can (and must)
 be shared with all members.
The format of a share group definition is publickey (hex encoded), number of shares, fake. 
Each separated by space, one line per member. Fake can be either 0 or 1, or omitted.
1 will generate a fake that can be used to withdraw from a reconstruction.


Usage:
  shamironsalt   <command>

Help Options:
  -h, --help  Show this help message

Available commands:
  genkey      Generate a key
  genrequest  Generate share request
  genshares   Generate shares
  recover     Recover a secret from share request responses
  respond     Respond to a share request

-----------------------

$ shamironsalt genkey
Usage:
  shamironsalt   genkey [genkey-OPTIONS]

The genkey command creates a new key. Use -k FILE to write the output to FILE

Help Options:
  -h, --help                     Show this help message

[genkey command options]
      -k, --keyfile=FILE         output filename
      -d, --display              show the public key contained in -k FILE (false)
      -p, --password=PASSWORD    set a password for the key
      -a, --askpassword          ask for the password

-----------------------

$ shamironsalt genshares
Usage:
  shamironsalt   genshares [genshares-OPTIONS]

The genshare command creates a list of new shares written to the -g FILE

Help Options:
  -h, --help                   Show this help message

[genshares command options]
      -o, --outfile=FILE       output filename to write the shares to
      -r, --recipients=FILE    recipient definition, one recipient public key per line, optional followed by number of shares and number of fakes
      -t, --threshhold=        number of shares required for reconstruction
      -c, --comment=COMMENT    comment to describe the secret
      -s, --secret=SECRET      the secret to be shared. If not given it is read from STDIN
      -a, --asksecret          ask for the secret
      -v                       be verbose. Repeat for more verbosity

-----------------------

$ shamironsalt genrequest
Usage:
  shamironsalt   genrequest [genrequest-OPTIONS]

The genrequest command generates requests for shares

Help Options:
  -h, --help                     Show this help message

[genrequest command options]
      -o, --outfile=FILE         output filename to write the requests to
      -S, --shares=FILE          file containing shares from a previous genshare operation
      -i, --identity=FILE        file containing keypair that is part of the share group
      -p, --password=PASSWORD    optional password to decrypto keypair
      -a, --askpassword          ask for the password

-----------------------

$ shamironsalt respond 
Usage:
  shamironsalt   respond [respond-OPTIONS]

Unless -o is given, display information about the request. If -o is given, produce a response

Help Options:
  -h, --help                      Show this help message

[respond command options]
      -S, --shares=FILE           file containing shares from a previous genshare operation
      -r, --request=FILE          file containing the share request
      -i, --identity=FILE         file containing keypair that is part of the share group
      -p, --password=PASSWORD     optional password to decrypto keypair
      -a, --askpassword           ask for the password
      -d, --display               display information about request. Overrides -o
      -o, --outfile=FILE          write response to FILE. Otherwise only information about the request is displayed (__NOSUCHFILE)
      -F, --fake
      -R, --replyshares=NUMBER    reply with NUMBER shares (255)
      -v                          be verbose. Repeat for more verbosity

-----------------------

$ shamironsalt recover
Usage:
  shamironsalt   recover [recover-OPTIONS]

Takes one share message and a list of responses to recover the secret

Help Options:
  -h, --help                     Show this help message

[recover command options]
      -S, --shares=FILE          file containing shares from a previous genshare operation
      -i, --identity=FILE        file containing keypair that is part of the share group
      -p, --password=PASSWORD    optional password to decrypto keypair
      -r, --responses=FILE       File containing responses to a share request
      -v                         be verbose. Repeat for more verbosity
      -a, --askpassword          ask for the password

-------------------------

Example share group definition:
$ cat sharegroup.def 
ddb4d695efa5e26df94967d15a5066a938e42487e681bc535d59d814fbe15241 2 0
1b5d0b86f7d6d69505bffd504fa722184d4feb2f331cc71d4170e33f01890e36 2 0
43879234c5702d0179aff825485e04a713840b3a518a1387b43ab8cd91d3ec6c 2 0
d66200c5efd90a0b35e83f644713ef9b16c5d0bdcab36ba3ac4d2004f959a53b 2 0
$


-------------------------



Shamir On Salt by Example
=========================


# Let's generate some keys. Usually this is done by the individual members. 
# This produces the public keys on stdout.
$ mkdir keys
$ shamironsalt genkey -k keys/key1.kp
3829345cc40dee90031c886a9e2d579e9617fddf1077e23b5de8c5dff34de97a
$ shamironsalt genkey -k keys/key2.kp
3dedf218cca1139098f1f8df5564cebb2d8b080d202e9024b4bf010cdbcbde5d
$ shamironsalt genkey -k keys/key3.kp
9463ab9086e9aba4622f63c7d11886beb40ea07ccabede1e1e9f8f5eeeacb94d
$ shamironsalt genkey -k keys/key4.kp
4fec3c665bb28207267931fe5ae47e884dc62aeec182e6b8f7c9cdd3f3aa0f21
$ 

# Create a sharegroup definition which gives 2 shares and no fakes to each member:
$ for key in keys/* ; do echo $(shamironsalt genkey -d -k ${key}) 2 0 ; done > sharegroupdef.txt
$ 
$ cat sharegroupdef.txt 
3829345cc40dee90031c886a9e2d579e9617fddf1077e23b5de8c5dff34de97a 2 0
3dedf218cca1139098f1f8df5564cebb2d8b080d202e9024b4bf010cdbcbde5d 2 0
9463ab9086e9aba4622f63c7d11886beb40ea07ccabede1e1e9f8f5eeeacb94d 2 0
4fec3c665bb28207267931fe5ae47e884dc62aeec182e6b8f7c9cdd3f3aa0f21 2 0
$

# Share a secret between members of the share group. We set the threshold at 3. # while each member has 2 shares. That means that at least two members have to cooperate.
# shares.txt will then contain the encrypted shares. The file (or the relevant lines) are then given to the members
$ shamironsalt genshares -vvvvv -o shares.txt -r sharegroupdef.txt -t 3 -c "Keep this a secret at all cost!" -s "some secret you want to share" 
Recipient added: Pubkey:3829345cc40dee90031c886a9e2d579e9617fddf1077e23b5de8c5dff34de97a Shares: 2 Fake: false
Recipient added: Pubkey:3dedf218cca1139098f1f8df5564cebb2d8b080d202e9024b4bf010cdbcbde5d Shares: 2 Fake: false
Recipient added: Pubkey:9463ab9086e9aba4622f63c7d11886beb40ea07ccabede1e1e9f8f5eeeacb94d Shares: 2 Fake: false
Recipient added: Pubkey:4fec3c665bb28207267931fe5ae47e884dc62aeec182e6b8f7c9cdd3f3aa0f21 Shares: 2 Fake: false
Share group configuration:
	SecretShare: 0a6d9445ed051983dbf3ecddd44ade62e0655aebb5bd1202ca72a2bc381b723eea1d43a3d8ac7de75c0622e685f983d995570a85ca7405d3a8d8230aa232ea5d
	Comment: Keep this a secret at all cost!
	Members: 4
	Threshold: 3
	Max per Member: 2
	Shares: 8
	Fakes: 0
$

# For some reason we have to reconstruct the secret. For this a "share request" 
# needs to be generated for each member of the share group.
# Only members of the share group can construct such a request:
$ shamironsalt genrequest -o requests.txt -S shares.txt -i keys/key1.kp 
$
$ cat requests.txt
3dedf218cca1139098f1f8df5564cebb2d8b080d202e9024b4bf010cdbcbde5d 303130303030333030303 [...]
$
# The share requests are contained in requests.txt. The file (or the relevant lines) need to be made available to other share members now.

# We have received a share request. Let's see what it says:
$ shamironsalt respond -S shares.txt -r requests.txt -i keys/key2.kp -d -vvvv
Sender PubKey: 3829345cc40dee90031c886a9e2d579e9617fddf1077e23b5de8c5dff34de97a
My PubKey: 3dedf218cca1139098f1f8df5564cebb2d8b080d202e9024b4bf010cdbcbde5d
Share configuration:
	SecretShare ID: 0a6d9445ed051983dbf3ecddd44ade62e0655aebb5bd1202ca72a2bc381b723eea1d43a3d8ac7de75c0622e685f983d995570a85ca7405d3a8d8230aa232ea5d
	Comment: Keep this a secret at all cost!
	Shares: 2
	Fake available: false
$

# Ok, we are going to cooperate. Let's respond to the request. The response 
# ends up in response.txt, which has to be sent to the member requesting the shares.

$ shamironsalt respond -S shares.txt -r requests.txt -i keys/key2.kp -o response.txt  -vvvv
Sender PubKey: 3829345cc40dee90031c886a9e2d579e9617fddf1077e23b5de8c5dff34de97a
My PubKey: 3dedf218cca1139098f1f8df5564cebb2d8b080d202e9024b4bf010cdbcbde5d
Share configuration:
	SecretShare ID: 0a6d9445ed051983dbf3ecddd44ade62e0655aebb5bd1202ca72a2bc381b723eea1d43a3d8ac7de75c0622e685f983d995570a85ca7405d3a8d8230aa232ea5d
	Comment: Keep this a secret at all cost!
	Shares: 2
	Fake available: false
Response content:
	SecretShare ID: 0a6d9445ed051983dbf3ecddd44ade62e0655aebb5bd1202ca72a2bc381b723eea1d43a3d8ac7de75c0622e685f983d995570a85ca7405d3a8d8230aa232ea5d
	Shares: 2
$ 

# We have received multiple responses, let's add them to the same file:
$ cat response* > allresponses.txt

# Now let us recover the secret:
$ shamironsalt recover -S shares.txt -i keys/key1.kp -r allresponses.txt 
some secret you want to share
$ 

# Or, with some more verbose output:

$ shamironsalt recover -S shares.txt -i keys/key1.kp -r allresponses.txt -vvvv
My PubKey: 3829345cc40dee90031c886a9e2d579e9617fddf1077e23b5de8c5dff34de97a
Share configuration:
	SecretShare ID: 0a6d9445ed051983dbf3ecddd44ade62e0655aebb5bd1202ca72a2bc381b723eea1d43a3d8ac7de75c0622e685f983d995570a85ca7405d3a8d8230aa232ea5d
	Comment: Keep this a secret at all cost!
Adding responses:
	Added response 1
	Added response 2
	Added response 3
Recovery Parameters:
	Threshhold: 3
	Members participating: 4
	Shares available: 8
Recovered secret: some secret you want to share
$

# That's it!
