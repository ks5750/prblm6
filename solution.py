#! /usr/bin/env python3
from nacl.exceptions import BadSignatureError
from nacl.public import PrivateKey, Box
from nacl.public import PublicKey
from nacl.signing import SigningKey
import sys
import json
from nacl.signing import VerifyKey


#
# with open(sys.argv[1]) as json_data:
#     inputs = json.load(json_data)
inputs = json.load(sys.stdin)
outputs = {}

# Problem 1
input_1 = bytes.fromhex(inputs["problem1"])
alice_public_key = PublicKey(input_1)  # their public key bytes go here

BobsPrivateKey = PrivateKey(b"A" * 32)
BobsPrivateKey.encode()
nonce=b"B" * 24
message = b"hello world"


ciphertext_alice = Box(
    BobsPrivateKey,
    alice_public_key,
).encrypt(message, nonce).ciphertext
# print("alice encrypts:", ciphertext_alice.hex())
outputs["problem1"] = ciphertext_alice.hex()



# Problem 2
input2_cypher= bytes.fromhex(inputs["problem2"])
bob_public_key = PublicKey(input_1)  # their public key bytes go here

privateK = PrivateKey(b"A" * 32)
privateK.encode()
nonce_2=b"C" * 24
message = b"hello world"


plantext_alice = Box(
    privateK,
    alice_public_key,
).decrypt(input2_cypher, nonce_2)
outputs["problem2"] = plantext_alice.decode()


# Problem 2
input2_cypher= bytes.fromhex(inputs["problem2"])
bob_public_key = PublicKey(input_1)  # their public key bytes go here

privateK = PrivateKey(b"A" * 32)
privateK.encode()
nonce_2=b"C" * 24
message = b"hello world"


plantext_alice = Box(
    privateK,
    alice_public_key,
).decrypt(input2_cypher, nonce_2)
outputs["problem2"] = plantext_alice.decode()

# Problem 3

outputs["problem3"] = Box(privateK, alice_public_key).encode().hex()


# Problem 4
input4_string= inputs["problem4"].encode()
privKey4 = SigningKey(b"D" * 32)
privKey4.encode()

signature = privKey4.sign(input4_string).signature

outputs["problem4"] = signature.hex()

# Problem 5
input5_array= inputs["problem5"]
signing_public_key=bytes.fromhex(input5_array["signing_public_key"])
signature=bytes.fromhex(input5_array["signature"])
candidates=input5_array["candidates"]

their_public_key = VerifyKey(signing_public_key)
their_public_key.encode()
for x in candidates:

    try:
        their_public_key.verify(x.encode(),signature)
    except BadSignatureError as e:
       continue
    outputs["problem5"] =x
    break


# Output
#
# In the video I wrote something more like `json.dump(outputs, sys.stdout)`.
# Either way works. This way adds some indentation and a trailing newline,
# which makes things look nicer in the terminal.
print(json.dumps(outputs, indent="  "))
