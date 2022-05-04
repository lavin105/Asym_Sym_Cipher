Brandon Lavinsky
brandon.lavinsky@wsu.edu

Files:

wsu-pub-crypt.cpp: engine for generating keys, encrypting, and decrypting messages using assymetric encryption.
Makefile: makefile to compile the source code.

Details:
Modulus is 32 bits
Block size is 31 bits

To Compile:

1. Run make
2. Observe the wsu-pub-crypt.o and wsu-pub-crypt executable file

To Run:

./wsu-pub-crypt -genkey (Generate key)
./wsu-pub-crypt -e -k pubkey.txt -in ptext.txt -out ctext.txt (To Encrypt)
./wsu-pub-crypt -d -k prikey.txt -in ctext.txt -out dtext.txt (To Decrypt)