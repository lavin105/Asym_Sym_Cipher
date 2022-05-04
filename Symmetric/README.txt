Brandon Lavinsky
brandon.lavinsky@wsu.edu

Files:
wsu-crypt.cpp - File that drives the entire program. Performs both encryption and decryption and all related file input/output operations.
Makefile - Makefile to compile the code.

To Compile:
1. Run make
2. Observe the wsu-crypt.o and wsu-crypt executable.

To Run:
For encryption: ./wsu-crypt -e -k key.txt -in plaintext.txt -out ciphertext.txt 
For decryption: ./wsu-crypt -d -k key.txt -in ciphertext.txt -out decrypted.txt 


Important Details:

1. For padding I used the ANSI X.923 scheme.
2. I removed the padded 0's before writing to the decrypted text file.
3. Encryption and decryption use ECB mode.

Interoperability:

I tested with Truc Duong's ciphertext and got the desired plaintext.
I tested with Thong Vu's ciphertext and got the desired plaintext.