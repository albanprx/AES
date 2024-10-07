# Context 

This project is for educational purposes only. It is not intended for use in real-world cryptographic applications. Do not use this implementation for securing sensitive data.

# AES User Guide

This implementation of AES supports the encryption and decryption of files using 128, 192, or 256-bit keys. It provides several modes of operation such as ECB, CBC, and CFB. Please note that GCM mode is not included in this version due to time constraints.

# Command to Launch the Program

## Compilation

To compile the program we can use this command:

make

## Encryption and Decryption :

### To encrypt a file using the ECB mode and the default key :

./AES -i ./tests/alice.txt -m ECB -c

### To specify an output file for the encryption :

./AES -i ./tests/alice.txt -m ECB -c -o ./tests/alice_cipher_ECB.txt

### To decrypt the file :

./AES -i ./tests/alice_cipher_ECB.txt -m ECB -d

### To specify a custom key for encryption (replace <KEY> with your key) :

./AES -i ./tests/alice.txt -m ECB -c -k <KEY>

## Using other modes :

### To use CBC mode with a custom initialization vector (IV) :

./AES -i ./tests/alice.txt -m CBC -c -n <IV>

### To run multiple tests, such as encrypting a file 100 times :

./AES -i ./tests/alice.txt -m ECB -c -t 100

## Available Options :

-h, --help : Display help message.

-i, --input <file> : Specify the input file.

-m, --mode <mode> : Set the encryption mode (ECB, CBC, CFB).

-c, --encrypt : Encrypt the input file.

-d, --decrypt : Decrypt the input file.

-k, --key <key> : Set the encryption/decryption key.

-o, --output <file> : Write the result to the specified file.

-n, --init <IV> : Set the initialization vector (IV) for CBC and CFB modes.