#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "../include/ECB.h"
#include "../include/AES.h"
#include "../include/CBC.h"
#include "../include/more.h"

/**
 * @brief Encrypts data blocks using the CBC mode.
 *
 * @param key          Encryption key.
 * @param blocks       Array of pointers to data blocks to be encrypted.
 * @param num_blocks   Number of data blocks.
 * @param cipher       Array of pointers to store the encrypted blocks.
 * @param num_cipher   Number of encrypted blocks.
 * @param vector_init  The vector initialization for the mode.
 * @return int         Returns 0 on success, -1 on failure.
 */
int CBC_cipher(unsigned char **key, unsigned char **blocks, size_t num_blocks, unsigned char **cipher, size_t *num_cipher, size_t Nr, unsigned char *vector_init)
{
    // Set the number of encrypted blocks equal to the number of input blocks.
    *num_cipher = num_blocks;

    // Create a temporary storage for the previous ciphertext block
    unsigned char previous_cipher_block[BLOCK_SIZE];
    memcpy(previous_cipher_block, vector_init, BLOCK_SIZE);

    // Encrypt each data block using the encryption key.
    for (size_t i = 0; i < num_blocks; i++)
    {
        // XOR the current plaintext block with the previous ciphertext block
        for (size_t j = 0; j < BLOCK_SIZE; j++)
        {
            blocks[i][j] ^= previous_cipher_block[j];
        }

        // Encrypt the XORed block
        AES_cipher(blocks[i], key, cipher[i], Nr);

        // Update the previous ciphertext block with the current ciphertext block
        memcpy(previous_cipher_block, cipher[i], BLOCK_SIZE);
    }
    return 0;
}

/**
 * @brief Decrypts data blocks using the CBC mode.
 *
 * @param key          Encryption key.
 * @param blocks       Array of pointers to data blocks to be encrypted.
 * @param num_blocks   Number of data blocks.
 * @param cipher       Array of pointers to store the encrypted blocks.
 * @param num_cipher   Number of encrypted blocks.
 * @param vector_init  The vector initialization for the mode.
 * @return int         Returns 0 on success, -1 on failure.
 */
int CBC_decipher(unsigned char **key, unsigned char **blocks, size_t num_blocks, unsigned char **cipher, size_t *num_cipher, size_t Nr, unsigned char *vector_init)
{
    // Set the number of encrypted blocks equal to the number of input blocks.
    *num_cipher = num_blocks;

    // Create a temporary storage for the previous ciphertext block
    unsigned char previous_cipher_block[BLOCK_SIZE];
    memcpy(previous_cipher_block, vector_init, BLOCK_SIZE);

    // Decrypt each ciphertext block using the decryption key.
    for (size_t i = 0; i < num_blocks; i++)
    {
        // Save the current ciphertext block before decryption
        unsigned char temp_cipher_block[BLOCK_SIZE];
        memcpy(temp_cipher_block, blocks[i], BLOCK_SIZE);

        // Decrypt the ciphertext block
        AES_decipher(blocks[i], key, cipher[i], Nr);

        // XOR the decrypted block with the previous ciphertext block
        for (size_t j = 0; j < BLOCK_SIZE; j++)
        {
            cipher[i][j] ^= previous_cipher_block[j];
        }

        // Update the previous ciphertext block with the current ciphertext block
        memcpy(previous_cipher_block, temp_cipher_block, BLOCK_SIZE);
    }
    return 0;
}
