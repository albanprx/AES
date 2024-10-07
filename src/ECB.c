#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include "../include/ECB.h"
#include "../include/AES.h"
#include "../include/more.h"

/**
 * @brief Encrypts data blocks using the ECB mode.
 *
 * @param key          Encryption key.
 * @param blocks       Array of pointers to data blocks to be encrypted.
 * @param num_blocks   Number of data blocks.
 * @param cipher       Array of pointers to store the encrypted blocks.
 * @param num_cipher   Number of encrypted blocks.
 * @return int         Returns 0 on success, -1 on failure.
 */
int ECB_cipher(unsigned char **key, unsigned char **blocks, size_t num_blocks, unsigned char **cipher, size_t *num_cipher, size_t Nr)
{
    // Set the number of encrypted blocks equal to the number of input blocks.
    *num_cipher = num_blocks;

    // Encrypt each data block using the encryption key.
    for (size_t i = 0; i < num_blocks; i++)
    {
        AES_cipher(blocks[i], key, cipher[i], Nr);
    }
    return 0;
}

/**
 * @brief Decrypts data blocks using the ECB mode.
 *
 * @param key          Encryption key.
 * @param blocks       Array of pointers to data blocks to be encrypted.
 * @param num_blocks   Number of data blocks.
 * @param cipher       Array of pointers to store the encrypted blocks.
 * @param num_cipher   Number of encrypted blocks.
 * @return int         Returns 0 on success, -1 on failure.
 */
int ECB_decipher(unsigned char **key, unsigned char **blocks, size_t num_blocks, unsigned char **cipher, size_t *num_cipher, size_t Nr)
{
    // Set the number of encrypted blocks equal to the number of input blocks.
    *num_cipher = num_blocks;

    // Encrypt each data block using the encryption key.
    for (size_t i = 0; i < num_blocks; i++)
    {
        AES_decipher(blocks[i], key, cipher[i], Nr);
    }
    return 0;
}