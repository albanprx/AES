#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "../include/CFB.h"
#include "../include/AES.h"
#include "../include/more.h"

/**
 * @brief Encrypts data blocks using the CFB mode.
 *
 * @param key          Encryption key.
 * @param blocks       Array of pointers to data blocks to be encrypted.
 * @param num_blocks   Number of data blocks.
 * @param cipher       Array of pointers to store the encrypted blocks.
 * @param num_cipher   Number of encrypted blocks.
 * @param vector_init  The initialization vector for the mode.
 * @param Nr           Number of rounds.
 * @return int         Returns 0 on success, -1 on failure.
 */
int CFB_cipher(unsigned char **key, unsigned char **blocks, size_t num_blocks, unsigned char **cipher, size_t *num_cipher, size_t Nr, unsigned char *vector_init)
{
    // Set the number of encrypted blocks equal to the number of input blocks.
    *num_cipher = num_blocks;

    // Create a temporary storage for the current state (initialization vector initially)
    unsigned char current_state[BLOCK_SIZE];
    memcpy(current_state, vector_init, BLOCK_SIZE);

    // Encrypt each data block using the encryption key.
    for (size_t i = 0; i < num_blocks; i++)
    {
        // Encrypt the current state
        unsigned char encrypted_state[BLOCK_SIZE];
        AES_cipher(current_state, key, encrypted_state, Nr);

        // XOR the encrypted state with the plaintext block to produce the ciphertext block
        for (size_t j = 0; j < BLOCK_SIZE; j++)
        {
            cipher[i][j] = blocks[i][j] ^ encrypted_state[j];
        }

        // Update the current state with the ciphertext block
        memcpy(current_state, cipher[i], BLOCK_SIZE);
    }
    return 0;
}

/**
 * @brief Decrypts data blocks using the CFB mode.
 *
 * @param key          Encryption key.
 * @param blocks       Array of pointers to data blocks to be decrypted.
 * @param num_blocks   Number of data blocks.
 * @param cipher       Array of pointers to store the decrypted blocks.
 * @param num_cipher   Number of decrypted blocks.
 * @param vector_init  The initialization vector for the mode.
 * @param Nr           Number of rounds.
 * @return int         Returns 0 on success, -1 on failure.
 */
int CFB_decipher(unsigned char **key, unsigned char **blocks, size_t num_blocks, unsigned char **cipher, size_t *num_cipher, size_t Nr, unsigned char *vector_init)
{
    // Définir le nombre de blocs déchiffrés égal au nombre de blocs d'entrée.
    *num_cipher = num_blocks;

    // Créer un stockage temporaire pour l'état actuel (initialisation vector initialement)
    unsigned char current_state[BLOCK_SIZE];
    memcpy(current_state, vector_init, BLOCK_SIZE);

    // Déchiffrer chaque bloc de texte chiffré en utilisant la clé de chiffrement
    for (size_t i = 0; i < num_blocks; i++)
    {
        // Chiffrer l'état actuel
        unsigned char encrypted_state[BLOCK_SIZE];
        AES_cipher(current_state, key, encrypted_state, Nr);

        // XOR l'état chiffré avec le bloc de texte chiffré pour produire le bloc de texte clair
        for (size_t j = 0; j < BLOCK_SIZE; j++)
        {
            cipher[i][j] = blocks[i][j] ^ encrypted_state[j];
        }

        // Mettre à jour l'état actuel avec le bloc de texte chiffré
        memcpy(current_state, blocks[i], BLOCK_SIZE);
    }
    return 0;
}