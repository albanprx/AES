#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <ctype.h>
#include "../include/AES.h"
#include "../include/more.h"

/**
 * @brief This function passes a text file to a string.
 *
 * @param content The final string.
 * @param filename The file to pass.
 * @return EXIT_FAILURE if the parser failed or EXIT_SUCCESS if all is good.
 */
int file_parser(char **content, const char *filename, long *file_length)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        printf("Failed to open the file for reading.\n");
        printf("Make sure the file is in the correct directory or you provided the correct path.\n");
        printf("Ensure they are in the form ./tests/<file_name>\n");
        return EXIT_FAILURE;
    }

    // Go to the end of the file to get its size.
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    if (file_size == -1)
    {
        printf("Failed to determine the file size.\n");
        fclose(file);
        return EXIT_FAILURE;
    }
    // Reset file cursor
    fseek(file, 0, SEEK_SET);

    // Allocate memory based on file size.
    *content = (char *)malloc((size_t)file_size + 1);

    if (*content == NULL)
    {
        printf("Memory allocation failed.\n");
        fclose(file);
        return EXIT_FAILURE;
    }
    // Read the contents of the file in the character string.
    size_t bytes_read = fread(*content, sizeof(char), (size_t)file_size, file);
    if (bytes_read != (size_t)file_size)
    {
        printf("Failed to read the entire file.\n");
        fclose(file);
        free(*content);
        return EXIT_FAILURE;
    }

    // Add end of string character.
    (*content)[bytes_read] = '\0';

    fclose(file);
    *file_length = file_size;
    return EXIT_SUCCESS;
}
/**
 * @brief This function checks if a character is a hexadecimal character.
 *
 * @params c a character.
 * @return true or false.
 */
bool is_hexadecimal(char c)
{
    return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f');
}

/**
 * @brief This function checks if the key and key size passed by user are correct.
 *
 * @params key The key passed by user.
 * @params key_lenght The lenght passed by user or by default lenght = 128.
 * @return EXIT_FAILURE if the key passer failed or EXIT_SUCCESS if all is well.
 */
int key_verif(char *key, int key_lenght)
{
    if (key_lenght != 128 && key_lenght != 192 && key_lenght != 256)
    {
        printf("The key size is invalid. Make sure the key is 128, 192, or 256 bits in length.\n");
        return EXIT_FAILURE;
    }
    int t = strlen(key);
    for (int i = 0; i < t; i++)
    {
        if (!is_hexadecimal(key[i]))
        {
            printf("Key contains invalid characters in hexadecimal.\n");
            printf("Using the correct size default key.\n");
            if (key_lenght == 128)
            {
                strcpy(key, DEFAULT_KEY_128);
            }
            else if (key_lenght == 192)
            {
                strcpy(key, DEFAULT_KEY_192);
            }
            else if (key_lenght == 256)
            {
                strcpy(key, DEFAULT_KEY_256);
            }
            return EXIT_SUCCESS;
        }
    }
    return EXIT_SUCCESS;
}

/**
 * @brief This function frees the memory allocated for the array of text blocks of unsigned char.
 *
 * @param blocks Pointer to the array of text blocks.
 * @param num_blocks The number of blocks in the array.
 */
void free_blocks(unsigned char **blocks, size_t num_blocks)
{
    if (blocks != NULL)
    {
        for (size_t i = 0; i < num_blocks; i++)
        {
            free(blocks[i]);
        }
        free(blocks);
    }
}

/**
 * @brief This function frees the memory allocated for the array of text blocks of char.
 *
 * @param blocks Pointer to the array of text blocks.
 * @param num_blocks The number of blocks in the array.
 */
void free_blocks2(char **blocks, size_t num_blocks)
{
    if (blocks != NULL)
    {
        for (size_t i = 0; i < num_blocks; i++)
        {
            free(blocks[i]);
        }
        free(blocks);
    }
}

/**
 * @brief This function splits the given text into blocks of 128 bits (16 bytes) each.
 *
 * @param text The text to be split into blocks.
 * @param text_length The length of the text.
 * @param blocks Pointer to store the array of block pointers.
 * @param num_blocks Pointer to store the number of blocks.
 * @return 0 on success, -1 on failure.
 */
int split_text_into_blocks(char *text, size_t text_length, unsigned char ***blocks, size_t *num_blocks)
{
    // Checks if the parameters passed are valid.
    if (text == NULL || text_length == 0 || blocks == NULL || num_blocks == NULL)
    {
        printf("Invalid parameters\n");
        return -1;
    }

    // Calculate the number of blocks needed.
    *num_blocks = text_length / BLOCK_SIZE;
    if (text_length % BLOCK_SIZE != 0)
    {
        (*num_blocks)++;
    }
    // Allocate memory for blocks.
    *blocks = (unsigned char **)malloc(*num_blocks * sizeof(unsigned char *));
    if (*blocks == NULL)
    {
        printf("Memory allocation failed for blocks\n");
        return -1;
    }

    // Break text into 128-bit blocks.
    for (size_t i = 0; i < *num_blocks; i++)
    {
        // Allocate memory for an individual block.
        (*blocks)[i] = (unsigned char *)malloc(BLOCK_SIZE);
        if ((*blocks)[i] == NULL)
        {
            printf("Memory allocation failed for block %zu\n", i);
            // If unsuccessful, free the previously allocated memory.
            for (size_t j = 0; j < i; j++)
            {
                free((*blocks)[j]);
            }
            free(*blocks);
            return -1;
        }

        // Copy text data into block.
        size_t bytes_to_copy = (i == *num_blocks - 1) ? (text_length - i * BLOCK_SIZE) : BLOCK_SIZE;
        memcpy((*blocks)[i], text + i * BLOCK_SIZE, bytes_to_copy);

        // Pad with zeros if necessary for the last block.
        if (bytes_to_copy < BLOCK_SIZE)
        {
            memset((*blocks)[i] + bytes_to_copy, 0, BLOCK_SIZE - bytes_to_copy);
        }
    }
    return 0;
}

/**
 * @brief This function concatenates a list of blocks into a single string.
 *
 * @param text The text to store the concatenated blocks.
 * @param text_length The length of the text.
 * @param blocks Array of block pointers.
 * @param num_blocks Number of blocks in the array.
 * @return 0 on success, -1 on failure.
 */
int concatenate_blocks(char *text, size_t *text_length, unsigned char ***blocks, size_t *num_blocks)
{
    // Calculate the total size of the resulting string.
    size_t total_size = *num_blocks * BLOCK_SIZE;
    // Concatenate the blocks into the resulting text.
    size_t temp = 0;
    for (size_t i = 0; i < *num_blocks; i++)
    {
        memcpy(text + temp, (*blocks)[i], BLOCK_SIZE);
        temp += BLOCK_SIZE;
    }

    // Add a null terminator at the end of the concatenated text.
    text[total_size] = '\0';
    *text_length = total_size;
    return 0;
}

/**
 * @brief This function writes a string to a file. If the file is not empty, it creates a new file.
 *
 * @param filename The name of the file to write to.
 * @param content The string to write to the file.
 * @param concatenated_text_length The length of the file.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int write_to_file(const char *filename, const char *content, size_t concatenated_text_length)
{
    FILE *file = fopen(filename, "r");
    if (file != NULL)
    {
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        fclose(file);
        if (file_size >= LONG_MAX)
        {
            printf("File %s is too large.\n", filename);
            return EXIT_FAILURE;
        }
        if (file_size == 0) // File is empty
        {
            file = fopen(filename, "w");
        }
        else // File is not empty
        {
            char new_filename[strlen(filename) + 5]; // "_new" + null terminator
            snprintf(new_filename, sizeof(new_filename), "%s_new", filename);
            file = fopen(new_filename, "w");
        }
    }
    else // File does not exist
    {
        file = fopen(filename, "w");
    }

    if (file == NULL)
    {
        printf("Failed to open the file %s for writing.\n", filename);
        return EXIT_FAILURE;
    }
    // Convert each character in content to its hexadecimal representation and write it to the file
    for (size_t i = 0; i < concatenated_text_length; i++)
    {
        fprintf(file, "%c", (unsigned char)content[i]); // Write two hexadecimal digits for each character
    }

    fclose(file);
    return EXIT_SUCCESS;
}

/**
 * @brief Displays the result of a function.
 *
 * @param result        Result of the function (0 for success, non-zero for failure).
 * @param function_name Name of the function.
 * @param blocks        Array of pointers to data blocks.
 * @param num_blocks    Number of data blocks.
 * @param verbose       Indicates if verbose mode is enabled.
 * @param debug         Indicates if debug mode is enabled.
 */
void affichage_result(int result, const char *function_name, unsigned char ***blocks, size_t *num_blocks, bool verbose, bool debug)
{
    if (result == 0)
    {
        // If the function succeeded and verbose mode is enabled, display a success message.
        if (verbose)
        {
            printf("%s successful.\n", function_name);
        }
        // If debug mode is enabled, display the data blocks.
        if (debug)
        {
            for (size_t i = 0; i < *num_blocks; i++)
            {
                printf("Block %zu: ", i + 1);
                for (size_t j = 0; j < BLOCK_SIZE; j++)
                {
                    printf("%02X ", (*blocks)[i][j]);
                    if ((j + 1) % 4 == 0)
                    {
                        printf(" ");
                    }
                }
                printf("\n");
            }
            for (size_t i = 0; i < *num_blocks; i++)
            {
                printf("Block %zu: ", i + 1);
                for (size_t j = 0; j < BLOCK_SIZE; j++)
                {
                    printf("%c", (*blocks)[i][j]);
                }
                printf("\n");
            }
        }
    }
    else
    {
        // If the function failed, display an error message and exit the program.
        fprintf(stderr, "%s failed.\n", function_name);
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Multiplies two polynomials in GF(2^8) with the given irreducible polynomial x^8 + x^4 + x^3 + x + 1.
 *
 * @param a First polynomial.
 * @param b Second polynomial.
 * @return unsigned char Result of the polynomial multiplication.
 */
unsigned char mult(unsigned char a, unsigned char b)
{
    unsigned char result = 0;             // Initialize the result of the multiplication
    unsigned char hi_bit_set;             // Variable to store the highest bit of 'a'
                                          // Perform polynomial multiplication using bitwise operations
    for (int i = 0; i < 8 && b != 0; i++) // Stop the loop when b becomes 0
    {
        // If the least significant bit of 'b' is set, XOR the result with 'a'
        if ((b & 1) == 1)
            result ^= a;

        // Check if the highest bit of 'a' is set
        hi_bit_set = (a & 0x80);

        // Left shift 'a' by one bit
        a <<= 1;

        // If the highest bit of 'a' was set before the shift, perform polynomial division with irreducible polynomial
        if (hi_bit_set == 0x80)
        {
            a ^= 0x1b; // Irreducible polynomial: x^8 + x^4 + x^3 + x + 1
        }

        // Right shift 'b' by one bit
        b >>= 1;
    }

    // Return the result of the polynomial multiplication
    return result;
}

/**
 * @brief Print the contents of the blocks.
 *
 * This function prints the contents of the blocks in hexadecimal format.
 *
 * @param blocks    The blocks to be printed.
 * @param num_blocks    The number of blocks.
 */
void printBlocks(unsigned char **blocks, size_t num_blocks)
{
    for (size_t i = 0; i < num_blocks; i++)
    {
        printf("Block %zu: ", i + 1);
        for (size_t j = 0; j < BLOCK_SIZE; j++)
        {
            printf("%02X ", blocks[i][j]);
        }
        printf("\n");
    }
}

/**
 * @brief This function checks if the vector and vector size passed by user are correct.
 *
 * @params vector_init The vector init passed by user.
 * @params vector_lenght The lenght passed by user or by default lenght = 128.
 * @return EXIT_FAILURE if the key passer failed or EXIT_SUCCESS if all is well.
 */
int vector_init_verif(char *vector_init, int vector_lenght)
{
    if (vector_lenght != 128)
    {
        printf("The vector size is invalid. Make sure the key is 128 bits in length.\n");
        return EXIT_FAILURE;
    }
    int t = strlen(vector_init);
    for (int i = 0; i < t; i++)
    {
        if (!is_hexadecimal(vector_init[i]))
        {
            printf("Key contains invalid characters in hexadecimal.\n");
            printf("Using the correct size default key.\n");
            if (vector_lenght == 128)
            {
                strcpy(vector_init, DEFAULT_VECTOR_128);
            }
            return EXIT_SUCCESS;
        }
    }
    return EXIT_SUCCESS;
}