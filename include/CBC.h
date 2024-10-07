#ifndef CBC_H
#define CBC_H
#include "more.h"

int CBC_cipher(unsigned char **key, unsigned char **blocks, size_t num_blocks, unsigned char **cipher, size_t *num_cipher, size_t Nr, unsigned char *vector_init);
int CBC_decipher(unsigned char **key, unsigned char **blocks, size_t num_blocks, unsigned char **cipher, size_t *num_cipher, size_t Nr, unsigned char *vector_init);

#endif /* CBC_H */