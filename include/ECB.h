#ifndef ECB_H
#define ECB_H
#include "more.h"

int ECB_cipher(unsigned char **key, unsigned char **blocks, size_t num_blocks, unsigned char **cipher, size_t *num_cipher, size_t Nr);
int ECB_decipher(unsigned char **key, unsigned char **blocks, size_t num_blocks, unsigned char **cipher, size_t *num_cipher, size_t Nr);
#endif /* ECB_H */