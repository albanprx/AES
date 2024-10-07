#ifndef CFB_H
#define CFB_H
#include "more.h"

int CFB_cipher(unsigned char **key, unsigned char **blocks, size_t num_blocks, unsigned char **cipher, size_t *num_cipher, size_t Nr, unsigned char *vector_init);
int CFB_decipher(unsigned char **key, unsigned char **blocks, size_t num_blocks, unsigned char **cipher, size_t *num_cipher, size_t Nr, unsigned char *vector_init);

#endif /* CFB_H */