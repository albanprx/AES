#ifndef AES_H
#define AES_H
#include "more.h"
#include "ECB.h"
#include <stdint.h>

int subBytes(unsigned char *blocks);
int invsubBytes(unsigned char *blocks);
int shiftRows(unsigned char *blocks);
int invshiftRows(unsigned char *blocks);
int mixColumns(unsigned char **blocks, size_t num_blocks, char *mode);
int mixColumns2(unsigned char *blocks);
int invmixColumns2(unsigned char *blocks);
int addRoundKey(unsigned char *blocks, unsigned char *round_key);
void KeyExpansion(uint8_t *key, uint32_t *w, int nk, int num_round_keys);
uint8_t char_to_hex(char c);
void uint32_to_digits(uint32_t value, uint8_t *digits);
int getRoundKeys(uint32_t *expandedKey, int num_round_keys, unsigned char ***round_keys);
int AES_cipher(unsigned char *block, unsigned char **roundkey, unsigned char *cipher, size_t Nr);
int AES_decipher(unsigned char *block, unsigned char **roundkey, unsigned char *cipher, size_t Nr);
#endif /* AES_H */