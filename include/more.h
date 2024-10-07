#ifndef MORE_H
#define MORE_H
#define DEFAULT_KEY_128 "000102030405060708090a0b0c0d0e0f"
#define DEFAULT_KEY_192 "000102030405060708090a0b0c0d0e0f0001020304050607"
#define DEFAULT_KEY_256 "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
#define DEFAULT_VECTOR_128 "00000000000000000000000000000000"
#define BLOCK_SIZE 16 // 16 octets = 128 bits
#define AES_MAX_ROUND_KEYS 14

int file_parser(char **content, const char *filename, long *file_length);
bool is_hexadecimal(char c);
int key_verif(char *key, int key_lenght);
void free_blocks(unsigned char **blocks, size_t num_blocks);
void free_blocks2(char **blocks, size_t num_blocks);
int split_text_into_blocks(char *text, size_t text_length, unsigned char ***blocks, size_t *num_blocks);
int concatenate_blocks(char *text, size_t *text_length, unsigned char ***blocks, size_t *num_blocks);
int write_to_file(const char *filename, const char *content, size_t concatenated_text_length);
void affichage_result(int result, const char *function_name, unsigned char ***blocks, size_t *num_blocks, bool verbose, bool debug);
unsigned char mult(unsigned char a, unsigned char b);
void printBlocks(unsigned char **blocks, size_t num_blocks);
int vector_init_verif(char *vector_init, int vector_lenght);

#endif /* MORE_H */