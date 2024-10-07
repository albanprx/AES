#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>
#include "../include/AES.h"
#include "../include/ECB.h"
#include "../include/CBC.h"
#include "../include/CFB.h"
#include "../include/more.h"

void fhelp()
{
    printf("Usage: ./AES -i <file_name> -m <mode> [-d | -c] -k <key> [option]\n");
    printf("Options:\n");
    printf("  -i, --input <file_name>    Input file containing the text to be encrypted or decrypted.\n");
    printf("  -m, --mode <mode>          Encryption/Decryption mode (ECB, CBC, CFB).\n");
    printf("  -d, --decrypt              Decrypt the input text.\n");
    printf("  -c, --encrypt              Encrypt the input text.\n");
    printf("  -k, --key <key>            Encryption/Decryption key.\n");
    printf("  -o, --output <file_name>   Write the output to the specified file.\n");
    printf("  -v, --verbose              Verbose mode.\n");
    printf("  -b, --debug                Full Verbose mode, only for debug.\n");
    printf("  -t, --time <number>        The test program, add the number of times you want to perform the test.\n");
    printf("  -n, --init <init vector>   The initialization vector, then give it.\n");
    printf("  -h, --help                 Display this help message.\n");
}

// Implementation: S-Box

unsigned char sbox[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}; // F

unsigned char invsbox[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,  // 0
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,  // 1
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,  // 2
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,  // 3
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,  // 4
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,  // 5
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,  // 6
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,  // 7
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,  // 8
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,  // 9
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,  // A
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,  // B
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,  // C
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,  // D
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,  // E
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}; // F

unsigned char gf_mul_by_2[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
    0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
    0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
    0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
    0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
    0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
    0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
    0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
    0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
    0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
    0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
    0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
    0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
    0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
    0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
    0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5};

unsigned char gf_mul_by_3[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11,
    0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21,
    0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
    0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42, 0x41,
    0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9, 0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1,
    0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
    0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd, 0xb4, 0xb7, 0xb2, 0xb1,
    0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99, 0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81,
    0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a,
    0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6, 0xbf, 0xbc, 0xb9, 0xba,
    0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2, 0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea,
    0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda,
    0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4f, 0x4c, 0x49, 0x4a,
    0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a,
    0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a,
    0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a};

unsigned char gf_mul_by_9[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x41, 0x5a, 0x53, 0x6c, 0x65, 0x7e, 0x77,
    0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf, 0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7,
    0x3b, 0x32, 0x29, 0x20, 0x1f, 0x16, 0x0d, 0x04, 0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c,
    0xab, 0xa2, 0xb9, 0xb0, 0x8f, 0x86, 0x9d, 0x94, 0xe3, 0xea, 0xf1, 0xf8, 0xc7, 0xce, 0xd5, 0xdc,
    0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49, 0x3e, 0x37, 0x2c, 0x25, 0x1a, 0x13, 0x08, 0x01,
    0xe6, 0xef, 0xf4, 0xfd, 0xc2, 0xcb, 0xd0, 0xd9, 0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98, 0x91,
    0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72, 0x05, 0x0c, 0x17, 0x1e, 0x21, 0x28, 0x33, 0x3a,
    0xdd, 0xd4, 0xcf, 0xc6, 0xf9, 0xf0, 0xeb, 0xe2, 0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa,
    0xec, 0xe5, 0xfe, 0xf7, 0xc8, 0xc1, 0xda, 0xd3, 0xa4, 0xad, 0xb6, 0xbf, 0x80, 0x89, 0x92, 0x9b,
    0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a, 0x43, 0x34, 0x3d, 0x26, 0x2f, 0x10, 0x19, 0x02, 0x0b,
    0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8, 0x9f, 0x96, 0x8d, 0x84, 0xbb, 0xb2, 0xa9, 0xa0,
    0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6a, 0x71, 0x78, 0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22, 0x39, 0x30,
    0x9a, 0x93, 0x88, 0x81, 0xbe, 0xb7, 0xac, 0xa5, 0xd2, 0xdb, 0xc0, 0xc9, 0xf6, 0xff, 0xe4, 0xed,
    0x0a, 0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35, 0x42, 0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d,
    0xa1, 0xa8, 0xb3, 0xba, 0x85, 0x8c, 0x97, 0x9e, 0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf, 0xd6,
    0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07, 0x0e, 0x79, 0x70, 0x6b, 0x62, 0x5d, 0x54, 0x4f, 0x46};

unsigned char gf_mul_by_11[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a, 0x31, 0x58, 0x53, 0x4e, 0x45, 0x74, 0x7f, 0x62, 0x69,
    0xb0, 0xbb, 0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81, 0xe8, 0xe3, 0xfe, 0xf5, 0xc4, 0xcf, 0xd2, 0xd9,
    0x7b, 0x70, 0x6d, 0x66, 0x57, 0x5c, 0x41, 0x4a, 0x23, 0x28, 0x35, 0x3e, 0x0f, 0x04, 0x19, 0x12,
    0xcb, 0xc0, 0xdd, 0xd6, 0xe7, 0xec, 0xf1, 0xfa, 0x93, 0x98, 0x85, 0x8e, 0xbf, 0xb4, 0xa9, 0xa2,
    0xf6, 0xfd, 0xe0, 0xeb, 0xda, 0xd1, 0xcc, 0xc7, 0xae, 0xa5, 0xb8, 0xb3, 0x82, 0x89, 0x94, 0x9f,
    0x46, 0x4d, 0x50, 0x5b, 0x6a, 0x61, 0x7c, 0x77, 0x1e, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2f,
    0x8d, 0x86, 0x9b, 0x90, 0xa1, 0xaa, 0xb7, 0xbc, 0xd5, 0xde, 0xc3, 0xc8, 0xf9, 0xf2, 0xef, 0xe4,
    0x3d, 0x36, 0x2b, 0x20, 0x11, 0x1a, 0x07, 0x0c, 0x65, 0x6e, 0x73, 0x78, 0x49, 0x42, 0x5f, 0x54,
    0xf7, 0xfc, 0xe1, 0xea, 0xdb, 0xd0, 0xcd, 0xc6, 0xaf, 0xa4, 0xb9, 0xb2, 0x83, 0x88, 0x95, 0x9e,
    0x47, 0x4c, 0x51, 0x5a, 0x6b, 0x60, 0x7d, 0x76, 0x1f, 0x14, 0x09, 0x02, 0x33, 0x38, 0x25, 0x2e,
    0x8c, 0x87, 0x9a, 0x91, 0xa0, 0xab, 0xb6, 0xbd, 0xd4, 0xdf, 0xc2, 0xc9, 0xf8, 0xf3, 0xee, 0xe5,
    0x3c, 0x37, 0x2a, 0x21, 0x10, 0x1b, 0x06, 0x0d, 0x64, 0x6f, 0x72, 0x79, 0x48, 0x43, 0x5e, 0x55,
    0x01, 0x0a, 0x17, 0x1c, 0x2d, 0x26, 0x3b, 0x30, 0x59, 0x52, 0x4f, 0x44, 0x75, 0x7e, 0x63, 0x68,
    0xb1, 0xba, 0xa7, 0xac, 0x9d, 0x96, 0x8b, 0x80, 0xe9, 0xe2, 0xff, 0xf4, 0xc5, 0xce, 0xd3, 0xd8,
    0x7a, 0x71, 0x6c, 0x67, 0x56, 0x5d, 0x40, 0x4b, 0x22, 0x29, 0x34, 0x3f, 0x0e, 0x05, 0x18, 0x13,
    0xca, 0xc1, 0xdc, 0xd7, 0xe6, 0xed, 0xf0, 0xfb, 0x92, 0x99, 0x84, 0x8f, 0xbe, 0xb5, 0xa8, 0xa3};

unsigned char gf_mul_by_13[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23, 0x68, 0x65, 0x72, 0x7f, 0x5c, 0x51, 0x46, 0x4b,
    0xd0, 0xdd, 0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3, 0xb8, 0xb5, 0xa2, 0xaf, 0x8c, 0x81, 0x96, 0x9b,
    0xbb, 0xb6, 0xa1, 0xac, 0x8f, 0x82, 0x95, 0x98, 0xd3, 0xde, 0xc9, 0xc4, 0xe7, 0xea, 0xfd, 0xf0,
    0x6b, 0x66, 0x71, 0x7c, 0x5f, 0x52, 0x45, 0x48, 0x03, 0x0e, 0x19, 0x14, 0x37, 0x3a, 0x2d, 0x20,
    0x6d, 0x60, 0x77, 0x7a, 0x59, 0x54, 0x43, 0x4e, 0x05, 0x08, 0x1f, 0x12, 0x31, 0x3c, 0x2b, 0x26,
    0xbd, 0xb0, 0xa7, 0xaa, 0x89, 0x84, 0x93, 0x9e, 0xd5, 0xd8, 0xcf, 0xc2, 0xe1, 0xec, 0xfb, 0xf6,
    0xd6, 0xdb, 0xcc, 0xc1, 0xe2, 0xef, 0xf8, 0xf5, 0xbe, 0xb3, 0xa4, 0xa9, 0x8a, 0x87, 0x90, 0x9d,
    0x06, 0x0b, 0x1c, 0x11, 0x32, 0x3f, 0x28, 0x25, 0x6e, 0x63, 0x74, 0x79, 0x5a, 0x57, 0x40, 0x4d,
    0xda, 0xd7, 0xc0, 0xcd, 0xee, 0xe3, 0xf4, 0xf9, 0xb2, 0xbf, 0xa8, 0xa5, 0x86, 0x8b, 0x9c, 0x91,
    0x0a, 0x07, 0x10, 0x1d, 0x3e, 0x33, 0x24, 0x29, 0x62, 0x6f, 0x78, 0x75, 0x56, 0x5b, 0x4c, 0x41,
    0x61, 0x6c, 0x7b, 0x76, 0x55, 0x58, 0x4f, 0x42, 0x09, 0x04, 0x13, 0x1e, 0x3d, 0x30, 0x27, 0x2a,
    0xb1, 0xbc, 0xab, 0xa6, 0x85, 0x88, 0x9f, 0x92, 0xd9, 0xd4, 0xc3, 0xce, 0xed, 0xe0, 0xf7, 0xfa,
    0xb7, 0xba, 0xad, 0xa0, 0x83, 0x8e, 0x99, 0x94, 0xdf, 0xd2, 0xc5, 0xc8, 0xeb, 0xe6, 0xf1, 0xfc,
    0x67, 0x6a, 0x7d, 0x70, 0x53, 0x5e, 0x49, 0x44, 0x0f, 0x02, 0x15, 0x18, 0x3b, 0x36, 0x21, 0x2c,
    0x0c, 0x01, 0x16, 0x1b, 0x38, 0x35, 0x22, 0x2f, 0x64, 0x69, 0x7e, 0x73, 0x50, 0x5d, 0x4a, 0x47,
    0xdc, 0xd1, 0xc6, 0xcb, 0xe8, 0xe5, 0xf2, 0xff, 0xb4, 0xb9, 0xae, 0xa3, 0x80, 0x8d, 0x9a, 0x97};

unsigned char gf_mul_by_14[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a, 0x70, 0x7e, 0x6c, 0x62, 0x48, 0x46, 0x54, 0x5a,
    0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca, 0x90, 0x9e, 0x8c, 0x82, 0xa8, 0xa6, 0xb4, 0xba,
    0xdb, 0xd5, 0xc7, 0xc9, 0xe3, 0xed, 0xff, 0xf1, 0xab, 0xa5, 0xb7, 0xb9, 0x93, 0x9d, 0x8f, 0x81,
    0x3b, 0x35, 0x27, 0x29, 0x03, 0x0d, 0x1f, 0x11, 0x4b, 0x45, 0x57, 0x59, 0x73, 0x7d, 0x6f, 0x61,
    0xad, 0xa3, 0xb1, 0xbf, 0x95, 0x9b, 0x89, 0x87, 0xdd, 0xd3, 0xc1, 0xcf, 0xe5, 0xeb, 0xf9, 0xf7,
    0x4d, 0x43, 0x51, 0x5f, 0x75, 0x7b, 0x69, 0x67, 0x3d, 0x33, 0x21, 0x2f, 0x05, 0x0b, 0x19, 0x17,
    0x76, 0x78, 0x6a, 0x64, 0x4e, 0x40, 0x52, 0x5c, 0x06, 0x08, 0x1a, 0x14, 0x3e, 0x30, 0x22, 0x2c,
    0x96, 0x98, 0x8a, 0x84, 0xae, 0xa0, 0xb2, 0xbc, 0xe6, 0xe8, 0xfa, 0xf4, 0xde, 0xd0, 0xc2, 0xcc,
    0x41, 0x4f, 0x5d, 0x53, 0x79, 0x77, 0x65, 0x6b, 0x31, 0x3f, 0x2d, 0x23, 0x09, 0x07, 0x15, 0x1b,
    0xa1, 0xaf, 0xbd, 0xb3, 0x99, 0x97, 0x85, 0x8b, 0xd1, 0xdf, 0xcd, 0xc3, 0xe9, 0xe7, 0xf5, 0xfb,
    0x9a, 0x94, 0x86, 0x88, 0xa2, 0xac, 0xbe, 0xb0, 0xea, 0xe4, 0xf6, 0xf8, 0xd2, 0xdc, 0xce, 0xc0,
    0x7a, 0x74, 0x66, 0x68, 0x42, 0x4c, 0x5e, 0x50, 0x0a, 0x04, 0x16, 0x18, 0x32, 0x3c, 0x2e, 0x20,
    0xec, 0xe2, 0xf0, 0xfe, 0xd4, 0xda, 0xc8, 0xc6, 0x9c, 0x92, 0x80, 0x8e, 0xa4, 0xaa, 0xb8, 0xb6,
    0x0c, 0x02, 0x10, 0x1e, 0x34, 0x3a, 0x28, 0x26, 0x7c, 0x72, 0x60, 0x6e, 0x44, 0x4a, 0x58, 0x56,
    0x37, 0x39, 0x2b, 0x25, 0x0f, 0x01, 0x13, 0x1d, 0x47, 0x49, 0x5b, 0x55, 0x7f, 0x71, 0x63, 0x6d,
    0xd7, 0xd9, 0xcb, 0xc5, 0xef, 0xe1, 0xf3, 0xfd, 0xa7, 0xa9, 0xbb, 0xb5, 0x9f, 0x91, 0x83, 0x8d};

/**
 * @brief Substitutes bytes in the data blocks using the S-box.
 *
 * @param blocks      Array of pointers to data blocks.
 * @return            0 if successful.
 */
int subBytes(unsigned char *blocks)
{
    // Iterate over each byte in the block
    for (size_t j = 0; j < BLOCK_SIZE; j++)
    {
        // Substitute the byte using the S-box
        blocks[j] = sbox[blocks[j]];
    }
    return 0; // Return success
}

/**
 * @brief Substitutes bytes in the data blocks using the S-box inverse.
 *
 * @param blocks      Array of pointers to data blocks.
 * @return            0 if successful.
 */
int invsubBytes(unsigned char *blocks)
{
    // Iterate over each byte in the block
    for (size_t j = 0; j < BLOCK_SIZE; j++)
    {
        // Substitute the byte using the S-box
        blocks[j] = invsbox[blocks[j]];
    }
    return 0; // Return success
}

/**
 * @brief Shifts the rows of the blocks according to the AES specification.
 * For encryption, the function shifts the rows to the left.
 *
 * @param blocks     Array of pointers to data blocks.
 *
 * @return int       0 if successful.
 */
int shiftRows(unsigned char *blocks)
{
    unsigned char temp;
    // Row 1: no shift
    // Row 2: shift one position to the left
    temp = blocks[1];
    blocks[1] = blocks[5];
    blocks[5] = blocks[9];
    blocks[9] = blocks[13];
    blocks[13] = temp;
    // Row 3: shift two positions to the left
    temp = blocks[2];
    blocks[2] = blocks[10];
    blocks[10] = temp;
    temp = blocks[6];
    blocks[6] = blocks[14];
    blocks[14] = temp;
    // Row 4: shift three positions to the left
    temp = blocks[3];
    blocks[3] = blocks[15];
    blocks[15] = blocks[11];
    blocks[11] = blocks[7];
    blocks[7] = temp;
    return 0; // Return success
}

/**
 * @brief Shifts the rows of the blocks according to the AES specification.
 * For decryption, the function shifts the rows to the right.
 *
 * @param blocks     Array of pointers to data blocks.
 *
 * @return int       0 if successful.
 */
int invshiftRows(unsigned char *blocks)
{
    unsigned char temp;
    // Row 1: no shift
    // Row 2: shift one position to the right
    temp = blocks[13];
    blocks[13] = blocks[9];
    blocks[9] = blocks[5];
    blocks[5] = blocks[1];
    blocks[1] = temp;
    // Row 3: shift two positions to the right
    temp = blocks[2];
    blocks[2] = blocks[10];
    blocks[10] = temp;
    temp = blocks[6];
    blocks[6] = blocks[14];
    blocks[14] = temp;
    // Row 4: shift three positions to the right
    temp = blocks[3];
    blocks[3] = blocks[7];
    blocks[7] = blocks[11];
    blocks[11] = blocks[15];
    blocks[15] = temp;

    return 0; // Return success
}

/**
 * @brief Applies the MixColumns operation to the blocks according to the AES specification.
 *
 * @param blocks     Array of pointers to data blocks.
 * @param num_blocks Number of data blocks.
 * @param mode       Mode specifier ('c' for encryption, 'd' for decryption).
 *                   For encryption, the function applies MixColumns transformation.
 *                   For decryption, the function applies inverse MixColumns transformation.
 * @return int       0 if successful, -1 if an invalid mode is specified.
 */
int mixColumns(unsigned char **blocks, size_t num_blocks, char *mode)
{
    if (strcmp(mode, "c") == 0) // Check if mode is 'c'
    {
        // Iterate over each data block
        for (size_t i = 0; i < num_blocks; i++)
        {
            // Iterate over each column in the block (4 columns)
            for (size_t j = 0; j < 4; j++)
            {
                // Retrieve the values of column j
                unsigned char a = blocks[i][j * 4];
                unsigned char b = blocks[i][1 + j * 4];
                unsigned char c = blocks[i][2 + j * 4];
                unsigned char d = blocks[i][3 + j * 4];

                // MixColumns operations for encryption
                blocks[i][j * 4] = mult(0x02, a) ^ mult(0x03, b) ^ c ^ d;
                blocks[i][1 + j * 4] = a ^ mult(0x02, b) ^ mult(0x03, c) ^ d;
                blocks[i][2 + j * 4] = a ^ b ^ mult(0x02, c) ^ mult(0x03, d);
                blocks[i][3 + j * 4] = mult(0x03, a) ^ b ^ c ^ mult(0x02, d);
            }
        }
    }
    else if (strcmp(mode, "d") == 0) // If mode is decryption
    {
        // Iterate over each data block
        for (size_t i = 0; i < num_blocks; i++)
        {
            // Iterate over each column in the block (4 columns)
            for (size_t j = 0; j < 4; j++)
            {
                // Retrieve the values of column j
                unsigned char a = blocks[i][j * 4];
                unsigned char b = blocks[i][1 + 4 * j];
                unsigned char c = blocks[i][2 + 4 * j];
                unsigned char d = blocks[i][3 + 4 * j];

                // MixColumns operations for decryption
                blocks[i][4 * j] = mult(0x0e, a) ^ mult(0x0b, b) ^ mult(0x0d, c) ^ mult(0x09, d);
                blocks[i][1 + 4 * j] = mult(0x09, a) ^ mult(0x0e, b) ^ mult(0x0b, c) ^ mult(0x0d, d);
                blocks[i][2 + 4 * j] = mult(0x0d, a) ^ mult(0x09, b) ^ mult(0x0e, c) ^ mult(0x0b, d);
                blocks[i][3 + 4 * j] = mult(0x0b, a) ^ mult(0x0d, b) ^ mult(0x09, c) ^ mult(0x0e, d);
            }
        }
    }
    else // Mode is neither 'c' nor 'd', return failure
    {
        fprintf(stderr, "Invalid mode specified.\n");
        return -1;
    }
    return 0; // Return success
}

/**
 * @brief Applies the MixColumns operation to the blocks according to the AES specification.
 * For encryption, the function applies MixColumns transformation.
 *
 * @param blocks     Array of pointers to data blocks.
 *
 * @return int       0 if successful.
 */
int mixColumns2(unsigned char *blocks)
{
    // Iterate over each column in the block (4 columns)
    for (size_t j = 0; j < 4; j++)
    {
        // Retrieve the values of column j
        unsigned char a = blocks[j * 4];
        unsigned char b = blocks[1 + j * 4];
        unsigned char c = blocks[2 + j * 4];
        unsigned char d = blocks[3 + j * 4];

        // MixColumns operations for encryption
        blocks[j * 4] = gf_mul_by_2[a] ^ gf_mul_by_3[b] ^ c ^ d;
        blocks[1 + j * 4] = a ^ gf_mul_by_2[b] ^ gf_mul_by_3[c] ^ d;
        blocks[2 + j * 4] = a ^ b ^ gf_mul_by_2[c] ^ gf_mul_by_3[d];
        blocks[3 + j * 4] = gf_mul_by_3[a] ^ b ^ c ^ gf_mul_by_2[d];
    }
    return 0; // Return success
}

/**
 * @brief Applies the MixColumns operation to the blocks according to the AES specification.
 * For decryption, the function applies inverse MixColumns transformation.
 *
 * @param blocks     Array of pointers to data blocks.
 *
 * @return int       0 if successful, -1 if an invalid mode is specified.
 */
int invmixColumns2(unsigned char *blocks)
{
    // Iterate over each column in the block (4 columns)
    for (size_t j = 0; j < 4; j++)
    {
        // Retrieve the values of column j
        unsigned char a = blocks[j * 4];
        unsigned char b = blocks[1 + 4 * j];
        unsigned char c = blocks[2 + 4 * j];
        unsigned char d = blocks[3 + 4 * j];

        // MixColumns operations for decryption
        blocks[4 * j] = gf_mul_by_14[a] ^ gf_mul_by_11[b] ^ gf_mul_by_13[c] ^ gf_mul_by_9[d];
        blocks[1 + 4 * j] = gf_mul_by_9[a] ^ gf_mul_by_14[b] ^ gf_mul_by_11[c] ^ gf_mul_by_13[d];
        blocks[2 + 4 * j] = gf_mul_by_13[a] ^ gf_mul_by_9[b] ^ gf_mul_by_14[c] ^ gf_mul_by_11[d];
        blocks[3 + 4 * j] = gf_mul_by_11[a] ^ gf_mul_by_13[b] ^ gf_mul_by_9[c] ^ gf_mul_by_14[d];
    }
    return 0; // Return success
}

/**
 * @brief Applies the AddRoundKey operation to the blocks according to the AES specification.
 *
 * @param blocks     Array of pointers to data blocks.
 * @param round_key  Round key to be XORed with the blocks.
 * @return int       0 if successful.
 */
int addRoundKey(unsigned char *blocks, unsigned char *round_key)
{
    // Iterate over each byte in the block
    for (size_t j = 0; j < 16; j++)
    {
        // XOR each byte of the block with the corresponding byte of the round key
        blocks[j] ^= round_key[j];
    }
    // Return success
    return 0;
}

// Round constant array
static const uint8_t Rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// SubBytes transformation
static void SubBytes(uint8_t *word)
{
    for (int i = 0; i < 4; ++i)
    {
        word[i] = sbox[word[i]];
    }
}

// RotWord transformation
static void RotWord(uint8_t *word)
{
    uint8_t temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

/**
 * @brief Convert a hexadecimal character to its corresponding numeric value.
 *
 * @param c The hexadecimal character.
 * @return The numeric value of the hexadecimal character.
 */
uint8_t char_to_hex(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    else if (c >= 'A' && c <= 'F')
    {
        return 10 + (c - 'A');
    }
    else if (c >= 'a' && c <= 'f')
    {
        return 10 + (c - 'a');
    }
    else
    {
        fprintf(stderr, "Invalid hexadecimal character: %c\n", c);
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Key expansion function.
 *
 * Expands the initial key into a key schedule for AES encryption.
 *
 * @param key The initial key.
 * @param w   Array to store the generated round keys.
 */
void KeyExpansion(uint8_t *key, uint32_t *w, int nk, int num_round_keys)
{
    uint8_t temp[nk];

    // Copy the initial key
    for (int i = 0; i < nk; ++i)
    {
        w[i] = (char_to_hex(key[8 * i]) << 28) | (char_to_hex(key[8 * i + 1]) << 24) |
               (char_to_hex(key[8 * i + 2]) << 20) | (char_to_hex(key[8 * i + 3]) << 16) |
               (char_to_hex(key[8 * i + 4]) << 12) | (char_to_hex(key[8 * i + 5]) << 8) |
               (char_to_hex(key[8 * i + 6]) << 4) | char_to_hex(key[8 * i + 7]);
    }
    for (int i = nk; i < (num_round_keys + 1) * 4; ++i)
    {
        temp[0] = w[i - 1] >> 24;
        temp[1] = w[i - 1] >> 16;
        temp[2] = w[i - 1] >> 8;
        temp[3] = w[i - 1];
        if (i % nk == 0)
        {
            RotWord(temp);
            SubBytes(temp);
            temp[0] ^= Rcon[i / nk - 1];
        }
        else if (nk > 6 && i % nk == 4)
        {
            SubBytes(temp);
        }

        w[i] = w[i - nk] ^ (temp[0] << 24) ^ (temp[1] << 16) ^ (temp[2] << 8) ^ temp[3];
    }
}

/**
 * @brief Convert a 32-bit integer to an array of 8-bit digits.
 *
 * This function takes a 32-bit integer value and splits it into 8-bit digits,
 * storing each digit in an array of 8 elements.
 *
 * @param value     The 32-bit integer value to be converted.
 * @param digits    The array to store the resulting 8-bit digits.
 */
void uint32_to_digits(uint32_t value, uint8_t *digits)
{
    digits[0] = (value >> 28) & 0x0F;
    digits[1] = (value >> 24) & 0x0F;
    digits[2] = (value >> 20) & 0x0F;
    digits[3] = (value >> 16) & 0x0F;
    digits[4] = (value >> 12) & 0x0F;
    digits[5] = (value >> 8) & 0x0F;
    digits[6] = (value >> 4) & 0x0F;
    digits[7] = value & 0x0F;
}

/**
 * @brief Generate round keys from the expanded main key.
 *
 * This function generates round keys from the expanded main key. It allocates
 * memory for the round keys and fills each round key by extracting the
 * appropriate bytes from the expanded main key.
 *
 * @param expandedKey   The expanded main key.
 * @param num_round_keys    The number of round keys to generate.
 * @param round_keys    Pointer to the array of pointers where the round keys will be stored.
 * @return 0 on success, -1 on failure.
 */
int getRoundKeys(uint32_t *expandedKey, int num_round_keys, unsigned char ***round_keys)
{
    // Allocate memory for blocks.
    *round_keys = (unsigned char **)malloc(num_round_keys * sizeof(unsigned char *));
    if (*round_keys == NULL)
    {
        printf("Memory allocation failed for round key array\n");
        return -1;
    }
    // Copie round key
    int incre = 0;
    for (int i = 0; i < num_round_keys; i++)
    {
        // Allocate memory for an individual block.
        (*round_keys)[i] = (unsigned char *)malloc(BLOCK_SIZE * 2);
        if ((*round_keys)[i] == NULL)
        {
            printf("Memory allocation failed for round key %u\n", i);
            // If unsuccessful, free the previously allocated memory.
            for (int j = 0; j < i; j++)
            {
                free((*round_keys)[j]);
            }
            free(*round_keys);
            return -1;
        }
        int temp = 0;
        for (int k = 0; k < 4; k++)
        {
            uint8_t digits[8];
            uint32_to_digits(expandedKey[incre], digits);
            for (int j = 0; j < 8; j += 2)
            {
                (*round_keys)[i][temp] = (digits[j] << 4) | digits[j + 1];
                temp++;
            }
            incre++;
        }
    }
    return 0;
}

/**
 * @brief Perform one round of AES encryption on the given blocks.
 *
 * This function performs one round of AES encryption on the provided blocks
 * using the specified mode and round key.
 *
 * @param block     The block to be encrypted.
 * @param roundkey  The round key used for encryption.
 * @param cipher    The resulting encrypted block.
 * @param Nr        The total number of rounds.
 * @return 0 on success, -1 on failure.
 */
int AES_cipher(unsigned char *block, unsigned char **roundkey, unsigned char *cipher, size_t Nr)
{
    // Copy the ieme blocks of blocks in cipher
    memcpy(cipher, block, BLOCK_SIZE);
    addRoundKey(cipher, roundkey[0]);
    for (size_t i = 1; i < Nr - 1; i++)
    {
        subBytes(cipher);
        shiftRows(cipher);
        mixColumns2(cipher);
        addRoundKey(cipher, roundkey[i]);
    }
    subBytes(cipher);
    shiftRows(cipher);
    addRoundKey(cipher, roundkey[Nr - 1]);
    return 0;
}

/**
 * @brief Perform one round of AES decryption on the given blocks.
 *
 * This function performs one round of AES decryption on the provided blocks
 * using the specified mode and round key.
 *
 * @param block     The block to be decrypted.
 * @param roundkey  The round key used for decryption.
 * @param cipher    The resulting decrypted block.
 * @param number    The number of blocks.
 * @param Nr        The total number of rounds.
 * @return 0 on success, -1 on failure.
 */
int AES_decipher(unsigned char *block, unsigned char **roundkey, unsigned char *cipher, size_t Nr)
{
    // Copy the ieme blocks of blocks in cipher
    memcpy(cipher, block, BLOCK_SIZE);
    addRoundKey(cipher, roundkey[Nr - 1]);
    for (size_t i = Nr - 2; i > 0; i--)
    {
        invshiftRows(cipher);
        invsubBytes(cipher);
        addRoundKey(cipher, roundkey[i]);
        invmixColumns2(cipher);
    }
    invshiftRows(cipher);
    invsubBytes(cipher);
    addRoundKey(cipher, roundkey[0]);
    return 0;
}

int main(int argc, char *argv[])
{
    clock_t start, end;
    double cpu_time_used;

    // Declaration of variables
    int opt = 0;
    long ffile_length = 100;
    long *file_length = &ffile_length;
    char *input_file = NULL;
    char *output_file = NULL;
    bool output_specified = false;
    char *mode = NULL;
    char *key = NULL;
    char *vector_init = NULL;
    bool encrypt = false;
    bool decrypt = false;
    bool verbose = false;
    bool debug = false;
    bool time_flag = false;
    int t = 1;

    const char *const short_opts = "i:m:k:o:cdvbht:n:";
    const struct option long_opts[] = {
        {"input", required_argument, 0, 'i'},
        {"mode", required_argument, 0, 'm'},
        {"key", required_argument, 0, 'k'},
        {"output", required_argument, 0, 'o'},
        {"encrypt", no_argument, 0, 'c'},
        {"decrypt", no_argument, 0, 'd'},
        {"verbose", no_argument, 0, 'v'},
        {"debug", no_argument, 0, 'b'},
        {"time", required_argument, 0, 't'},
        {"init", required_argument, 0, 'n'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'i':
            input_file = optarg;
            break;
        case 'm':
            mode = optarg;
            break;
        case 'k':
            key = optarg;
            break;
        case 'o':
            output_file = optarg;
            output_specified = true;
            break;
        case 'c':
            encrypt = true;
            break;
        case 'd':
            decrypt = true;
            break;
        case 'v':
            verbose = true;
            break;
        case 'b':
            debug = true;
            break;
        case 't':
            t = atoi(optarg);
            time_flag = true;
            break;
        case 'n':
            vector_init = optarg;
            break;
        case 'h':
            fhelp();
            exit(EXIT_SUCCESS);
        case '?':
            fhelp();
            exit(EXIT_FAILURE);
        default:
            fprintf(stderr, "Unexpected option\n");
            fhelp();
            exit(EXIT_FAILURE);
        }
    }

    if (input_file == NULL || mode == NULL || (encrypt && decrypt) || (!encrypt && !decrypt))
    {
        fprintf(stderr, "Missing or invalid arguments.\n");
        fhelp();
        exit(EXIT_FAILURE);
    }

    // Parse the input file
    char *file_content = NULL;
    if (file_parser(&file_content, input_file, file_length) == EXIT_SUCCESS)
    {
        if (verbose)
        {
            printf("Content of the file:\n%s\n", file_content);
        }
    }
    else
    {
        fprintf(stderr, "Failed to parse the file.\n");
        exit(EXIT_FAILURE);
    }

    // Split the text into blocks
    unsigned char **blocks;
    size_t num_blocks;
    affichage_result(split_text_into_blocks(file_content, *file_length, &blocks, &num_blocks), "split text", &blocks, &num_blocks, verbose, debug);
    // Verify the encryption/decryption key
    if (key == NULL)
    {
        key = DEFAULT_KEY_128;
    }

    int key_length = strlen(key) * 4;
    if (key_verif(key, key_length) != EXIT_SUCCESS)
    {
        fprintf(stderr, "Failed to verify the encryption/decryption key.\n");
        exit(EXIT_FAILURE);
    }
    if (verbose)
    {
        printf("Key used : %s\n", key);
        printf("Key size used : %d bits\n", key_length);
    }
    // Expansion key
    size_t num_round_keys;
    int nk;
    switch (key_length)
    {
    case 128:
        num_round_keys = 10;
        nk = 4;
        break;
    case 192:
        num_round_keys = 12;
        nk = 6;
        break;
    case 256:
        num_round_keys = 14;
        nk = 8;
        break;
    default:
        printf("Unsupported key size!\n");
    }

    uint8_t temp[(num_round_keys + 1) * 16];
    uint32_t *expandedKey = (uint32_t *)temp;
    KeyExpansion((uint8_t *)key, expandedKey, nk, num_round_keys);
    unsigned char **round_keys;
    num_round_keys++;
    affichage_result(getRoundKeys(expandedKey, num_round_keys, &round_keys), "Round key", &round_keys, &num_round_keys, verbose, debug);

    unsigned char **cipher;
    size_t num_cipher;
    unsigned char **decipher;
    size_t num_decipher;
    // Calculate the total size of the concatenated text
    size_t concatenated_text_length = num_blocks * BLOCK_SIZE;
    char *concatenated_text = NULL;
    // Allocate memory for the concatenated text, plus one extra byte for the null terminator
    concatenated_text = (char *)malloc(concatenated_text_length + 1);
    if (concatenated_text == NULL)
    {
        fprintf(stderr, "Memory allocation failed for concatenated text.\n");
        exit(EXIT_FAILURE);
    }

    cipher = (unsigned char **)malloc(num_blocks * sizeof(unsigned char *));
    if (cipher == NULL)
    {
        fprintf(stderr, "Memory allocation failed for cipher\n");
        exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i < num_blocks; i++)
    {
        cipher[i] = (unsigned char *)malloc(BLOCK_SIZE);
        if (cipher[i] == NULL)
        {
            fprintf(stderr, "Memory allocation failed for cipher[%zu]\n", i);
            for (size_t j = 0; j < i; j++)
            {
                free(cipher[j]);
            }
            free(cipher);
            exit(EXIT_FAILURE);
        }
    }

    decipher = (unsigned char **)malloc(num_blocks * sizeof(unsigned char *));
    if (decipher == NULL)
    {
        fprintf(stderr, "Memory allocation failed for decipher\n");
        exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i < num_blocks; i++)
    {
        decipher[i] = (unsigned char *)malloc(BLOCK_SIZE);
        if (decipher[i] == NULL)
        {
            fprintf(stderr, "Memory allocation failed for decipher[%zu]\n", i);
            for (size_t j = 0; j < i; j++)
            {
                free(decipher[j]);
            }
            free(decipher);
            exit(EXIT_FAILURE);
        }
    }

    if (strcmp(mode, "ECB") == 0)
    {
        if (encrypt)
        {
            start = clock();
            for (int i = 0; i < t; i++)
            {
                affichage_result(ECB_cipher(round_keys, blocks, num_blocks, cipher, &num_cipher, num_round_keys), "encryption", &cipher, &num_cipher, verbose, debug);
                for (size_t j = 0; j < num_cipher; j++)
                {
                    memcpy(blocks[j], cipher[j], BLOCK_SIZE);
                }
            }
            end = clock();
            cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC; // Calculate elapsed time in seconds

            concatenate_blocks(concatenated_text, &concatenated_text_length, &blocks, &num_blocks);
            printf("Result :\n");
            for (size_t i = 0; i < concatenated_text_length; i++)
            {
                printf("%c", concatenated_text[i]);
            }
            printf("\n");
            if (time_flag)
            {
                printf("Loop execution time : %f seconds\n", cpu_time_used);
            }
        }
        else if (decrypt)
        {
            start = clock();
            for (int i = 0; i < t; i++)
            {
                affichage_result(ECB_decipher(round_keys, blocks, num_blocks, decipher, &num_decipher, num_round_keys), "decryption", &decipher, &num_decipher, verbose, debug);
                for (size_t j = 0; j < num_decipher; j++)
                {
                    memcpy(blocks[j], decipher[j], BLOCK_SIZE);
                }
            }
            end = clock();
            cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC; // Calculate elapsed time in seconds
            concatenate_blocks(concatenated_text, &concatenated_text_length, &blocks, &num_blocks);
            printf("Result :\n");
            for (size_t i = 0; i < concatenated_text_length; i++)
            {
                printf("%c", concatenated_text[i]);
            }
            printf("\n");
            if (time_flag)
            {
                printf("Loop execution time : %f seconds\n", cpu_time_used);
            }
        }
        else
        {
            fprintf(stderr, "Invalid mode specified.\n");
        }
    }
    else if (strcmp(mode, "CBC") == 0)
    {
        if (vector_init == NULL)
        {
            vector_init = DEFAULT_VECTOR_128;
        }
        int vector_lenght = strlen(vector_init) * 4;
        if (vector_init_verif(vector_init, vector_lenght) != EXIT_SUCCESS)
        {
            fprintf(stderr, "Failed to verify the vector input.\n");
            exit(EXIT_FAILURE);
        }
        if (verbose)
        {
            printf("Vector input used : %s\n", vector_init);
            printf("Vector size used : %d bits\n", vector_lenght);
        }

        if (encrypt)
        {
            start = clock();
            for (int i = 0; i < t; i++)
            {
                affichage_result(CBC_cipher(round_keys, blocks, num_blocks, cipher, &num_cipher, num_round_keys, (unsigned char *)vector_init), "encryption", &cipher, &num_cipher, verbose, debug);
                for (size_t j = 0; j < num_cipher; j++)
                {
                    memcpy(blocks[j], cipher[j], BLOCK_SIZE);
                }
            }
            end = clock();
            cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC; // Calculate elapsed time in seconds
            concatenate_blocks(concatenated_text, &concatenated_text_length, &blocks, &num_blocks);
            printf("Result :\n");
            for (size_t i = 0; i < concatenated_text_length; i++)
            {
                printf("%c", concatenated_text[i]);
            }
            printf("\n");
            if (time_flag)
            {
                printf("Loop execution time : %f seconds\n", cpu_time_used);
            }
        }
        else if (decrypt)
        {
            start = clock();
            for (int i = 0; i < t; i++)
            {
                affichage_result(CBC_decipher(round_keys, blocks, num_blocks, decipher, &num_decipher, num_round_keys, (unsigned char *)vector_init), "decryption", &decipher, &num_decipher, verbose, debug);
                for (size_t j = 0; j < num_decipher; j++)
                {
                    memcpy(blocks[j], decipher[j], BLOCK_SIZE);
                }
            }
            end = clock();
            cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC; // Calculate elapsed time in seconds
            concatenate_blocks(concatenated_text, &concatenated_text_length, &blocks, &num_blocks);
            printf("Result :\n");
            for (size_t i = 0; i < concatenated_text_length; i++)
            {
                printf("%c", concatenated_text[i]);
            }
            printf("\n");
            if (time_flag)
            {
                printf("Loop execution time : %f seconds\n", cpu_time_used);
            }
        }
        else
        {
            fprintf(stderr, "Invalid mode specified.\n");
        }
    }
    else if (strcmp(mode, "CFB") == 0)
    {
        if (vector_init == NULL)
        {
            vector_init = DEFAULT_VECTOR_128;
        }
        int vector_lenght = strlen(vector_init) * 4;
        if (vector_init_verif(vector_init, vector_lenght) != EXIT_SUCCESS)
        {
            fprintf(stderr, "Failed to verify the vector input.\n");
            exit(EXIT_FAILURE);
        }
        if (verbose)
        {
            printf("Vector input used : %s\n", vector_init);
            printf("Vector size used : %d bits\n", vector_lenght);
        }

        if (encrypt)
        {
            start = clock();
            for (int i = 0; i < t; i++)
            {
                affichage_result(CFB_cipher(round_keys, blocks, num_blocks, cipher, &num_cipher, num_round_keys, (unsigned char *)vector_init), "encryption", &cipher, &num_cipher, verbose, debug);
                for (size_t j = 0; j < num_cipher; j++)
                {
                    memcpy(blocks[j], cipher[j], BLOCK_SIZE);
                }
            }
            end = clock();
            cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC; // Calculate elapsed time in seconds
            concatenate_blocks(concatenated_text, &concatenated_text_length, &blocks, &num_blocks);
            printf("Result :\n");
            for (size_t i = 0; i < concatenated_text_length; i++)
            {
                printf("%c", concatenated_text[i]);
            }
            printf("\n");
            if (time_flag)
            {
                printf("Loop execution time : %f seconds\n", cpu_time_used);
            }
        }
        else if (decrypt)
        {
            start = clock();
            for (int i = 0; i < t; i++)
            {
                affichage_result(CFB_decipher(round_keys, blocks, num_blocks, decipher, &num_decipher, num_round_keys, (unsigned char *)vector_init), "decryption", &decipher, &num_decipher, verbose, debug);
                for (size_t j = 0; j < num_decipher; j++)
                {
                    memcpy(blocks[j], decipher[j], BLOCK_SIZE);
                }
            }
            end = clock();
            cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC; // Calculate elapsed time in seconds
            concatenate_blocks(concatenated_text, &concatenated_text_length, &blocks, &num_blocks);
            printf("Result :\n");
            for (size_t i = 0; i < concatenated_text_length; i++)
            {
                printf("%c", concatenated_text[i]);
            }
            printf("\n");
            if (time_flag)
            {
                printf("Loop execution time : %f seconds\n", cpu_time_used);
            }
        }
        else
        {
            fprintf(stderr, "Invalid mode specified.\n");
        }
    }
    else if (strcmp(mode, "GCM") == 0)
    {
        printf("This code is not supported");
    }
    else
    {
        printf("Error mode, the mode input is not supported");
    }

    if (output_specified)
    {
        if (write_to_file(output_file, concatenated_text, concatenated_text_length) == EXIT_FAILURE)
        {
            fprintf(stderr, "Failed to write content to the file\n %s\n", output_file);
            exit(EXIT_FAILURE);
        }
        if (verbose)
        {
            printf("Content successfully written to the file\n %s\n", output_file);
        }
    }
    num_cipher = num_blocks;
    num_decipher = num_blocks;
    // free memory.
    if (file_content != NULL)
    {
        free(file_content);
    }
    if (blocks != NULL)
    {
        free_blocks(blocks, num_blocks);
    }
    if (round_keys != NULL)
    {
        free_blocks(round_keys, num_round_keys);
    }
    if (cipher != NULL)
    {
        free_blocks(cipher, num_cipher);
    }
    if (decipher != NULL)
    {
        free_blocks(decipher, num_decipher);
    }
    if (concatenated_text != NULL)
    {
        free(concatenated_text);
    }

    return 0;
}