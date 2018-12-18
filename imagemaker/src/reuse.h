#include "sha256.h"

#define SHA256_DIGEST_LENGTH 32

int calc_sha256(char* path, unsigned char output[SHA256_DIGEST_LENGTH]);