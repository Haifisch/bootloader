#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <stdint.h>
#include <assert.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "reuse.h"

int calc_sha256(char* path, unsigned char output[SHA256_DIGEST_LENGTH])
{
  FILE* file = fopen(path, "rb");
  if(!file) return -1;

  sha256_context sha256;
  sha256_starts(&sha256);
  const int bufSize = 5;
  unsigned char* buffer = malloc(bufSize);
  int bytesRead = 0;
  if(!buffer) return -1;
  while((bytesRead = fread(buffer, 1, bufSize, file)))
  {
      sha256_update(&sha256, buffer, bytesRead);
  }   
  sha256_finish(&sha256, output);

  fclose(file);
  free(buffer);
  return 0;
}   