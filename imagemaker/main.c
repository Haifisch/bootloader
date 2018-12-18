#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define EDSIGN_SIGNATURE_SIZE 64

typedef struct ImageHeader {
    uint32_t magic;
    uint32_t dataSize;
    uint32_t imageType;
    uint32_t production;
} __attribute__ ((packed)) ImageHeader;

typedef struct ImageSigningExtension {
	uint8_t  publickey[32];
    uint8_t  imageSignature[EDSIGN_SIGNATURE_SIZE];
    uint8_t  imageDigest[32];
} __attribute__ ((packed)) ImageSigningExtension;


typedef struct ImageRootHeader {
    ImageHeader header;
    ImageSigningExtension signing;
} __attribute__ ((packed)) ImageRootHeader;

void hexDump (char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;
    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }
    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }
    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }
    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}


void test_make_image(void) {
	ImageRootHeader *rootHeader;
	rootHeader = (ImageRootHeader*)malloc(sizeof(ImageRootHeader));
	memset(rootHeader, 0, sizeof(ImageRootHeader));

	rootHeader->header.magic = 'EBSI';   
    rootHeader->header.dataSize = 0x4141; 
    rootHeader->header.imageType = 'ENOS';
    rootHeader->header.production = 0x0;

    uint8_t fakeSig[EDSIGN_SIGNATURE_SIZE];
    memset(fakeSig, 0x41, EDSIGN_SIGNATURE_SIZE);
    memcpy(rootHeader->signing.imageSignature, fakeSig, EDSIGN_SIGNATURE_SIZE);

    uint8_t fakeDigest[32];
    memset(fakeDigest, 0xFF, 32);
    memcpy(rootHeader->signing.imageDigest, fakeDigest, 32);

    uint8_t fakePublickey[32];
    memset(fakePublickey, 0x11, 32);
    memcpy(rootHeader->signing.publickey, fakePublickey, 32);

	hexDump("rootImage", rootHeader, sizeof(ImageRootHeader));
	FILE *f;
    f = fopen("test.bin", "wb+");
    fwrite(rootHeader, sizeof(ImageRootHeader), 1, f);
    fclose(f);
}

int main(int argc, char const *argv[])
{
	printf("imagemaker v1.0.0\n");
	test_make_image();
	return 0;
}