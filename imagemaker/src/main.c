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

#include "debug.h"
#include "reuse.h"
#include "25519/edsign.h"

#define EDSIGN_SIGNATURE_SIZE 64

static char *mainOSImage = NULL, *bootloaderImage = NULL, *outputFile = NULL;
static bool isVerbose = 0; 

typedef enum {
    IMAGE_PROD_DEVELOPMENT = 0,
    IMAGE_PROD_PRODUCTION = 1,
} ImageProductionType;

typedef struct ImageHeader {
    uint32_t magic;
    uint32_t dataSize;
    uint32_t imageType;
    ImageProductionType production;
} __attribute__ ((packed)) ImageHeader;

typedef struct ImageSigningExtension {
    uint8_t  imageSignature[EDSIGN_SIGNATURE_SIZE];
    uint8_t  imageDigest[32];
    uint8_t  publickey[32];
} __attribute__ ((packed)) ImageSigningExtension;


typedef struct ImageRootHeader {
    ImageHeader header;
    ImageSigningExtension signing;
} __attribute__ ((packed)) ImageRootHeader;

void test_make_image(void) {
	ImageRootHeader *rootHeader;
	rootHeader = (ImageRootHeader*)malloc(sizeof(ImageRootHeader));
	memset(rootHeader, 0, sizeof(ImageRootHeader));

	rootHeader->header.magic = 'ESBI';   
    rootHeader->header.dataSize = 0x4141; 
    rootHeader->header.imageType = 'ESOI';
    rootHeader->header.production = IMAGE_PROD_DEVELOPMENT;

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

void test_read_image(void) {
    unsigned char imageBuffer[0x100] = {0};
    ImageRootHeader *hdr;
    FILE *fp = fopen("test.bin", "r"); 
    fread(imageBuffer, sizeof(char), 0x100, fp);
    fclose(fp);

    hdr = (ImageRootHeader *)imageBuffer;
    if ((hdr->header.magic) != 0x45534249) {
        printf("bad magic 0x%08x expecting 0x%08x\n", (hdr->header.magic), 'ESBI');
    } else {
        printf("\nMagic looks OK..\n");
    }

    printf("\nImage header\n");
    printf("MAGIC: %08x\n", (hdr->header.magic));
    printf("SIZE : %08x\n", (hdr->header.dataSize));
    printf("TYPE : %08x\n", (hdr->header.imageType));
    printf("PROD : %08x\n", (hdr->header.production));
    printf("\nPublic Key ==> 0x%08lx bytes\n", sizeof(hdr->signing.publickey));
    print_hex((hdr->signing.publickey), sizeof(hdr->signing.publickey));
    printf("Digest Key ==> 0x%08lx bytes\n", sizeof(hdr->signing.imageDigest));
    print_hex((hdr->signing.imageDigest), sizeof(hdr->signing.imageDigest));
    printf("Signature ==> 0x%08lx bytes\n", sizeof(hdr->signing.imageSignature));
    print_hex((hdr->signing.imageSignature), sizeof(hdr->signing.imageSignature));

    hexDump("hdr", hdr, sizeof(ImageRootHeader));
}

void begin_making_image(void) {
    printf("\nCreating image...\n");
    if (isVerbose) {
        printf("OS ==> %s\n", mainOSImage);
        printf("BL ==> %s\n", bootloaderImage);
    }

    // Initialize new image header
    ImageRootHeader *rootHeader;
    rootHeader = (ImageRootHeader*)malloc(sizeof(ImageRootHeader));
    memset(rootHeader, 0, sizeof(ImageRootHeader));
    
    // set some of the standard values
    rootHeader->header.magic = 'ESBI';   
    rootHeader->header.imageType = 'ESOI';
    rootHeader->header.production = IMAGE_PROD_DEVELOPMENT; // force non-prod for now
    
    // open, seek and then tell the size of our OS image
    FILE *fp = fopen(mainOSImage, "rb");
    fseek(fp, 0L, SEEK_END);
    rootHeader->header.dataSize = ftell(fp);
    printf("OS Size === %08x\n", (rootHeader->header.dataSize));
    fclose(fp);

    // sha256(mainos)
    printf("\nComputing digest...\n");
    unsigned char shaBuff[SHA256_DIGEST_LENGTH] = {0};
    calc_sha256(mainOSImage, shaBuff); 
    print_complex("Digest", ":::", (unsigned char *)shaBuff, SHA256_DIGEST_LENGTH, true, 5);
    memcpy(rootHeader->signing.imageDigest, shaBuff, SHA256_DIGEST_LENGTH);

    // sign digest
    printf("\nSigning digest...\n");
    uint8_t pub[EDSIGN_PUBLIC_KEY_SIZE];
    uint8_t signature[EDSIGN_SIGNATURE_SIZE];
    uint8_t secret[32] = { 0xC4, 0x6C, 0x22, 0xA1, 
                           0xF5, 0x02, 0x98, 0x83, 
                           0xF4, 0xA9, 0x38, 0x0E, 
                           0x60, 0x35, 0xDF, 0x97, 
                           0x12, 0x64, 0xD9, 0x8B, 
                           0x97, 0x76, 0xA2, 0x05, 
                           0xA4, 0x4E, 0xDB, 0x45, 
                           0x90, 0x75, 0xBC, 0xFB};

    // get pub from our secret
    edsign_sec_to_pub(pub, secret); 
    print_complex("secret", ":::", (unsigned char *)secret, EDSIGN_PUBLIC_KEY_SIZE, true, 5);
    print_complex("publickey", ":::", (unsigned char *)pub, EDSIGN_PUBLIC_KEY_SIZE, true, 5);
    memcpy(rootHeader->signing.publickey, pub, EDSIGN_PUBLIC_KEY_SIZE);

    // sign the hash
    edsign_sign(signature, pub, secret, shaBuff, SHA256_DIGEST_LENGTH);
    print_complex("signature", ":::", (unsigned char *)signature, EDSIGN_SIGNATURE_SIZE, true, 5);
    memcpy(rootHeader->signing.imageSignature, signature, EDSIGN_SIGNATURE_SIZE);
    if (isVerbose)
    {
        hexDump("header", rootHeader, sizeof(ImageRootHeader));
    }

    // read in bootloader
    FILE *f = fopen(bootloaderImage, "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET); 

    char *bootloaderBuffer = malloc(fsize + 1);
    fread(bootloaderBuffer, fsize, 1, f);
    fclose(f);

    // calculate padding to 0x8000
    long padding = (0x8000-fsize);
    char paddingBuff[padding];
    memset(paddingBuff, 0xFF, padding);
    printf("BL Size === %04lx\n", fsize);
    printf("Padding === %04lx\n", padding);

    // read in mainos
    FILE *fos = fopen(bootloaderImage, "rb");
    fseek(fos, 0, SEEK_END);
    long mainosSize = ftell(fos);
    fseek(fos, 0, SEEK_SET); 

    char *mainosBuffer = malloc(mainosSize + 1);
    fread(mainosBuffer, mainosSize, 1, fos);
    fclose(fos);

    // write out all buffers
    FILE *fpo = fopen(outputFile, "wb+");
    fwrite(bootloaderBuffer, fsize, 1, fpo);
    fwrite(paddingBuff, padding, 1, fpo);
    printf("ftell before header %04lx\n", ftell(fpo));
    fwrite(rootHeader, sizeof(ImageRootHeader), 1, fpo);
    fwrite(mainosBuffer, mainosSize, 1, fpo);
    fclose(fpo);
}

void print_usage(void) {
    print_opt("--ticket", "::: Ticket file to stitch");
    print_opt("--mainos", "::: Input OS firmware");
    print_opt("--bootloader", "::: Input bootloader firmware");
    print_opt("--output", "::: Output signed and stitched firmware");
    print_opt("--verbose", "::: Enable verbosity");
    print_opt("--help", "::: Show this message");
}

int main(int argc, char *argv[])
{
    bool run = true;
    int opt;
    printf("imagemaker v1.0.0\n");
    while (1) {
        static struct option user_options[] = {
            {"ticket", required_argument, 0, 't'},
            {"mainos", required_argument, 0, 'm'},
            {"output", required_argument, 0, 'o'},
            {"bootloader", required_argument, 0, 'b'},
            {"runTestOnly", no_argument, 0, 'r'},
            {"verbose", no_argument, 0, 'v'},
            {"help", no_argument, 0, '?'},
        };
        int option_index = 0;
        opt = getopt_long(argc, argv, ":i:o:t:", user_options, &option_index);
        
        if(opt == -1)
            break;

        switch (opt) {
            case 'm':
                mainOSImage = optarg;
                break;
            
            case 'b':
                bootloaderImage = optarg;
                break;

            case 'o':
                outputFile = optarg;
                break;

            case 'v':
                isVerbose = true;
                break;

            case 'r':
                test_make_image();
                test_read_image();
                break;

            default:
                break;
        }
    }

    if(!mainOSImage) {
        printf("No main OS image\n");
        run = false;
    }

    if (!bootloaderImage)
    {
        printf("No bootloader image\n");
        run = false;
    }
    
    if(!outputFile) {
        printf("No output file\n");
        run = false;
    }

    if (run) {
        begin_making_image();
        return 0;
    }

    print_usage();
    return 0;
}