#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "debug.h"

void print_complex(char *label, char *seperator, unsigned char *value, int valueLen, bool valueHex, int maxWidth) {
    if (valueHex)
    {
        printf("%-*s %s ", maxWidth, label, seperator);
        print_hash(value, valueLen);
        return;
    } else {
        printf("%-*s %s %s\n", maxWidth, label, seperator, value);
    }
}

void print_opt(char *option, char *desc) {
    printf("%-15s %s\n", option, desc);
}

void print_hex(uint8_t *s, size_t len) {
    int oCount = 0;
    for(int i = 0; i < len; i++) {
        printf("0x%02x", s[i]);
        oCount += 1;
        if (oCount == 8)
        {
            printf("\n");
            oCount = 0;
        } else {
            if ((i+1) < len) { printf(", "); }
        }
    }
    printf("\n");
}

void print_hash(uint8_t *s, size_t len) {
    for(int i = 0; i < len; i++) {
        printf("%02x", s[i]);
    }
    printf("\n");
}

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