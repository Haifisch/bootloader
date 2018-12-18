#include <stdbool.h>

void hexDump(char *desc, void *addr, int len);
void print_hex(uint8_t *s, size_t len);
void print_hash(uint8_t *s, size_t len);
void print_opt(char *option, char *desc);
void print_complex(char *label, char *seperator, unsigned char *value, int valueLen, bool valueHex, int maxWidth);
