/*
 * Read, set (top up) the credit on a very specific type of NFC laundry card
 *
 * Copyright (c) 2024, Andrea Peter
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the “Software”), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
 * LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <freefare.h>
#include <nfc/nfc.h>
#include <stdarg.h>

// Return codes
#define EXIT_INVALID_ARGS 2   // Invalid arguments
#define EXIT_NFC_FAILURE 3    // NFC failure

// Number of supported devices
#define MAX_DEVICES 4

// MIFARE Classic 1K keys
#define KEY_LEN 6
#define KEY_LEN_CHARS (KEY_LEN * 2)

typedef unsigned char key[KEY_LEN];

nfc_connstring devices[MAX_DEVICES];
size_t nb_found_devices = 0;

// The credit value is stored in two blocks
#define BLOCK_CREDIT_1 6
#define BLOCK_CREDIT_2 8


typedef struct {
    nfc_context *ctx;
    nfc_device *device;
    MifareTag tag;  // The tag we use
    MifareTag *tags;  // All found tags
} context;

static int auth_b(MifareTag tag, MifareClassicBlockNumber block, key key_b);
static void check(context *context, key key_b, int32_t *credit);
static void close_and_err(context *context, int retval, char *format, ...);
static void close_nfc(context *context);
static void debug(char *format, ...);
static void set_credit(context *context, key key_b, double new_credit);
static int str_to_hex(const char *str, unsigned char *hex);
static void usage(char *prog_name);

static int verbose = 0;

/**
 * Close nfc device, tags and library
 * @param context NFC tag context
 */
static void close_nfc(context *context) {
    if (context->tag) {
        mifare_classic_disconnect(context->tag);
    }
    if (context->tags) {
        freefare_free_tags(context->tags);
    }
    if (context->device) {
        nfc_close(context->device);
    }
    if (context->ctx) {
        nfc_exit(context->ctx);
    }
}


/**
 * Shut down NFC, print error to stderr and exit with retval
 * @param context NFC tag context
 * @param retval Exit value
 * @param format Formatted message with optional arguments
 */
static void close_and_err(context *context, int retval, char *format, ...) {
    close_nfc(context);

    va_list args;
    va_start(args, format);
    verrx(retval, format, args);
    va_end(args);
}


/**
 * Print to stdout if we are in verbose mode
 * @param format Formatted message with optional arguments
 */
static void debug(char *format, ...) {
    if (verbose) {
        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
    }
}


/**
 * Transform hex string to bytes
 * @param str Input string
 * @param hex Output bytes
 * @return 0 if OK
 */
static int str_to_hex(const char *str, unsigned char *hex) {
    unsigned int length = strlen(str);
    unsigned int i = 0;
    unsigned int j = 0;
    unsigned char c = 0;

    if (length % 2 != 0) {
        return 1;  // Uneven input string
    }
    for (i = 0; i < length; i += 2) {
        c = 0;
        for (j = 0; j < 2; j++) {
            if (str[i+j] >= 'A' && str[i+j] <= 'F') {
                c += (str[i+j] - 'A' + 10)  * ((i + j) % 2 == 0 ? 16 : 1);
            } else if (str[i+j] >= 'a' && str[i+j] <= 'f') {
                c += (str[i+j] - 'a' + 10)  * ((i + j) % 2 == 0 ? 16 : 1);
            } else if (str[i+j] >= '0' && str[i+j] <= '9') {
                c += (str[i+j] - '0')  * ((i + j) % 2 == 0 ? 16 : 1);
            } else {
                return 2;  // Invalid character
            }
        }
        hex[i / 2] = c;
    }
    return 0;
}


/**
 * Authenticate to given block with the given B key
 * @param block: Block on which to authenticate
 * @param key_b: B key
 * @return: 0 if OK
 */
static int auth_b(MifareTag tag, MifareClassicBlockNumber block, key key_b) {
    return mifare_classic_authenticate(tag, block, key_b, MFC_KEY_B);
}


/**
 * Try to authenticate, check whether the values are consistent and get current credit
 * @param context: NFC tag context
 * @param key_b: B key for authentication
 * @param credit: Out parameter, current credit on the card
 */
static void check(context *context, key key_b, int32_t *credit) {
    int32_t credit_val1;
    int32_t credit_val2;

    // Try to authenticate with B key to the two sectors containing the credit
    if (auth_b(context->tag, BLOCK_CREDIT_1, key_b)) {
        close_and_err(context, EXIT_FAILURE, "Could not authenticate on sector 1", NULL);
    }
    // Read block
    if (mifare_classic_read_value(context->tag, BLOCK_CREDIT_1, &credit_val1, NULL)) {
        close_and_err(context, EXIT_FAILURE, "Could not read value from block 0x%02x", BLOCK_CREDIT_1);
    }

    if (auth_b(context->tag, BLOCK_CREDIT_2, key_b)) {
        close_and_err(context, EXIT_FAILURE, "Could not authenticate on sector 2", NULL);
    }
    // Read block
    if (mifare_classic_read_value(context->tag, BLOCK_CREDIT_2, &credit_val2, NULL)) {
        close_and_err(context, EXIT_FAILURE, "Could not read value from block 0x%02x", BLOCK_CREDIT_2);
    }

    // The two values should match
    if (credit_val1 != credit_val2) {
        close_and_err(context,
                      EXIT_FAILURE,
                      "The two credit values differ, block 0x%02x: %d, block 0x%02x: %d",
                      BLOCK_CREDIT_1, credit_val1, BLOCK_CREDIT_2, credit_val2);
    }

    *credit = credit_val1;
}


/**
 * Set given credit
 * @param context: NFC tag context
 * @param key_b: B key
 * @param new_credit: Credit to set
 */
static void set_credit(context *context, key key_b, double new_credit) {
    int32_t new_credit_int = (int32_t)(new_credit * 100);

    if (auth_b(context->tag, BLOCK_CREDIT_1, key_b)) {
        close_and_err(context,
                      EXIT_FAILURE,
                      "Could not authenticate on sector %s",
                      mifare_classic_block_sector(BLOCK_CREDIT_1));
    }

    if (mifare_classic_init_value(context->tag, BLOCK_CREDIT_1, new_credit_int, 0)) {
        close_and_err(context,
                      EXIT_NFC_FAILURE,
                      "Could not write credit value in block 0x%02x",
                      BLOCK_CREDIT_1);
    }

    if (auth_b(context->tag, BLOCK_CREDIT_2, key_b)) {
        close_and_err(context,
                      EXIT_FAILURE,
                      "Could not authenticate on sector %d",
                      mifare_classic_block_sector(BLOCK_CREDIT_2));
    }

    if (mifare_classic_init_value(context->tag, BLOCK_CREDIT_2, new_credit_int, 0)) {
        close_and_err(context,
                      EXIT_NFC_FAILURE,
                      "Could not write credit value in block 0x%02x",
                      BLOCK_CREDIT_2);
    }

    printf("Credit set to %.2f\n", new_credit);
}


/**
 * Print usage
 * @param prog_name: Program name
 */
static void usage(char *prog_name) {
    fprintf(stderr, "usage: %s [-v] [-s VALUE] KEY_B \n", prog_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "By default only read current credit value\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, " -s VALUE    Set credit value\n");
    fprintf(stderr, " -v          Verbose output\n");
    fprintf(stderr, " KEY_B       B key for sectors 1 and 2\n");
}


int main(int argc, char* argv[])
{

    // NFC
    MifareTag tag = NULL;
    MifareTag *tags = NULL;
    nfc_device* device = NULL;

    // Command line arguments
    int ch;
    int do_set_credit = 0;
    key key_b;
    char *end_ptr = NULL;
    double new_credit = 0.0;

    // Get arguments
    while ((ch = getopt(argc, argv, "vs:")) != -1) {
        switch(ch) {
            case 's':
                do_set_credit = 1;
                if (optarg == NULL) {
                    usage(argv[0]);
                    exit(EXIT_INVALID_ARGS);
                }
                new_credit = strtod(optarg, &end_ptr);
                if (end_ptr == optarg) {
                    errx(EXIT_INVALID_ARGS, "New credit must be a number\n");
                }
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                usage(argv[0]);
                exit(EXIT_INVALID_ARGS);
        }
    }

    // Parsing the B key
    if (optind == argc) {
        usage(argv[0]);
        exit(EXIT_INVALID_ARGS);
    }
    if(strlen(argv[optind]) != KEY_LEN_CHARS) {
        errx(EXIT_INVALID_ARGS, "KEY_B must be %d characters long", KEY_LEN_CHARS);
    }
    if (str_to_hex(argv[optind], key_b) != 0) {
        errx(EXIT_INVALID_ARGS, "Invalid key\n");
    }
    debug("Using B key %s to authenticate to sectors 0x01 and 0x02\n", argv[optind]);

    context context;
    context.ctx = NULL;
    context.device = NULL;
    context.tag = NULL;
    context.tags = NULL;

    nfc_context* ctx;

    nfc_init(&ctx);
    if (ctx == NULL) {
        errx(errno, "Unable to init libnfc: %s\n", strerror(errno));
    }

    context.ctx = ctx;

    debug("Using libnfc %s\n", nfc_version());
    debug("Using libfreefare <unknown version>\n");

    debug("Listing devices...\n");
    nb_found_devices = nfc_list_devices(context.ctx, devices, MAX_DEVICES);

    if (nb_found_devices) {

        debug("Found %zd device(s):\n", nb_found_devices);

        for (int i = 0; i < nb_found_devices; i++) {
            debug(" - %s\n", devices[i]);
        }
    } else {
        errx(EXIT_FAILURE, "No devices found");
    }

    debug("Using %s\n", devices[0]);

    // We assume the first device is the one
    debug("Open %s\n", devices[0]);
    device = nfc_open(context.ctx, devices[0]);
    if (device == NULL) {
        close_and_err(&context, EXIT_NFC_FAILURE, "Error opening device\n");
    }
    context.device = device;

    debug("%s ready\n", nfc_device_get_name(device));

    // Select first MIFARE Classic 1K tag
    tags = freefare_get_tags(device);
    if (!tags) {
        close_and_err(&context, EXIT_FAILURE, "Error listing Mifare tags\n", NULL);
    }
    context.tags = tags;
    for (int i=0; tags[0]; i++) {
        if (freefare_get_tag_type(tags[i]) == CLASSIC_1K) {
            tag = tags[i];
            break;
        }
    }
    if (!tag) {
        close_and_err(&context, EXIT_FAILURE, "No Mifare Classic 1K tag found\n", NULL);
    }
    context.tag = tag;

    debug("Using tag %s with ID %s\n", freefare_get_tag_friendly_name(tag), freefare_get_tag_uid(tag));

    // Select passive target
    if (mifare_classic_connect(tag) != 0) {
        close_and_err(&context, EXIT_FAILURE, "Could not connect to tag\n", NULL);
    }

    int32_t credit;
    check(&context, key_b, &credit);
    printf("The current credit value is %d.%02d\n", credit / 100, credit % 100);


    if (do_set_credit) {
        set_credit(&context, key_b, new_credit);
    }

    close_nfc(&context);

    return 0;
}
