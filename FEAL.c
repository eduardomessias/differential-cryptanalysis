/*
 * The FEAL cipher
 */
#include <stdio.h>

// Use of random and time
#include <stdlib.h>
#include <time.h>

#define WORD32 unsigned int
#define BYTE unsigned char

#define ROUNDS 4

#define ROT2(x) (((x) << 2) | ((x) >> 6))

#define G0(a, b) (ROT2((BYTE)((a) + (b))))
#define G1(a, b) (ROT2((BYTE)((a) + (b) + 1)))

static WORD32 pack32(BYTE *b)
{ /* pack 4 bytes into a 32-bit Word */
    return (WORD32)b[3] | ((WORD32)b[2] << 8) | ((WORD32)b[1] << 16) | ((WORD32)b[0] << 24);
}

static void unpack32(WORD32 a, BYTE *b)
{ /* unpack bytes from a 32-bit word */
    b[0] = (BYTE)(a >> 24);
    b[1] = (BYTE)(a >> 16);
    b[2] = (BYTE)(a >> 8);
    b[3] = (BYTE)a;
}

/* the Feal function */
WORD32 f(WORD32 input)
{
    BYTE x[4], y[4];
    unpack32(input, x);
    y[1] = G1(x[1] ^ x[0], x[2] ^ x[3]);
    y[0] = G0(x[0], y[1]);
    y[2] = G0(y[1], x[2] ^ x[3]);
    y[3] = G1(y[2], x[3]);
    WORD32 output = pack32(y);
    return output;
}

void encrypt(BYTE data[8], WORD32 key[6])
{
    WORD32 left, right, temp;

    // Preparation
    left = pack32(&data[0]) ^ key[4];

    right = pack32(&data[4]) ^ key[5];
    right = left ^ right;

    // Rounds
    for (int i = 0; i < ROUNDS; i++)
    {
        WORD32 temp = right;
        WORD32 roundInput = right ^ key[i];
        WORD32 roundOutput = f(roundInput);
        right = left ^ roundOutput;
        left = temp;
    }

    // Finalization
    right ^= left;

    unpack32(right, &data[0]);
    unpack32(left, &data[4]);
}

void decrypt(BYTE data[8], WORD32 key[6])
{
    WORD32 left, right, temp;

    right = pack32(&data[0]);
    left = right ^ pack32(&data[4]);

    for (int i = 0; i < ROUNDS; i++)
    {
        temp = left;
        left = right ^ f(left ^ key[ROUNDS - 1 - i]);
        right = temp;
    }

    right ^= left;

    left ^= key[4];
    right ^= key[5];
    unpack32(left, &data[0]);
    unpack32(right, &data[4]);
}

/* Not the key you are looking for!!! */
WORD32 key[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

/* Solution to the exercise */
WORD32 subkeys[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
unsigned long long plain0[6], plain1[6];
unsigned long long cipher0[6], cipher1[6];
int plainLength = 12;

void randomiseSubkeys()
{
    srand(time(NULL));
    printf("Creating random keys...\n");
    for (int i = 0; i < 6; i++)
    {
        subkeys[i] = (rand() << 16L) | (rand() & 0xFFFFL);
        printf("Key %d: %08X\n", i, subkeys[i]);
    }
}

unsigned long left(unsigned long long x)
{
    return x >> 32LL;
}

unsigned long right(unsigned long long x)
{
    return x & 0xFFFFFFFFLL;
}

unsigned long long combined(unsigned long left, unsigned long right)
{
    return (((unsigned long long)left) << 32LL) | (((unsigned long long)(right)) & 0xFFFFFFFFLL);
}

unsigned long long encryptUsingSubkeys(unsigned long long plain)
{
    unsigned long leftHalf = left(plain);
    unsigned long rightHalf = right(plain);

    leftHalf ^= subkeys[4];
    leftHalf ^= subkeys[5];

    unsigned long r2L = leftHalf ^ rightHalf;
    unsigned long r2R = leftHalf ^ f(r2R ^ subkeys[0]);

    unsigned long r3L = r2R;
    unsigned long r3R = r2L ^ f(r3R ^ subkeys[1]);

    unsigned long r4L = r3R;
    unsigned long r4R = r3L ^ f(r3R ^ subkeys[2]);

    unsigned long cL = r4L ^ f(r4R ^ subkeys[3]);
    unsigned long cR = cL ^ r4R;

    return combined(cL, cR);
}

void generatePairs(unsigned long long differential)
{
    printf("Generating plain/ciphertext pairs for differential 0x%016llx...\n", differential);

    for (int i = 0; i < plainLength; i++)
    {
        plain0[i] = (rand() & 0xFFFFLL) << 48LL;
        plain0[i] += (rand() & 0xFFFFLL) << 32LL;
        plain0[i] += (rand() & 0xFFFFLL) << 16LL;
        plain0[i] += (rand() & 0xFFFFLL);
        cipher0[i] = encryptUsingSubkeys(plain0[i]);

        plain1[i] = plain0[i] ^ differential;
        cipher1[i] = encryptUsingSubkeys(plain1[i]);

        printf("[%d] P0-C0: 0x%016llx-0x%016llx, P1-C1: 0x%016llx-0x%016llx\n", i, plain0[i], cipher0[i], plain1[i], cipher1[i]);
    }
}

void recoverLastRoundCiphers()
{
    // Keep the index
    int i;

    for (i = 0; i < plainLength; i++)
    {
        unsigned long cipher0L = left(cipher0[i]),
                      cipher0R = right(cipher0[i]) ^ cipher0L,
                      cipher1L = left(cipher1[i]),
                      cipher1R = right(cipher1[i]) ^ cipher1L;

        cipher0[i] = combined(cipher0L, cipher0R);
        cipher1[i] = combined(cipher1L, cipher1R);
    }

    printf("Recovered last round ciphers: C0 = 0x%16llx C1 = 0x%016llx \n", cipher0[i], cipher1[i]);
}

unsigned long recoverLastRoundSubkey(unsigned long differential)
{
    unsigned int fromTime = time(NULL);
    unsigned long subkey = 0x00000000L;

    printf("Recovering last round subkey using output differential 0x%08lx...\n", differential);

    for (subkey = 0x00000000L; subkey < 0xFFFFFFFFL; subkey++)
    {
        int score = 0;
        int try = 0;

        for (try = 0; try < plainLength; try++)
        {
            unsigned long c0L = cipher0[try] >> 32LL;
            unsigned long c1L = cipher1[try] >> 32LL;
            unsigned long cipherLeft = c0L ^ c1L;
            unsigned long candidateDifferential = cipherLeft ^ differential;

            unsigned long c0R = cipher0[try] & 0xFFFFFFFFLL;
            unsigned long c1R = cipher1[try] & 0xFFFFFFFFLL;
            unsigned long roundInput0 = c0R ^ subkey;
            unsigned long roundInput1 = c1R ^ subkey;
            unsigned long roundOutput0 = f(roundInput0);
            unsigned long roundOutput1 = f(roundInput1);
            unsigned long computedDifferential = roundOutput0 ^ roundOutput1;

            if (computedDifferential == candidateDifferential)
            {
                score++;
            }
            else
            {
                break;
            }
        }

        if (score > 0)
        {
            printf("Achieved score: %d\n", score);
        }

        if (score == plainLength)
        {
            printf("Found last round subkey: 0x%08lx\n", subkey);
            return subkey;
        }
    }
    unsigned int toTime = time(NULL);
    printf("Failed to recover last round subkey in %i seconds.\n", (toTime - fromTime));
    return 0;
}

int main(int argc, char **argv)
{
    BYTE data[8];

    argc--;
    argv++;

    if (argc != 8)
    {
        printf("command line error - input 8 bytes of plaintext in hex\n");
        printf("For example:-\n");
        printf("feal 01 23 45 67 89 ab cd ef\n");
        return 0;
    }
    for (int i = 0; i < 8; i++)
        sscanf(argv[i], "%hhx", &data[i]);

    printf("Plaintext=  ");
    for (int i = 0; i < 8; i++)
        printf("%02x", data[i]);
    printf("\n");

    encrypt(data, key);
    printf("Ciphertext= ");
    for (int i = 0; i < 8; i++)
        printf("%02x", data[i]);

    printf("\n");

    decrypt(data, key);
    printf("Plaintext=  ");
    for (int i = 0; i < 8; i++)
        printf("%02x", data[i]);
    printf("\n");

    printf("------------------------------------\n");
    printf("Differential Cryptanalysis on FEAL-4 using chosen-plaintext attack\n");
    printf("By Eduardo Messias\n\n");

    printf("Meet-in-the-middle attack:\n");

    unsigned long long round4Differential = 0x8080000080800000L;
    unsigned long long differential2 = 0x0000000080800000LL;
    unsigned long long differential3 = 0x0000000002000000LL;
    unsigned long outputDifferential = 0x02000000L;

    // Round 4
    randomiseSubkeys();
    generatePairs(round4Differential);
    recoverLastRoundCiphers();
    recoverLastRoundSubkey(outputDifferential);

    return 0;
}