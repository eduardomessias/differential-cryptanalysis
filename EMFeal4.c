#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#define MAXCHOSENPAIRS 10000
#define ull unsigned long long
#define uint unsigned
#define byte unsigned char

int num_plaintexts;
uint key[6];

ull plaintext0[MAXCHOSENPAIRS];
ull ciphertext0[MAXCHOSENPAIRS];
ull plaintext1[MAXCHOSENPAIRS];
ull ciphertext1[MAXCHOSENPAIRS];

uint getLeftHalf(ull x)
{
    return x >> 32;
}

uint getRightHalf(ull x)
{
    return x & 0xFFFFFFFFULL;
}

ull getCombinedHalves(uint a, uint b)
{
    return ((ull)a << 32) | ((ull)b & 0xFFFFFFFFULL);
}

void createRandomKeys()
{
    srand(time(NULL));

    for (int current = 0; current < 6; current++)
        key[current] = (rand() << 16) | (rand() & 0xFFFFU);
}

byte g(byte a, byte b, byte x)
{
    byte tmp = a + b + x;
    return (tmp << 2) | (tmp >> 6);
}

uint f(uint input)
{

    byte x[4], y[4];
    for (int current = 0; current < 4; current++)
    {
        x[3 - current] = (byte)input & 0xFF;
        input >>= 8;
    }

    y[1] = g(x[0] ^ x[1], x[2] ^ x[3], 1);
    y[0] = g(x[0], y[1], 0);
    y[2] = g(x[2] ^ x[3], y[1], 0);
    y[3] = g(x[3], y[2], 1);

    uint output = 0;
    for (int current = 0; current < 4; current++)
        output += ((uint)y[current]) << (8 * (3 - current));

    return output;
}

ull encrypt(ull plaintext)
{
    uint initialLeft = getLeftHalf(plaintext) ^ key[4];
    uint initialRight = getRightHalf(plaintext) ^ key[5];

    uint round1Left = initialLeft ^ initialRight;
    uint round1Right = initialLeft ^ f(round1Left ^ key[0]);

    uint round2Left = round1Right;
    uint round2Right = round1Left ^ f(round1Right ^ key[1]);

    uint round3Left = round2Right;
    uint round3Right = round2Left ^ f(round2Right ^ key[2]);

    uint round4Left = round3Left ^ f(round3Right ^ key[3]);
    uint round4Right = round4Left ^ round3Right;

    return getCombinedHalves(round4Left, round4Right);
}

void generatePlaintextCiphertextPairs(ull inputDiff)
{
    printf("Generating plain/ciphertext pairs for differential 0x%016llx...\n", inputDiff);

    srand(time(NULL));

    for (int current = 0; current < num_plaintexts; current++)
    {
        plaintext0[current] = (rand() & 0xFFFFULL) << 48;
        plaintext0[current] += (rand() & 0xFFFFULL) << 32;
        plaintext0[current] += (rand() & 0xFFFFULL) << 16;
        plaintext0[current] += (rand() & 0xFFFFULL);

        ciphertext0[current] = encrypt(plaintext0[current]);
        plaintext1[current] = plaintext0[current] ^ inputDiff;
        ciphertext1[current] = encrypt(plaintext1[current]);

        printf("[%d] P0-C0: 0x%llx-0x%llx, P1-C1: 0x%llx-0x%llx\n", current, plaintext0[current], ciphertext0[current], plaintext1[current], ciphertext1[current]);
    }
}

void decryptLastOperation()
{
    for (int current = 0; current < num_plaintexts; current++)
    {
        uint cipherLeft0 = getLeftHalf(ciphertext0[current]);
        uint cipherRight0 = getRightHalf(ciphertext0[current]) ^ cipherLeft0;
        uint cipherLeft1 = getLeftHalf(ciphertext1[current]);
        uint cipherRight1 = getRightHalf(ciphertext1[current]) ^ cipherLeft1;

        ciphertext0[current] = getCombinedHalves(cipherLeft0, cipherRight0);
        ciphertext1[current] = getCombinedHalves(cipherLeft1, cipherRight1);
    }
}

uint crackHighestRound(uint differential)
{
    uint subkey;
    uint fromTime = time(NULL);
    printf("Recovering last round subkey using output differential 0x%08x...\n", differential);

    for (subkey = 0x00000000U; subkey <= 0xFFFFFFFFU; subkey++)
    {
        int score = 0;

        for (int current = 0; current < num_plaintexts; current++)
        {

            uint cipherRight0 = getRightHalf(ciphertext0[current]);
            uint cipherLeft0 = getLeftHalf(ciphertext0[current]);
            uint cipherRight1 = getRightHalf(ciphertext1[current]);
            uint cipherLeft1 = getLeftHalf(ciphertext1[current]);

            uint cipherLeft = cipherLeft0 ^ cipherLeft1;
            uint candidate = cipherLeft ^ differential;

            uint fInput0 = cipherRight0 ^ subkey;
            uint fInput1 = cipherRight1 ^ subkey;
            uint fOutput0 = f(fInput0);
            uint fOutput1 = f(fInput1);
            uint computed = fOutput0 ^ fOutput1;

            if (candidate == computed)
            {
                score++;
            }
            else
            {
                break;
            }
        }

        if (score == num_plaintexts)
        {
            printf("Found subkey: 0x%x\n", subkey);
            break;
        }
    }
    uint toTime = time(NULL);
    printf("Recovering subkey took %i seconds.\n", (toTime - fromTime));
    return subkey;
}

void decryptHighestRound(uint crackedKey)
{
    for (int current = 0; current < num_plaintexts; current++)
    {
        uint cipherLeft0 = getRightHalf(ciphertext0[current]);
        uint cipherLeft1 = getRightHalf(ciphertext1[current]);

        uint cipherRight0 = f(cipherLeft0 ^ crackedKey) ^ getLeftHalf(ciphertext0[current]);
        uint cipherRight1 = f(cipherLeft1 ^ crackedKey) ^ getLeftHalf(ciphertext1[current]);

        ciphertext0[current] = getCombinedHalves(cipherLeft0, cipherRight0);
        ciphertext1[current] = getCombinedHalves(cipherLeft1, cipherRight1);
    }
}

int main(int argc, char **argv)
{
    printf("Differential Cryptanalysis on FEAL-4 using chosen-plaintext attack\n");
    printf("By Eduardo Messias\n\n");
    printf("------------------------------------\n");
    printf("Meet-in-the-middle attack:\n");

    num_plaintexts = 12;

    createRandomKeys();
    uint startTime = time(NULL);

    // Round 4
    printf("Round 4:\n");
    generatePlaintextCiphertextPairs(0x8080000080800000ULL);
    decryptLastOperation();
    uint crackedKey3 = crackHighestRound(0x02000000U);

    // Round 3
    printf("Round 3:\n");
    generatePlaintextCiphertextPairs(0x0000000080800000ULL);
    decryptLastOperation();
    decryptHighestRound(crackedKey3);
    uint crackedKey2 = crackHighestRound(0x02000000U);

    // Round 2
    printf("Round 2:\n");
    generatePlaintextCiphertextPairs(0x0000000002000000ULL);
    decryptLastOperation();
    decryptHighestRound(crackedKey3);
    decryptHighestRound(crackedKey2);
    uint crackedKey1 = crackHighestRound(0x02000000U);

    // Round 1
    printf("Round 1:\n");
    decryptHighestRound(crackedKey1);

    uint roundStartTime = time(NULL);
    uint crackedKey0 = 0;
    uint crackedKey4 = 0;
    uint crackedKey5 = 0;

    for (uint tmpK0 = 0; tmpK0 < 0xFFFFFFFFL; tmpK0++)
    {
        uint tmpK4 = 0;
        uint tmpK5 = 0;

        for (int current = 0; current < num_plaintexts; current++)
        {
            uint plainLeft0 = getLeftHalf(plaintext0[current]);
            uint plainRight0 = getRightHalf(plaintext0[current]);
            uint cipherLeft0 = getLeftHalf(ciphertext0[current]);
            uint cipherRight0 = getRightHalf(ciphertext0[current]);

            uint temp = f(cipherRight0 ^ tmpK0) ^ cipherLeft0;

            if (tmpK4 == 0)
            {
                tmpK4 = temp ^ plainLeft0;
                tmpK5 = temp ^ cipherRight0 ^ plainRight0;
            }
            else if (((temp ^ plainLeft0) != tmpK4) || ((temp ^ cipherRight0 ^ plainRight0) != tmpK5))
            {
                tmpK4 = 0;
                tmpK5 = 0;
                break;
            }
        }
        if (tmpK4 != 0)
        {

            crackedKey0 = tmpK0;
            crackedKey4 = tmpK4;
            crackedKey5 = tmpK5;

            break;
        }
    }

    printf("found key K0: 0x%08x\n", crackedKey0);
    printf("found key K4: 0x%08x\n", crackedKey4);
    printf("found key K5: 0x%08x\n", crackedKey5);
    uint endTime = time(NULL);
    printf("Total time: %i seconds.\n", (endTime - startTime));

    // Testing
    printf("Testing...\n");

    generatePlaintextCiphertextPairs(0x123FEC3C243BA9B2LL);

    key[0] = crackedKey0;
    key[1] = crackedKey1;
    key[2] = crackedKey2;
    key[3] = crackedKey3;
    key[4] = crackedKey4;
    key[5] = crackedKey5;

    for (int current = 0; current < num_plaintexts; current++)
    {
        ull a, b;
        a = encrypt(plaintext0[current]);
        b = encrypt(plaintext1[current]);
        if (a != ciphertext0[current] || b != ciphertext1[current])
        {
            printf("Error: encryption failed!\n");
            return 0;
        }
    }
    printf("Test passed. Each ciphertext generated using the keys obtained in the method are matching.\n");
    printf("Finished successfully.\n");
    return 0;
}