/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key exchange
*********************************************************************************************/
#include <assert.h>

// Benchmark and test parameters  
#if defined(GENERIC_IMPLEMENTATION) || (TARGET == TARGET_ARM) 
    #define BENCH_LOOPS        5      // Number of iterations per bench 
    #define TEST_LOOPS         5      // Number of iterations per test
#else
    #define BENCH_LOOPS       100       
    #define TEST_LOOPS        10      
#endif

extern int ORACLE_CALLS;

int cryptotest_attack()
{
    unsigned int i;
    unsigned char PrivateKeyB[SIDH_SECRETKEYBYTES_B] = {0}, GuessedKeyB[SIDH_SECRETKEYBYTES_B] = {0};
    unsigned char PublicKeyB[SIDH_PUBLICKEYBYTES];
    int RUNS = 10;
    unsigned long long cycles_EVE = 0, cycles1, cycles2;
    int runtime_EVE = 0;
    printf("\n+++\tRecovering Bob's private key\n");
    printf("+++\tBobₛₖ : k₀ + k₁3 + k₂3² + ... + kₙ3ⁿ\n");
    printf("+++\tKey recovery printing: k₀k₁k₂...kₙ\n\n");
    for( i = 0; i < RUNS; i++)
    {
        printf("[%3d%%] Bobₛₖ: ", 100 * i / (int) RUNS);
        fflush(stdout);
        random_mod_order_B(PrivateKeyB);
        EphemeralKeyGeneration_B(PrivateKeyB, PublicKeyB);
        cycles1 = cpucycles();
        IterativeAttack_EVE(GuessedKeyB, PrivateKeyB);
        cycles2 = cpucycles();
        cycles_EVE = cycles_EVE + (cycles2 - cycles1);
        runtime_EVE = runtime_EVE + ORACLE_CALLS;
        assert(LastIsogenyRecovery_EVE(GuessedKeyB, PublicKeyB) == 0);
        assert(memcmp(GuessedKeyB, PrivateKeyB, SIDH_SECRETKEYBYTES_B) == 0);
        printf("\r\x1b[K");
    }
    printf("[%3d%%] All experiments PASSED\n", 100 * i / (int) RUNS);
    printf("\tAttack runs in ............................... %10lld millions of cycles\n", cycles_EVE/(1000000 * RUNS));
    printf("\tAttack performs .............................. %10d oracle calls \n", runtime_EVE/RUNS);
    return PASSED;
}

int main()
{
    int Status = PASSED;
    Status = cryptotest_attack();
    return Status;
}