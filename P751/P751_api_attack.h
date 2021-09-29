/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: API header file for P751
*********************************************************************************************/  

#ifndef P751_API_ATTACK_H
#define P751_API_ATTACK_H

#include "../PQCrypto-SIDH/src/P751/P751_api.h"

#define prime p751

// Backtracking instances: attacking to Bob
// Input:  a guessed private key GuessedKeyB in the range [0, 2^Floor(Log(2,3^239)) - 1], stored in 47 bytes.
//         Two integer iteration and swap in [0, 237] and {0,1,2}, respectively.
// Output: a backtracking public key PublicKeyA consisting of 3 GF(p751^2) elements encoded in 564 bytes,
//         which ensures iteration-th isogenous curve is E : y^2 = x^3 +6x^2 + x
int BacktrackingInstance_EVE_SIDHp751(unsigned char* PublicKeyA, const unsigned char *GuessedKeyB, const unsigned int iteration, const unsigned int swap);
int NextBacktrackingInstance_EVE_SIDHp751(unsigned char* PublicKeyA, const unsigned int iteration, const int choice);

// Oracle (it verifies curve supersingularity by kernel point check): Bob's ephemeral shared secret computation.
// Bob does not know he received a backtracking instance (this function is simulating the fault injection
// It produces a shared secret key SharedSecretB using his secret key PrivateKeyB and Alice's public key PublicKeyA
// Inputs: Bob's PrivateKeyB is an integer in the range [0, 2^Floor(Log(2,3^239)) - 1], stored in 47 bytes. 
//         Alice's PublicKeyA consists of 3 GF(p751^2) elements encoded in 564 bytes.
//         an integer iteration in [0, 237].
// Output: a shared secret SharedSecretB that consists of one element in GF(p751^2) encoded in 110 bytes.
//         Additionally, this injects the faults at the iteration-th isogeny (either on the curve coeff. or kernel gen.).
//         Thus, the Oracle verifies is the last kernel point has order 3. If so, then the j-invariant output determines
//         a supersingular curve. If not, then the fault injection degenerated the output.
//         Returning 1 means failure in the supersingularity test.
int Oracle_EVE_SIDHp751(unsigned char* SharedSecretB, const unsigned char* PrivateKeyB, const unsigned char* PublicKeyA, const unsigned int iteration);

// Guessing Secret Bits: assuming Bob's private key is written as k_0 + k_1*3 + ... + k_i*3^i + ... + k_{238}*3^{238}
// Input:  First "iteration - 1" guessed coefficients k_i's
// Output: the iteration-th coefficient k_{iteration}
int GuessingSecretBits_EVE_SIDHp751(unsigned char* GuessedKeyB, const unsigned char* PrivateKeyB, const unsigned int iteration);

// Simulating the iterative attack
int IterativeAttack_EVE_SIDHp751(unsigned char* GuessedKeyB, const unsigned char* PrivateKeyB);

// Recovery last isogeny
int LastIsogenyRecovery_EVE_SIDHp751(unsigned char* GuessedKeyB, const unsigned char* PublicKeyB);

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Building instance: improve version from Ueno, Xagawa, Tanaka, Ito, Takahashi, and Homma paper: eprint 2021/849
void BuildInstance_EVE_SIKEp751(unsigned char* c_, unsigned char* c, const unsigned char *GuessedKeyB, const unsigned int iteration, const unsigned int g);
// Guess the ith radix-3 coefficient by comparing K == Decaps(s, sk3, pk3, c0, c1)
int GuessCoefficient_EVE_SIKEp751(unsigned char* GuessedKeyB, unsigned char* K_, const unsigned char* K, const unsigned int iteration, const unsigned int g);
// Recovery last isogeny
int LastCoefficient_EVE_SIKEp751(unsigned char* GuessedKeyB, const unsigned char* PublicKeyB);
#endif