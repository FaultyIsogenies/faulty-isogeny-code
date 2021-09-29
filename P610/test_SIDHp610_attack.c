/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key exchange SIDHp610
*********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "../PQCrypto-SIDH/tests/test_extras.h"
#include "P610_api_attack.h"

#define SCHEME_NAME    "SIDHp610"

#define random_mod_order_A            random_mod_order_A_SIDHp610
#define random_mod_order_B            random_mod_order_B_SIDHp610
#define EphemeralKeyGeneration_A      EphemeralKeyGeneration_A_SIDHp610
#define EphemeralKeyGeneration_B      EphemeralKeyGeneration_B_SIDHp610
#define EphemeralSecretAgreement_A    EphemeralSecretAgreement_A_SIDHp610
#define EphemeralSecretAgreement_B    EphemeralSecretAgreement_B_SIDHp610

// Simulating the iterative attack
#define BacktrackingInstance_EVE     BacktrackingInstance_EVE_SIDHp610
#define NextBacktrackingInstance_EVE NextBacktrackingInstance_EVE_SIDHp610
#define Oracle_EVE                   Oracle_EVE_SIDHp610
#define GuessingSecretBits_EVE       GuessingSecretBits_EVE_SIDHp610
#define IterativeAttack_EVE          IterativeAttack_EVE_SIDHp610
#define LastIsogenyRecovery_EVE      LastIsogenyRecovery_EVE_SIDHp610

#include "../test_sidh_attack.c"