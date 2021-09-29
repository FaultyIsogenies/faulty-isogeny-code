/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key exchange SIDHp503
*********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "../PQCrypto-SIDH/tests/test_extras.h"
#include "P503_api_attack.h"

#define SCHEME_NAME    "SIDHp503"

#define random_mod_order_A            random_mod_order_A_SIDHp503
#define random_mod_order_B            random_mod_order_B_SIDHp503
#define EphemeralKeyGeneration_A      EphemeralKeyGeneration_A_SIDHp503
#define EphemeralKeyGeneration_B      EphemeralKeyGeneration_B_SIDHp503
#define EphemeralSecretAgreement_A    EphemeralSecretAgreement_A_SIDHp503
#define EphemeralSecretAgreement_B    EphemeralSecretAgreement_B_SIDHp503

// Simulating the iterative attack
#define BacktrackingInstance_EVE     BacktrackingInstance_EVE_SIDHp503
#define NextBacktrackingInstance_EVE NextBacktrackingInstance_EVE_SIDHp503
#define Oracle_EVE                   Oracle_EVE_SIDHp503
#define GuessingSecretBits_EVE       GuessingSecretBits_EVE_SIDHp503
#define IterativeAttack_EVE          IterativeAttack_EVE_SIDHp503
#define LastIsogenyRecovery_EVE      LastIsogenyRecovery_EVE_SIDHp503

#include "../test_sidh_attack.c"