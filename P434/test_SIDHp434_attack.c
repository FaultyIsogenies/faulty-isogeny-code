/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key exchange SIDHp434
*********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "../PQCrypto-SIDH/tests/test_extras.h"
#include "P434_api_attack.h"

#define SCHEME_NAME    "SIDHp434"

#define random_mod_order_A            random_mod_order_A_SIDHp434
#define random_mod_order_B            random_mod_order_B_SIDHp434
#define EphemeralKeyGeneration_A      EphemeralKeyGeneration_A_SIDHp434
#define EphemeralKeyGeneration_B      EphemeralKeyGeneration_B_SIDHp434
#define EphemeralSecretAgreement_A    EphemeralSecretAgreement_A_SIDHp434
#define EphemeralSecretAgreement_B    EphemeralSecretAgreement_B_SIDHp434

// Simulating the iterative attack
#define BacktrackingInstance_EVE     BacktrackingInstance_EVE_SIDHp434
#define NextBacktrackingInstance_EVE NextBacktrackingInstance_EVE_SIDHp434
#define Oracle_EVE                   Oracle_EVE_SIDHp434
#define GuessingSecretBits_EVE       GuessingSecretBits_EVE_SIDHp434
#define IterativeAttack_EVE          IterativeAttack_EVE_SIDHp434
#define LastIsogenyRecovery_EVE      LastIsogenyRecovery_EVE_SIDHp434

#include "../test_sidh_attack.c"