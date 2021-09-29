/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: supersingular isogeny parameters and generation of functions for P751
*********************************************************************************************/  

#include "P751_api_attack.h"
#include "../PQCrypto-SIDH/src/P751/P751.c"

// Simulating the iterative attack
#define BacktrackingInstance_EVE     BacktrackingInstance_EVE_SIDHp751
#define NextBacktrackingInstance_EVE NextBacktrackingInstance_EVE_SIDHp751
#define Oracle_EVE                   Oracle_EVE_SIDHp751
#define GuessingSecretBits_EVE       GuessingSecretBits_EVE_SIDHp751
#define IterativeAttack_EVE          IterativeAttack_EVE_SIDHp751
#define LastIsogenyRecovery_EVE      LastIsogenyRecovery_EVE_SIDHp751

#define BuildInstance_EVE      BuildInstance_EVE_SIKEp751
#define GuessCoefficient_EVE   GuessCoefficient_EVE_SIKEp751
#define LastCoefficient_EVE    LastCoefficient_EVE_SIKEp751

#include "../sidh_attack.c"
//#include "../sike_attack_uxtith.c"
