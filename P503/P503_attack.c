/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: supersingular isogeny parameters and generation of functions for P503
*********************************************************************************************/  

#include "P503_api_attack.h"
#include "../PQCrypto-SIDH/src/P503/P503.c"

// Simulating the iterative attack
#define BacktrackingInstance_EVE     BacktrackingInstance_EVE_SIDHp503
#define NextBacktrackingInstance_EVE NextBacktrackingInstance_EVE_SIDHp503
#define Oracle_EVE                   Oracle_EVE_SIDHp503
#define GuessingSecretBits_EVE       GuessingSecretBits_EVE_SIDHp503
#define IterativeAttack_EVE          IterativeAttack_EVE_SIDHp503
#define LastIsogenyRecovery_EVE      LastIsogenyRecovery_EVE_SIDHp503

#define BuildInstance_EVE      BuildInstance_EVE_SIKEp503
#define GuessCoefficient_EVE   GuessCoefficient_EVE_SIKEp503
#define LastCoefficient_EVE    LastCoefficient_EVE_SIKEp503

#include "../sidh_attack.c"
//#include "../sike_attack_uxtith.c"
