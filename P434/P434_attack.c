/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: supersingular isogeny parameters and generation of functions for P434
*********************************************************************************************/  

#include "P434_api_attack.h"
#include "../PQCrypto-SIDH/src/P434/P434.c"

// Simulating the iterative attack
#define BacktrackingInstance_EVE     BacktrackingInstance_EVE_SIDHp434
#define NextBacktrackingInstance_EVE NextBacktrackingInstance_EVE_SIDHp434
#define Oracle_EVE                   Oracle_EVE_SIDHp434
#define GuessingSecretBits_EVE       GuessingSecretBits_EVE_SIDHp434
#define IterativeAttack_EVE          IterativeAttack_EVE_SIDHp434
#define LastIsogenyRecovery_EVE      LastIsogenyRecovery_EVE_SIDHp434

#define BuildInstance_EVE      BuildInstance_EVE_SIKEp434
#define GuessCoefficient_EVE   GuessCoefficient_EVE_SIKEp434
#define LastCoefficient_EVE    LastCoefficient_EVE_SIKEp434

#include "../sidh_attack.c"
//#include "../sike_attack_uxtith.c"