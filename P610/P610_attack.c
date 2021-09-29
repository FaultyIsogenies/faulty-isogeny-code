/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: supersingular isogeny parameters and generation of functions for P610
*********************************************************************************************/  

#include "P610_api_attack.h"
#include "../PQCrypto-SIDH/src/P610/P610.c"

// Simulating the iterative attack
#define BacktrackingInstance_EVE     BacktrackingInstance_EVE_SIDHp610
#define NextBacktrackingInstance_EVE NextBacktrackingInstance_EVE_SIDHp610
#define Oracle_EVE                   Oracle_EVE_SIDHp610
#define GuessingSecretBits_EVE       GuessingSecretBits_EVE_SIDHp610
#define IterativeAttack_EVE          IterativeAttack_EVE_SIDHp610
#define LastIsogenyRecovery_EVE      LastIsogenyRecovery_EVE_SIDHp610

#define BuildInstance_EVE      BuildInstance_EVE_SIKEp610
#define GuessCoefficient_EVE   GuessCoefficient_EVE_SIKEp610
#define LastCoefficient_EVE    LastCoefficient_EVE_SIKEp610

#include "../sidh_attack.c"
//#include "../sike_attack_uxtith.c"
