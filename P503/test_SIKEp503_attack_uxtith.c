/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: benchmarking/testing isogeny-based key exchange SIDHp503
*********************************************************************************************/ 

#include <stdio.h>
#include <string.h>
#include "../PQCrypto-SIDH/tests/test_extras.h"
#include "P503_api_attack.h"

#define SCHEME_NAME    "SIKEp503"

#define crypto_kem_keypair            crypto_kem_keypair_SIKEp503
#define crypto_kem_enc                crypto_kem_enc_SIKEp503
#define crypto_kem_dec                crypto_kem_dec_SIKEp503

#define BuildInstance_EVE      BuildInstance_EVE_SIKEp503
#define GuessCoefficient_EVE   GuessCoefficient_EVE_SIKEp503
#define LastCoefficient_EVE    LastCoefficient_EVE_SIKEp503

#include "../test_sike_attack.c"