// Corresponding to Ueno, Xagawa, Tanaka, Ito, Takahashi, and Homma paper (https://eprint.iacr.org/2021/849)
void BuildInstance_EVE(unsigned char* c_, unsigned char* c, const unsigned char *GuessedKeyB, const unsigned int iteration, const unsigned int g)
{
    /* Instance constructed from Encaps output */
    // Decode public key: x(P'), x(Q'), and  x(P'-Q')
    assert(g <= 2);
    memcpy(c_, c, CRYPTO_CIPHERTEXTBYTES);
    digit_t scalar[NWORDS_ORDER] = {0}, scalar_1[NWORDS_ORDER] = {0}, scalar_2[NWORDS_ORDER] = {0}, scalar_3[NWORDS_ORDER] = {0};
    decode_to_digits(GuessedKeyB, scalar, SECRETKEY_B_BYTES, NWORDS_ORDER);

    point_proj_t XP = {0}, XQ = {0}, XPQ = {0}, XP_ = {0}, XQ_ = {0}, XPQ_ = {0}, XR = {0}, XS = {0};
    fp2_decode(c, XP->X);
    fp2_decode(c + FP2_ENCODED_BYTES, XQ->X);
    fp2_decode(c + 2 * FP2_ENCODED_BYTES, XPQ->X);

    fpcopy((digit_t * ) & Montgomery_one, (XP->Z)[0]);
    fpcopy((digit_t * ) & Montgomery_one, (XQ->Z)[0]);
    fpcopy((digit_t * ) & Montgomery_one, (XPQ->Z)[0]);

    // Initialize constants: A24plus = A+2C, A24minus = A-2C, where C=1
    f2elm_t A24plus = {0}, A24minus = {0}, A = {0}, one = {0}, A24 = {0};
    fpcopy((digit_t * ) & Montgomery_one, one[0]);  // 1
    get_A(XP->X, XQ->X, XPQ->X, A);
    mp_add((digit_t * ) & Montgomery_one, (digit_t * ) & Montgomery_one, A24minus[0], NWORDS_FIELD);
    mp2_add(A, A24minus, A24plus);              // A + 2
    mp2_sub_p2(A, A24minus, A24minus);          // A - 2
    fp2div2(A24plus, A24);                      // (A + 2)/2
    fp2div2(A24, A24);                          // (A + 2)/4

    // +++ Computing 3^{e3 - iteration - 1} ... I tried using mp_mul() but I failed!
    unsigned int i;
    felm_t k = {0}, m = {0}, t = {0}, three = {0}, kp = {0}, kq = {0}, kpq = {0}, mscalar = {0};
    fpcopy((digit_t * ) & Montgomery_one, k);   // 1
    fpcopy((digit_t * ) & Montgomery_one, t);   // 1
    fpcopy((digit_t * ) & Montgomery_one, m);   // 1
    fpadd(k, k, three);                         // 2
    fpadd(k, three, three);                     // 3
    for (i = 0; i < ((int)OBOB_EXPON - (int)iteration - 1); i++) fpmul_mont(k, three, k);
    for (i = 0; i < ((int)OBOB_EXPON - 1); i++) fpmul_mont(m, three, m);

    memcpy((digit_t *) mscalar, (digit_t *) scalar, sizeof(digit_t) * NWORDS_ORDER);
    to_mont(mscalar, mscalar);
    fpmul_mont(k, mscalar, kp);
    for( i = 0; i < g; i++) fpadd(kp, m, kp);
    fpadd(k, t, kq);
    fpadd(kp, kq, kpq);
    fpsub(kq, t, kq);
    fpsub(kq, t, kq);

    from_mont(kp, kp);      // 3^{e3 - iteration - 1}*sk + 3^{e3 - 1}*g
    from_mont(kq, kq);      // (3^{e3 - iteration - 1} + 1) - 2
    from_mont(kpq, kpq);    // 3^{e3 - iteration - 1}*(sk + 1) + 3^{e3 - 1}*g + 1

    memcpy((digit_t *) scalar_1, (digit_t *) kp, sizeof(digit_t) * NWORDS_ORDER);
    memcpy((digit_t *) scalar_2, (digit_t *) kq, sizeof(digit_t) * NWORDS_ORDER);
    memcpy((digit_t *) scalar_3, (digit_t *) kpq, sizeof(digit_t) * NWORDS_ORDER);

    // New Point: x(S) = x(P+Q)
    fp2copy(XP->X, XS->X);
    fp2copy(XP->Z, XS->Z);
    fp2copy(XQ->X, XR->X);
    fp2copy(XQ->Z, XR->Z);
    xDBLADD(XR, XS, XPQ->X, XPQ->Z, A24);

    // x([2]Q)
    fp2inv_mont(XR->Z);
    fp2mul_mont(XR->X, XR->Z, XR->X);
    fp2correction(XR->X);
    fp2copy(one, XR->Z);
    // x(P+Q)
    fp2inv_mont(XS->Z);
    fp2mul_mont(XS->X, XS->Z, XS->X);
    fp2correction(XS->X);
    fp2copy(one, XS->Z);

    LADDER3PT(XP->X, XQ->X, XS->X, scalar_1, BOB, XP_, A);  // x(P - [3^{e3 - iteration - 1}*sk + 3^{e3 - 1}*g]Q)
    LADDER3PT(XR->X, XQ->X, XQ->X, scalar_2, BOB, XQ_, A);  // x(2Q + [3^{e3 - iteration - 1} - 1]Q) = x([3^{e3 - iteration - 1} + 1]Q)
    LADDER3PT(XP->X, XQ->X, XS->X, scalar_3, BOB, XPQ_, A); // x(P - [3^{e3 - iteration - 1}*(sk + 1) + 3^{e3 - 1}*g + 1]Q)

    // Computing affine x-coordinates
    inv_3_way(XP_->Z, XQ_->Z, XPQ_->Z);
    // x(P3)
    fp2mul_mont(XP_->X, XP_->Z, XP_->X);
    fp2correction(XP_->X);
    fp2copy(one, XP_->Z);
    // x(Q3)
    fp2mul_mont(XQ_->X, XQ_->Z, XQ_->X);
    fp2correction(XQ_->X);
    fp2copy(one, XQ_->Z);
    // x(R3)
    fp2mul_mont(XPQ_->X, XPQ_->Z, XPQ_->X);
    fp2correction(XPQ_->X);
    fp2copy(one, XPQ_->Z);
    
    // Writing the new instance into c_
    fp2_encode(XP_->X, c_);
    fp2_encode(XQ_->X, c_ + FP2_ENCODED_BYTES);
    fp2_encode(XPQ_->X, c_ + 2 * FP2_ENCODED_BYTES);
}

int GuessCoefficient_EVE(unsigned char* GuessedKeyB, unsigned char* K_, const unsigned char* K, const unsigned int iteration, const unsigned int g)
{
    int i;
    // +++ Computing 3^iteration ... I tried using mp_mul() but I failed!
    felm_t t = {0}, three = {0};
    fpcopy((digit_t*)&Montgomery_one, t);

    fpadd(t, t, three);     // 2
    fpadd(t, three,three);  // 3
    for(i = 0; i < iteration; i++)
        fpmul_mont(t, three, t);
    from_mont(t, t);        // 3^iteration

    // +++ Adding the guessing radix-3 coeff
    digit_t SecretKeyB[NWORDS_ORDER] = {0};
    decode_to_digits(GuessedKeyB, SecretKeyB, SECRETKEY_B_BYTES, NWORDS_ORDER);
    for(i = 0; i < g; i++)
        mp_add(SecretKeyB, t, SecretKeyB, NWORDS_ORDER);

    if ((memcmp(K, K_, CRYPTO_BYTES) == 0) || (g == 2))
        encode_to_bytes(SecretKeyB, GuessedKeyB, SECRETKEY_B_BYTES);
    return 0;
}

int LastCoefficient_EVE(unsigned char* GuessedKeyB, const unsigned char* PublicKeyB)
{
    // Last isogeny recovery by brute force (three choices)
    // +++ Computing 3^i ... I tried using mp_mul() but I failed!
    int i;
    felm_t t = {0}, three = {0};
    fpcopy((digit_t*)&Montgomery_one, t);

    fpadd(t, t, three);     // 2
    fpadd(t, three,three);  // 3
    for(i = 0; i < (int)OBOB_EXPON - 1; i++)
        fpmul_mont(t, three, t);

    from_mont(t, t);        // 3^(OBOB_EXPON - 1)

    // +++
    digit_t SecretKeyB[NWORDS_ORDER] = {0};
    unsigned char GuessedPublicKeyB[CRYPTO_PUBLICKEYBYTES];
    decode_to_digits(GuessedKeyB, SecretKeyB, SECRETKEY_B_BYTES, NWORDS_ORDER);

    // ---
    EphemeralKeyGeneration_B(GuessedKeyB, GuessedPublicKeyB);
    if (memcmp(GuessedPublicKeyB, PublicKeyB, CRYPTO_PUBLICKEYBYTES) == 0)
        return 0;

    // ---
    mp_add(SecretKeyB, t, SecretKeyB, NWORDS_ORDER);
    encode_to_bytes(SecretKeyB, GuessedKeyB, SECRETKEY_B_BYTES);
    EphemeralKeyGeneration_B(GuessedKeyB, GuessedPublicKeyB);
    if (memcmp(GuessedPublicKeyB, PublicKeyB, CRYPTO_PUBLICKEYBYTES) == 0)
        return 0;

    // ---
    mp_add(SecretKeyB, t, SecretKeyB, NWORDS_ORDER);
    encode_to_bytes(SecretKeyB, GuessedKeyB, SECRETKEY_B_BYTES);
    EphemeralKeyGeneration_B(GuessedKeyB, GuessedPublicKeyB);
    if (memcmp(GuessedPublicKeyB, PublicKeyB, CRYPTO_PUBLICKEYBYTES) == 0)
        return 0;

    return 1;
}