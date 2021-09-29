/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: ephemeral supersingular isogeny Diffie-Hellman key exchange (SIDH)
*********************************************************************************************/ 

#include <stdio.h>
#include <assert.h>

typedef struct { f2elm_t X; f2elm_t Y; f2elm_t Z; } point_full_proj;  // Point representation in full projective XYZ Montgomery coordinates 
typedef point_full_proj point_full_proj_t[1];
int ORACLE_CALLS = 0;

void fp2pow(const f2elm_t a, const felm_t exp, f2elm_t c)
{
   f2elm_t tmp = {0}, one = {0};
   fpcopy((digit_t*)&Montgomery_one, one[0]); // 1
   fp2copy(one, c);
   fp2copy(a, tmp);

   int i, j;
   uint64_t flag;
   for(i = 0; i < NWORDS_FIELD; i++)
   {
      flag = 1;
      for(j = 0; j < RADIX; j++)
      {
         if( (flag & exp[i]) != 0 )
            fp2mul_mont(c, tmp, c);

         fp2sqr_mont(tmp, tmp);
         flag <<= 1;
      };
   };
};

int fp2_issquare(const f2elm_t a, f2elm_t b)
{
    // Algorithm 9 from 
    //                   G. Adj and F. Rodriguez-Henriquez, 
    //                   "Square Root Computation over Even Extension Fields," in IEEE Transactions on Computers, 
    //                   vol. 63, no. 11, pp. 2829-2841, Nov. 2014, doi: 10.1109/TC.2013.145.
    // Preprint version at https://eprint.iacr.org/2012/685
    
    f2elm_t a1 = {0}, alpha = {0}, alpha_conjugated = {0}, a0 = {0}, minus_one = {0}, zero = {0}, x0 = {0};
    fpcopy((digit_t*)&Montgomery_one, minus_one[0]); //  1
    fp2sub(zero, minus_one, minus_one);              // -1
    fp2correction(minus_one);

    // the prime variable is defined as pXXX in PXXX_api_attack.h where XXX is either 434, 503, 610, and 751
    felm_t p_minus_1_halves = {0}, p_minus_3_quarters = {0}, p = {0};
    fpcopy((digit_t *)prime, p);
    p_minus_1_halves[0] = 1;
    p_minus_3_quarters[0] = 3;
    mp_sub((digit_t *)prime, (digit_t *)p_minus_1_halves, (digit_t *)p_minus_1_halves, NWORDS_FIELD);
    fpdiv2(p_minus_1_halves, p_minus_1_halves);
    mp_sub((digit_t *)prime, (digit_t *)p_minus_3_quarters, (digit_t *)p_minus_3_quarters, NWORDS_FIELD);
    fpdiv2(p_minus_3_quarters, p_minus_3_quarters);
    fpdiv2(p_minus_3_quarters, p_minus_3_quarters);

    fp2pow(a, p_minus_3_quarters, a1);               // a1 <- a^( [p-3]/4)
    fp2correction(a1);
    fp2sqr_mont(a1, alpha);                          // alpha <- a1^2
    fp2mul_mont(alpha, a, alpha);                    // alpha <- a1^2 * a
    fpcopy(alpha[0], alpha_conjugated[0]);           //
    fpsub(zero[0], alpha[1], alpha_conjugated[1]);   // alpha_conjugated <- alpha[0] - alpha[1]*i
    fp2mul_mont(alpha_conjugated, alpha, a0);        // a0 <- alpha^p * alpha

    fp2correction(alpha);
    fp2correction(a0);

    //if (fp2_compare(minus_one, a0) == 0)
    if ((memcmp(minus_one[0], a0[0], NBITS_TO_NBYTES(NBITS_FIELD)) == 0) & (memcmp(minus_one[1], a0[1], NBITS_TO_NBYTES(NBITS_FIELD)) == 0))
        return 0;

    fp2mul_mont(a1, a, x0);                              // x0 <- a1 * a
    //if (fp2_compare(minus_one, alpha) == 0)
    if ((memcmp(minus_one[0], alpha[0], NBITS_TO_NBYTES(NBITS_FIELD)) == 0) & (memcmp(minus_one[1], alpha[1], NBITS_TO_NBYTES(NBITS_FIELD)) == 0))
    {
        // b <- (i * x0) = (-x[1]) + (x[0] * i)
        fpcopy(x0[1], b[0]);
        fpneg(b[0]);
        fpcopy(x0[0], b[1]);
    }
    else
    {
        fp2sub(alpha, minus_one, alpha);     // (alpha + 1)
        fp2correction(alpha);
        fp2pow(alpha, p_minus_1_halves, b);  // b <- (alpha + 1)^([p-1]/2)
        fp2correction(b);
        fp2mul_mont(b, x0, b);               // (alpha + 1)^([p-1]/2) * x0
    };
    return 1;
};

void sqrt_Fp2(const f2elm_t u, f2elm_t y)
{ // Computes square roots of elements in (Fp2)^2 using Hamburg's trick. 
    felm_t t0, t1, t2, t3;
    digit_t *a  = (digit_t*)u[0], *b  = (digit_t*)u[1];
    unsigned int i;

    fpsqr_mont(a, t0);                   // t0 = a^2
    fpsqr_mont(b, t1);                   // t1 = b^2
    fpadd(t0, t1, t0);                   // t0 = t0+t1 
    fpcopy(t0, t1);
    for (i = 0; i < OALICE_BITS - 2; i++) {   // t = t3^((p+1)/4)
        fpsqr_mont(t1, t1);
    }
    for (i = 0; i < OBOB_EXPON; i++) {
        fpsqr_mont(t1, t0);
        fpmul_mont(t1, t0, t1);
    }  
    fpadd(a, t1, t0);                    // t0 = a+t1      
    fpdiv2(t0, t0);                      // t0 = t0/2 
    fpcopy(t0, t2);
    fpinv_chain_mont(t2);                // t2 = t0^((p-3)/4)      
    fpmul_mont(t0, t2, t1);              // t1 = t2*t0             
    fpmul_mont(t2, b, t2);               // t2 = t2*b       
    fpdiv2(t2, t2);                      // t2 = t2/2 
    fpsqr_mont(t1, t3);                  // t3 = t1^2              
    fpcorrection(t0);
    fpcorrection(t3);
           
    if (memcmp(t0, t3, NBITS_TO_NBYTES(NBITS_FIELD)) == 0) {
        fpcopy(t1, y[0]);
        fpcopy(t2, y[1]);
    } else {
        fpneg(t1);
        fpcopy(t2, y[0]);
        fpcopy(t1, y[1]);
    }
}

unsigned int check_fcondition(const f2elm_t A, const f2elm_t C)
{
    // Checking if (A:C) determines an fp-curve coefficient
    // Assuming i^2 = - 1, we have A = a + b*i and C = c + d*i
    felm_t bc, ad;
    fpmul_mont(A[0], C[1], ad);
    fpcorrection(ad);
    fpmul_mont(A[1], C[0], bc);
    fpcorrection(bc);

    unsigned int i;
    for (i = 0; i < NWORDS_FIELD; i++) {
        if (ad[i] != bc[i]) return 0;
    }
    return 1;
}

void insert_zero(f2elm_t A, f2elm_t C)
{
    // Inserting zeros to the imaginary part of A and C
    unsigned int i;
    for (i = 0; i < NWORDS_FIELD; i++)
    {
        A[1][i] = 0;
        C[1][i] = 0;
    }
}

unsigned int iszero(const digit_t* k)
{
    // Checking if (A:C) determines an fp-curve coefficient
    // Assuming i^2 = - 1, we have A = a + b*i and C = c + d*i
    unsigned int i;
    for (i = 0; i < NWORDS_ORDER; i++) {
        if (k[i] != 0) return 0;
    }
    return 1;
}

unsigned int is_f2elm_zero(const f2elm_t x)
{
    // Is x = 0? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
    unsigned int i;

    for (i = 0; i < NWORDS_FIELD; i++) {
        if ((x[0][i] != 0) | (x[1][i] != 0)) return 0;
    }
    return 1;
}

unsigned int is_felm(const f2elm_t x)
{
    // Is x = 0? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
    unsigned int i;

    for (i = 0; i < NWORDS_FIELD; i++) {
        if (x[1][i] != 0) return 0;
    }
    return 1;
}

unsigned int isinfinity(const point_proj_t P)
{
    // Is P->Z = 0? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
    f2elm_t Z = {0};
    fp2copy(P->Z, Z);
    fp2correction(Z);
    return is_f2elm_zero(Z);
}

unsigned int isequal_proj(const point_proj_t P, const point_proj_t Q)
{
    // Is x(P) = x(Q)? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
    f2elm_t XPZQ = {0}, ZPXQ = {0};
    unsigned int i;

    fp2mul_mont(P->X, Q->Z, XPZQ);
    fp2mul_mont(P->Z, Q->X, ZPXQ);
    fp2correction(XPZQ);
    fp2correction(ZPXQ);

    for (i = 0; i < NWORDS_FIELD; i++)
        if ((XPZQ[0][i] != ZPXQ[0][i]) | (XPZQ[1][i] != ZPXQ[1][i])) return 0;

    return 1;
}

void toAffine(const f2elm_t A, const point_proj_t P, point_full_proj_t R)
{ // Given an xz-only representation on a montgomery curve, compute its affine representation
    f2elm_t zero = {0}, invz = {0}, one = {0}, tmp = {0};
    fpcopy((digit_t*)&Montgomery_one, one[0]);    
    if (1-isinfinity(P)) {
        fp2copy(P->Z, invz);
        fp2inv_mont(invz);
        fp2correction(invz);

        fp2mul_mont(P->X, invz, R->X); // x
        fp2correction(R->X);
        fp2mul_mont(R->X, A, R->Y);    // A*x
        fp2sqr_mont(R->X, tmp);        // x^2
        fp2add(tmp, R->Y, R->Y);       // x^2 + A*x
        fp2mul_mont(R->Y, R->X, R->Y); // x^3 + A*x^2
        fp2add(R->Y, R->X, tmp);       // x^3 + A*x^2 + x
        fp2correction(tmp);
        //sqrt_Fp2(tmp, R->Y);                          // sqrt(x^3 + A*x^2 + x) <--- It fails with tmp in GF(p) [why!???!]
        assert(fp2_issquare(tmp, R->Y) == 1);           // sqrt(x^3 + A*x^2 + x) <--- From Adj and Rodriguez-Henriquez work
        fp2correction(R->Y);

        // ---
        fp2sqr_mont(R->Y, invz);
        fp2correction(invz);
        assert(memcmp(invz[0], tmp[0], NBITS_TO_NBYTES(NBITS_FIELD)) == 0);
        assert(memcmp(invz[1], tmp[1], NBITS_TO_NBYTES(NBITS_FIELD)) == 0);
        // ---

        fp2copy(one, R->Z);
    } else {
        fp2copy(zero, R->X);
        fp2copy(one, R->Y); 
        fp2copy(zero, R->Z);               // R = EM!0;
    }
}

static void getDiffPoint(const f2elm_t A, const point_full_proj_t R, const point_full_proj_t S, point_proj_t D)
{
    // This function assumes R->Z = 1 and S->Z = 1
    f2elm_t t0, t1, t2, one = {0};
    fpcopy((digit_t*)&Montgomery_one, one[0]); 

    fp2sub(R->X, S->X, t0);
    fp2inv_mont(t0);
    fp2correction(t0);
    fp2add(R->Y, S->Y, t1);
    fp2mul_mont(t0, t1, t0);
    fp2correction(t0);
    fp2sqr_mont(t0, t1);
    fp2correction(t1);
    fp2add(R->X, S->X, t2);
    fp2add(t2, A, t2);
    fp2sub(t1, t2, D->X);
    fp2correction(D->X);
    fp2copy(one, D->Z);
}

int BacktrackingInstance_EVE(unsigned char* PublicKeyA, const unsigned char *GuessedKeyB, const unsigned int iteration, const unsigned int swap)
{
    // Backtracking instances construction.
    // For more details check description of BacktrackingInstance_EVE_SIDHpXXX in the PXXX_api_attack.h file
    // Initialize basis at E_0 : y² = x³ + 6x² + x
    point_proj_t XPB = {0}, XQB = {0}, XRB = {0};
    fpcopy((digit_t*)&Montgomery_one, (XPB->Z)[0]);
    fpcopy((digit_t*)&Montgomery_one, (XQB->Z)[0]);
    fpcopy((digit_t*)&Montgomery_one, (XRB->Z)[0]);

    // swapping the points
    if (swap == 0)
        init_basis((digit_t *)B_gen, XPB->X, XQB->X, XRB->X);
    if (swap == 1)
        init_basis((digit_t *)B_gen, XPB->X, XRB->X, XQB->X);
    else if (swap == 2)
        init_basis((digit_t *)B_gen, XRB->X, XQB->X, XPB->X);
    else
        assert((swap < 3) && (swap >= 0));

    // Initialize curve constants: A24minus = A-2C, A24plus = A+2C, where A=6, C=1
    // Additionally, a24 = (A + 2)/4 = (6 + 2)/4 = 2
    unsigned int i, j = 0;

    point_proj_t phiP = {0}, phiQ = {0}, phiR = {0},
    phiP3 = {0}, phiQ3 = {0}, phiR3 = {0},
    tmp = {0}, R = {0}, K = {0};
    point_full_proj_t phiP_affine = {0}, phiQ_affine = {0};
    fpcopy((digit_t * ) & Montgomery_one, (phiP->Z)[0]);
    fpcopy((digit_t * ) & Montgomery_one, (phiQ->Z)[0]);
    fpcopy((digit_t * ) & Montgomery_one, (phiR->Z)[0]);

    f2elm_t a24 = {0}, A24plus = {0}, A24minus = {0}, C24 = {0}, A = {0}, one = {0}, coeff[3];
    fpcopy((digit_t * ) & Montgomery_one, one[0]);
    fpcopy((digit_t * ) & Montgomery_one, a24[0]);
    fp2add(a24, a24, a24);               // a24  <- 2
    fp2add(a24, a24, A24minus);          // A-2C <- 4
    fp2add(a24, A24minus, A);            // A    <- 6
    fp2add(A24minus, A24minus, A24plus); // A+2C <- 8

    // We store phi(XQB) at phiP variable: phi(XQP) determines the dual kernel
    fp2copy(XQB->X, phiP->X);
    fp2copy(XQB->Z, phiP->Z);

    // Isogeny mappings moving from E_0 into E_i : y² = x³ + Ax² + x
    digit_t scalar_plus_one[NWORDS_ORDER] = {0}, scalar[NWORDS_ORDER] = {0};
    scalar_plus_one[0] = 1;
    decode_to_digits(GuessedKeyB, scalar, SECRETKEY_B_BYTES, NWORDS_ORDER);
    mp_add(scalar, scalar_plus_one, scalar_plus_one, NWORDS_ORDER);
    LADDER3PT(XPB->X, XQB->X, XRB->X, scalar, BOB, R, A);

    // Moving from E_0 into E_i
    // ------------------------> Non-optimal multiplicative 3-isogeny chain
    xTPLe(R, R, A24minus, A24plus, (int) OBOB_EXPON - (int) iteration);
    for (i = 1; i <= iteration; i++) {
        //printf("[%u] 3-isogeny mapping with iteration %u\n", i, iteration - i);
        fp2copy(R->X, K->X);
        fp2copy(R->Z, K->Z);
        xTPLe(K, K, A24minus, A24plus, (int) iteration - i);
        get_3_isog(K, A24minus, A24plus, coeff);

        eval_3_isog(R, coeff);
        eval_3_isog(phiP, coeff);
    }

    // Building the suitable basis: <phiP + [k]phiQ> = <phi(Q)>
    fp2sub(A24plus, A24minus, C24);      // 4C
    fp2add(A24plus, A24minus, A);        // 2A' = (A' + 2C) + (A' - 2C)
    fp2add(A, A, A);                     // 4A'
    fp2copy(C24, a24);
    fp2inv_mont(a24);                    // (1 / 4C)
    fp2correction(a24);
    fp2mul_mont(A, a24, A);              // A = (4A') / (4C)
    fp2correction(A);
    fp2mul_mont(a24, A24plus, a24);      // (A' + 2C) / (4C) = (A + 2)/4
    fp2correction(a24);

    xTPLe(phiP, phiP3, A24minus, A24plus, (int) (OBOB_EXPON - 1));
    f2elm_t X2 = {0};
    int breaking = fp2_issquare(A, X2);
    unsigned char XCOORD[FP2_ENCODED_BYTES] = {0};
    do {
        //printf("[elligator]\t%d\n", j);
        fp2zero(phiQ->X);
        fp2zero(phiQ->Z);
        fpcopy((digit_t * ) & Montgomery_one, (phiQ->Z)[0]);
        /**/
        breaking = 0;
        while (breaking == 0) {
            fp2zero(phiQ->X);
            randombytes(XCOORD, FP2_ENCODED_BYTES);
            fp2_decode(XCOORD, phiQ->X);

            fp2mul_mont(phiQ->X, A, phiQ->Z);       // A*x
            fp2correction(phiQ->Z);
            fp2sqr_mont(phiQ->X, X2);               // x^2
            fp2correction(X2);
            fp2add(X2, phiQ->Z, phiQ->Z);           // x^2 + A*x
            fp2mul_mont(phiQ->Z, phiQ->X, phiQ->Z); // x^3 + A*x^2
            fp2correction(phiQ->Z);
            fp2add(phiQ->Z, phiQ->X, X2);           // x^3 + A*x^2 + x
            fp2correction(X2);
            //sqrt_Fp2(X2,  phiQ->Z);               // sqrt(x^3 + A*x^2 + x) <--- It fails with tmp in GF(p) [why!???!]
            breaking = fp2_issquare(X2, phiQ->Z);   // sqrt(x^3 + A*x^2 + x) <--- From Adj and Rodriguez-Henriquez work
        }
        fp2zero(phiQ->Z);
        fpcopy((digit_t * ) & Montgomery_one, (phiQ->Z)[0]);
        /**/

        xDBLe(phiQ, phiQ, A24plus, C24, (int)(OALICE_BITS));
        xTPLe(phiQ, phiQ3, A24minus, A24plus, (int)(OBOB_EXPON) - 1);
        fp2correction(phiQ3->Z);
        xTPL(phiQ3, tmp, A24minus, A24plus);
        fp2correction(tmp->Z);
        ++j;

    } while (((1 - isinfinity(tmp)) || isinfinity(phiQ3)) || isequal_proj(phiQ3, phiP3));

    // Building the basis x(phiP) = x(phi(QB)), and x(phiP) (including x(phiP - phiQ)) with Z-coordinate equal one
    toAffine(A, phiP, phiP_affine);
    toAffine(A, phiQ, phiQ_affine);
    getDiffPoint(A, phiP_affine, phiQ_affine, phiR);
    fp2copy(phiP_affine->X, phiP->X);
    fp2copy(one, phiP->Z);
    fp2copy(phiQ_affine->X, phiQ->X);
    fp2copy(one, phiQ->Z);

    fp2correction(phiP->X);
    fp2correction(phiQ->X);
    fp2correction(phiR->X);

    // === Testing
    xTPLe(phiP, phiP3, A24minus, A24plus, (int) (OBOB_EXPON - 1));
    xTPLe(phiQ, phiQ3, A24minus, A24plus, (int) (OBOB_EXPON - 1));
    xTPLe(phiR, phiR3, A24minus, A24plus, (int) (OBOB_EXPON - 1));

    inv_3_way(phiP3->Z, phiQ3->Z, phiR3->Z);
    // x(P3)
    fp2mul_mont(phiP3->X, phiP3->Z, phiP3->X);
    fp2correction(phiP3->X);
    fp2copy(one, phiP3->Z);
    // x(Q3)
    fp2mul_mont(phiQ3->X, phiQ3->Z, phiQ3->X);
    fp2correction(phiQ3->X);
    fp2copy(one, phiQ3->Z);
    // x(R3)
    fp2mul_mont(phiR3->X, phiR3->Z, phiR3->X);
    fp2correction(phiR3->X);
    fp2copy(one, phiR3->Z);

    // ---
    xTPL(phiP3, tmp, A24minus, A24plus);
    fp2correction(tmp->X);
    fp2correction(tmp->Z);
    assert(isinfinity(tmp) == 1);
    // ---
    xTPL(phiQ3, tmp, A24minus, A24plus);
    fp2correction(tmp->X);
    fp2correction(tmp->Z);
    assert(isinfinity(tmp) == 1);
    // ---
    xTPL(phiR3, tmp, A24minus, A24plus);
    fp2correction(tmp->X);
    fp2correction(tmp->Z);
    assert(isinfinity(tmp) == 1);
    // ===

    // Generating the dual instance: recall x(phiP) = x(phi(QB))
    // --- XPB <- phiP + [scalar]phiQ
    LADDER3PT(phiP->X, phiQ->X, phiR->X, scalar, BOB, XPB, A);
    fp2inv_mont(XPB->Z);
    fp2correction(XPB->Z);
    fp2mul_mont(XPB->X, XPB->Z, XPB->X);
    fp2correction(XPB->X);
    fp2copy(one, XPB->Z);
    // --- XQB <- -phiQ
    fp2copy(phiQ->X, XQB->X);
    fp2copy(phiQ->Z, XQB->Z);
    // --- XRB <- XPB - XQB = phiP + [scalar + 1]phiQ
    LADDER3PT(phiP->X, phiQ->X, phiR->X, scalar_plus_one, BOB, XRB, A);
    fp2inv_mont(XRB->Z);
    fp2correction(XRB->Z);
    fp2mul_mont(XRB->X, XRB->Z, XRB->X);
    fp2correction(XRB->X);
    fp2copy(one, XRB->Z);

    // At this point, we have XPB + [scalar]XQB = (phiP + [scalar]phiQ) + [scalar](-phiQ) = phiP = x(phi(QB))
    xTPLe(XPB, phiP3, A24minus, A24plus, (int) (OBOB_EXPON - 1));
    xTPLe(XQB, phiQ3, A24minus, A24plus, (int) (OBOB_EXPON - 1));
    xTPLe(XRB, phiR3, A24minus, A24plus, (int) (OBOB_EXPON - 1));

    // === Testing
    inv_3_way(phiP3->Z, phiQ3->Z, phiR3->Z);
    // x(P3)
    fp2mul_mont(phiP3->X, phiP3->Z, phiP3->X);
    fp2correction(phiP3->X);
    fp2copy(one, phiP3->Z);
    // x(Q3)
    fp2mul_mont(phiQ3->X, phiQ3->Z, phiQ3->X);
    fp2correction(phiQ3->X);
    fp2copy(one, phiQ3->Z);
    // x(R3)
    fp2mul_mont(phiR3->X, phiR3->Z, phiR3->X);
    fp2correction(phiR3->X);
    fp2copy(one, phiR3->Z);

    // ---
    xTPL(phiP3, tmp, A24minus, A24plus);
    fp2correction(tmp->X);
    fp2correction(tmp->Z);
    assert(isinfinity(tmp) == 1);
    // ---
    xTPL(phiQ3, tmp, A24minus, A24plus);
    fp2correction(tmp->X);
    fp2correction(tmp->Z);
    assert(isinfinity(tmp) == 1);
    // ---
    xTPL(phiR3, tmp, A24minus, A24plus);
    fp2correction(tmp->X);
    fp2correction(tmp->Z);
    assert(isinfinity(tmp) == 1);

    // =======================================================
    //printf("// Eve's instance for iteration %u\n", iteration);
    fp2_encode(XPB->X, PublicKeyA);
    fp2copy(one, XPB->Z);
    fp2_encode(XQB->X, PublicKeyA + FP2_ENCODED_BYTES);
    fp2copy(one, XQB->Z);
    fp2_encode(XRB->X, PublicKeyA + 2 * FP2_ENCODED_BYTES);
    fp2copy(one, XRB->Z);

    fp2zero(XPB->X);
    fp2zero(XQB->X);
    fp2zero(XRB->X);

    fp2_decode(PublicKeyA, XPB->X);
    fp2_decode(PublicKeyA + FP2_ENCODED_BYTES, XQB->X);
    fp2_decode(PublicKeyA + 2 * FP2_ENCODED_BYTES, XRB->X);

    //get_A(XPB->X, XQB->X, XRB->X, A);
    LADDER3PT(XPB->X, XQB->X, XRB->X, scalar, BOB, R, A);
    assert(isequal_proj(R, phiP) == 1);

    fp2copy(XPB->X, phiP->X);
    fp2copy(XPB->Z, phiP->Z);
    fp2copy(XQB->X, phiQ->X);
    fp2copy(XQB->Z, phiQ->Z);
    fp2copy(XRB->X, phiR->X);
    fp2copy(XRB->Z, phiR->Z);

    // Next kernel is image point of either [3^{e3-i-1}](P + [scalar]Q), [3^{e3-i-1}](P + [scalar + 3^i]Q),
    // or [3^{e3-i-1}](P + [scalar + 2*(3^i)]Q). Recall, scalar is smaller than 3^i.
    digit_t scalar_0[NWORDS_ORDER] = {0}, scalar_1[NWORDS_ORDER] = {0}, scalar_2[NWORDS_ORDER] = {0};

    // +++ Computing 3^i ... I tried using mp_mul() but I failed!
    felm_t out = {0}, three = {0};
    fpcopy((digit_t * ) & Montgomery_one, out);
    fpadd(out, out, three); // 2
    fpadd(out, three, three); // 3
    for (i = 0; i < iteration; i++)
        fpmul_mont(out, three, out);

    fpadd(out, out, three);
    from_mont(out, out);
    from_mont(three, three);

    memcpy((digit_t *) scalar_1, (digit_t *) out, sizeof(digit_t) * NWORDS_ORDER);
    memcpy((digit_t *) scalar_2, (digit_t *) three, sizeof(digit_t) * NWORDS_ORDER);

    mp_add(scalar, scalar_0, scalar_0, NWORDS_ORDER); // scalar
    mp_add(scalar, scalar_1, scalar_1, NWORDS_ORDER); // scalar + 3^i
    mp_add(scalar, scalar_2, scalar_2, NWORDS_ORDER); // scalar + 2*(3^i)

    LADDER3PT(phiP->X, phiQ->X, phiR->X, scalar_0, BOB, phiP3, A);
    LADDER3PT(phiP->X, phiQ->X, phiR->X, scalar_1, BOB, phiQ3, A);
    LADDER3PT(phiP->X, phiQ->X, phiR->X, scalar_2, BOB, phiR3, A);

    xTPLe(phiP3, phiP3, A24minus, A24plus, (int) (OBOB_EXPON) - (int) iteration - 1);
    xTPLe(phiQ3, phiQ3, A24minus, A24plus, (int) (OBOB_EXPON) - (int) iteration - 1);
    xTPLe(phiR3, phiR3, A24minus, A24plus, (int) (OBOB_EXPON) - (int) iteration - 1);

    inv_3_way(phiP3->Z, phiQ3->Z, phiR3->Z);
    // x(P3)
    fp2mul_mont(phiP3->X, phiP3->Z, phiP3->X);
    fp2correction(phiP3->X);
    fp2copy(one, phiP3->Z);
    // x(Q3)
    fp2mul_mont(phiQ3->X, phiQ3->Z, phiQ3->X);
    fp2correction(phiQ3->X);
    fp2copy(one, phiQ3->Z);
    // x(R3)
    fp2mul_mont(phiR3->X, phiR3->Z, phiR3->X);
    fp2correction(phiR3->X);
    fp2copy(one, phiR3->Z);

    // Moving from E_0 into E_i
    // ------------------------> Non-optimal multiplicative 3-isogeny chain
    xTPLe(R, R, A24minus, A24plus, (int) OBOB_EXPON - (int) iteration);
    fp2inv_mont(R->Z);
    fp2mul_mont(R->X, R->Z, R->X);
    fp2correction(R->X);
    fp2copy(one, R->Z);
    for (i = 1; i <= iteration; i++) {
        //printf("[%u] 3-isogeny mapping with iteration %u\n", i, iteration - i);
        fp2copy(R->X, K->X);
        fp2copy(R->Z, K->Z);
        xTPLe(K, K, A24minus, A24plus, (int) iteration - i);
        get_3_isog(K, A24minus, A24plus, coeff);
        eval_3_isog(R, coeff);
        eval_3_isog(phiP3, coeff);
        eval_3_isog(phiQ3, coeff);
        eval_3_isog(phiR3, coeff);
    }

    // +++ E_i : y^2 = x^3 +6x^2 + x
    f2elm_t tmp_A = {0}, tmp_C = {0}, A_affine = {0};
    fp2add(A24plus, A24minus, tmp_A); // 2A'
    fp2add(tmp_A, tmp_A, tmp_A);      // 4A'
    fp2sub(A24plus, A24minus, tmp_C); // 4C
    fp2inv_mont(tmp_C);               // 1/(4C)
    fp2correction(tmp_C);
    fp2mul_mont(tmp_A, tmp_C, tmp_A); // A = A'/C
    fp2correction(tmp_A);
    fp2zero(tmp_C);
    fpcopy((digit_t * ) & Montgomery_one, tmp_C[0]);
    from_fp2mont(tmp_A, A_affine);
    f2elm_t six = {0};
    six[0][0] = 6;
    assert(memcmp(A_affine[0], six[0], NBITS_TO_NBYTES(NBITS_FIELD)) == 0);
    assert(memcmp(A_affine[1], six[1], NBITS_TO_NBYTES(NBITS_FIELD)) == 0);

    fp2correction(phiP3->Z);
    fp2correction(phiQ3->Z);
    fp2correction(phiR3->Z);
    inv_3_way(phiP3->Z, phiQ3->Z, phiR3->Z);
    // x(P3)
    fp2mul_mont(phiP3->X, phiP3->Z, phiP3->X);
    fp2correction(phiP3->X);
    fp2copy(one, phiP3->Z);
    // x(Q3)
    fp2mul_mont(phiQ3->X, phiQ3->Z, phiQ3->X);
    fp2correction(phiQ3->X);
    fp2copy(one, phiQ3->Z);
    // x(R3)
    fp2mul_mont(phiR3->X, phiR3->Z, phiR3->X);
    fp2correction(phiR3->X);
    fp2copy(one, phiR3->Z);

    assert(isequal_proj(phiP3, phiQ3) != 1);    // phiP3 != phiQ3
    assert(isequal_proj(phiQ3, phiR3) != 1);    // phiQ3 != phiR3
    assert(isequal_proj(phiP3, phiR3) != 1);    // phiP3 != phiR3

    // +++
    // --- phiP3, phiQ3, and phiR3 are order-3 points
    assert(isinfinity(phiP3) != 1);
    xTPL(phiP3, tmp, A24minus, A24plus);
    fp2correction(tmp->X);
    fp2correction(tmp->Z);
    assert(isinfinity(tmp) == 1);
    // ---
    assert(isinfinity(phiQ3) != 1);
    xTPL(phiQ3, tmp, A24minus, A24plus);
    fp2correction(tmp->X);
    fp2correction(tmp->Z);
    assert(isinfinity(tmp) == 1);
    // ---
    assert(isinfinity(phiR3) != 1);
    xTPL(phiR3, tmp, A24minus, A24plus);
    fp2correction(tmp->X);
    fp2correction(tmp->Z);
    assert(isinfinity(tmp) == 1);

    return is_felm(phiP3->X) ^ (is_felm(phiQ3->X) << 1) ^ (is_felm(phiR3->X) << 2);
}

int NextBacktrackingInstance_EVE(unsigned char* PublicKeyA, const unsigned int iteration, const int choice)
{
    /* Backtracking instance constructed from previously backtracking instance */
    // Decode public key: x(P'), x(Q'), and  x(P'-Q')
    point_proj_t P_ = {0}, Q_ = {0}, PQ_ = {0}, K = {0}, M = {0};
    fp2_decode(PublicKeyA, P_->X);
    fp2_decode(PublicKeyA + FP2_ENCODED_BYTES, Q_->X);
    fp2_decode(PublicKeyA + 2 * FP2_ENCODED_BYTES, PQ_->X);

    fpcopy((digit_t * ) & Montgomery_one, (P_->Z)[0]);
    fpcopy((digit_t * ) & Montgomery_one, (Q_->Z)[0]);
    fpcopy((digit_t * ) & Montgomery_one, (PQ_->Z)[0]);

    // Initialize constants: A24plus = A+2C, A24minus = A-2C, where C=1
    f2elm_t A24plus = {0}, A24minus = {0}, A = {0};
    get_A(P_->X, Q_->X, PQ_->X, A);
    mp_add((digit_t*)&Montgomery_one, (digit_t*)&Montgomery_one, A24minus[0], NWORDS_FIELD);
    mp2_add(A, A24minus, A24plus);
    mp2_sub_p2(A, A24minus, A24minus);

    // +++ Computing 3^i ... I tried using mp_mul() but I failed!
    unsigned int i;
    felm_t k = {0}, m ={0}, t ={0}, three = {0};
    fpcopy((digit_t*)&Montgomery_one, k);   // 1
    fpcopy((digit_t*)&Montgomery_one, t);   // 1
    fpadd(k, k, three);                     // 2
    fpadd(k, three, three);                 // 3
    for(i = 0; i < iteration; i++)
        fpmul_mont(k, three, k);
    from_mont(k, m);                        // 3^iteration
    fpsub(k, t, k);
    from_mont(k, k);                        // 3^iteration - 1
    LADDER3PT(P_->X, Q_->X, PQ_->X, m, BOB, M, A);  // x(P' + [3^iteration]Q')
    LADDER3PT(P_->X, Q_->X, PQ_->X, k, BOB, K, A);  // x(P' + [3^iteration - 1]Q')

    // Computing affine x-coordinate of x(P' + [3^iteration]Q')
    fp2inv_mont(M->Z);
    fp2correction(M->Z);
    fp2mul_mont(M->X, M->Z, P_->X);
    // Computing affine x-coordinate of x(P' + [3^iteration - 1]Q')
    fp2inv_mont(K->Z);
    fp2correction(K->Z);
    fp2mul_mont(K->X, K->Z, PQ_->X);

    // Notice, this new instance moves field belongings. Now, we have 3-isogeny kernels set up as:
    // from x(P3) to x(P3 + Q3)
    // from x(P3 + Q3) to x(P3 + [2]Q3)
    // from x(P3 + [2]Q3) to x(P3)
    fp2_encode(P_->X, PublicKeyA);
    fp2_encode(Q_->X, PublicKeyA + FP2_ENCODED_BYTES);
    fp2_encode(PQ_->X, PublicKeyA + 2 * FP2_ENCODED_BYTES);
    return ( 0x3 & (choice >> 1)) ^ ((choice & 0x1) << 2);
}

int Oracle_EVE(unsigned char* SharedSecretB, const unsigned char* PrivateKeyB, const unsigned char* PublicKeyA, const unsigned int iteration)
{
    ORACLE_CALLS += 1;
    // Oracle call for supersingularity check.
    // For more details check description of Oracle_EVE_SIDHpXXX in the PXXX_api_attack.h file
    point_proj_t supersingular, R, pts[MAX_INT_POINTS_BOB];
    f2elm_t coeff[3], PKB[3], jinv;
    f2elm_t A24plus = {0}, A24minus = {0}, A = {0};
    unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_BOB], npts = 0, ii = 0;
    digit_t SecretKeyB[NWORDS_ORDER] = {0};
      
    // Initialize images of Alice's basis
    fp2_decode(PublicKeyA, PKB[0]);
    fp2_decode(PublicKeyA + FP2_ENCODED_BYTES, PKB[1]);
    fp2_decode(PublicKeyA + 2*FP2_ENCODED_BYTES, PKB[2]);

    // Initialize constants: A24plus = A+2C, A24minus = A-2C, where C=1
    get_A(PKB[0], PKB[1], PKB[2], A);
    mp_add((digit_t*)&Montgomery_one, (digit_t*)&Montgomery_one, A24minus[0], NWORDS_FIELD);
    mp2_add(A, A24minus, A24plus);
    mp2_sub_p2(A, A24minus, A24minus);

    // Retrieve kernel point
    decode_to_digits(PrivateKeyB, SecretKeyB, SECRETKEY_B_BYTES, NWORDS_ORDER);
    LADDER3PT(PKB[0], PKB[1], PKB[2], SecretKeyB, BOB, R, A);

    f2elm_t tmp_A = {0}, tmp_C = {0}, A_affine = {0};
    f2elm_t six = {0};
    six[0][0] = 6;

    // Traverse tree
    index = 0;
    int fault = 1;
    for (row = 1; row < OBOB_EXPON; row++) {
        while (index < OBOB_EXPON-row) {
            fp2copy(R->X, pts[npts]->X);
            fp2copy(R->Z, pts[npts]->Z);
            pts_index[npts++] = index;
            m = strat_Bob[ii++];
            xTPLe(R, R, A24minus, A24plus, (int)m);
            index += m;
        }
        if (((int)iteration + 2) == (int)row) {
            // Supersingularity check, current kernel point generator must have order 3
            xTPL(R, supersingular, A24minus, A24plus);
            fault = isinfinity(supersingular);
        }

        get_3_isog(R, A24minus, A24plus, coeff);
        if ((int)iteration == (int)row)
        {
            // Backtracking instance forces E_i : y^2 = x^3 +6x^2 + x
            // Here i := iteration
            // There are some fixed indexes (strategy step iterations) requiring the fault injection on the
            // the next kernel point instead of the curve coefficient. This is because, i* iteration is not
            // entering on the while loop.
            fp2add(A24plus, A24minus, tmp_A); // 2A'
            fp2add(tmp_A, tmp_A, tmp_A);      // 4A'
            fp2sub(A24plus, A24minus, tmp_C); // 4C
            fp2inv_mont(tmp_C);               // 1/(4C)
            fp2correction(tmp_C);
            fp2mul_mont(tmp_A, tmp_C, tmp_A); // A = A'/C
            fp2correction(tmp_A);
            fp2zero(tmp_C);
            fpcopy((digit_t*)&Montgomery_one, tmp_C[0]);
            from_fp2mont(tmp_A, A_affine);

            assert(check_fcondition(A24plus, A24minus));
            assert(memcmp(A_affine[0], six[0], NBITS_TO_NBYTES(NBITS_FIELD)) == 0);
            assert(memcmp(A_affine[1], six[1], NBITS_TO_NBYTES(NBITS_FIELD)) == 0);
            //printf("[\033[1;31m%d,\tEphemeralSecretAgreement_B\033[0m]\tfp-curve coefficient\n", row);
        }

        if (((int)iteration + 1) == (int)row)
        {
            // At iteration (i + 1), E_{i+1} can be either defined over fp or fp2. Injecting zeroes at
            // the imaginary parts of the projective curve coefficients A24plus and A24minus, permits
            // to guess base field of E_{i+1}.
            /*
            if (check_fcondition(A24plus, A24minus))
                printf("[\033[1;31m%d,\tEphemeralSecretAgreement_B\033[0m]\t \033[1;31mfp\033[0m-curve coefficient\n", row);
            else
                printf("[\033[1;34m%d,\tEphemeralSecretAgreement_B\033[0m]\t\033[1;34mfp2\033[0m-curve coefficient\n", row);
            */
            insert_zero(A24plus, A24minus);
        }

        for (i = 0; i < npts; i++) {
            eval_3_isog(pts[i], coeff);
        } 

        fp2copy(pts[npts-1]->X, R->X); 
        fp2copy(pts[npts-1]->Z, R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    if (((int)iteration + 2) == (int)row) {
        // Supersingularity check, current kernel point generator must have order 3
        xTPL(R, supersingular, A24minus, A24plus);
        fault = isinfinity(supersingular);
    }
    get_3_isog(R, A24minus, A24plus, coeff);

    fp2add(A24plus, A24minus, A);                 
    fp2add(A, A, A);
    fp2sub(A24plus, A24minus, A24plus);                   
    j_inv(A, A24plus, jinv);
    fp2_encode(jinv, SharedSecretB);    // Format shared secret

    return fault;
}

int GuessingSecretBits_EVE(unsigned char* GuessedKeyB, const unsigned char* PrivateKeyB, const unsigned int iteration)
{
    // Guessing secret bits from Bon's private key
    // For more details check description of GuessingSecretBits_EVE_SIDHpXXX in the PXXX_api_attack.h file
    //char *real[2] = {"\033[1;34m", "\033[1;31m"};
    unsigned char PublicKeyA[SIDH_PUBLICKEYBYTES];
    unsigned char SharedSecretB[SIDH_BYTES];
    digit_t SecretKeyB[NWORDS_ORDER] = {0};
    int choices = 0, counter = 0, guess, i = 0;

    choices = BacktrackingInstance_EVE(PublicKeyA, GuessedKeyB, iteration, 0);
    guess = Oracle_EVE(SharedSecretB, PrivateKeyB, PublicKeyA, iteration);
    counter = (int) (((int) (choices & 0x1) != 0) == guess)
            + (int) (((int) (choices & 0x2) != 0) == guess)
            + (int) (((int) (choices & 0x4) != 0) == guess);

    if (counter > 1)
    {
        // swifted radix-3 coefficient
        int swifted_choices = NextBacktrackingInstance_EVE(PublicKeyA, iteration, choices);
        guess = Oracle_EVE(SharedSecretB, PrivateKeyB, PublicKeyA, iteration);
        counter = (int) (((int) (swifted_choices & 0x1) != 0) == guess)
                + (int) (((int) (swifted_choices & 0x2) != 0) == guess)
                + (int) (((int) (swifted_choices & 0x4) != 0) == guess);
        if (counter > 1)
        {
            if ((choices & 0x1) == (swifted_choices & 0x1))
                counter = 0;
            else if ((choices & 0x2) == (swifted_choices & 0x2))
                counter = 1;
            else
            {
                assert((choices & 0x4) == (swifted_choices & 0x4));
                counter = 2;
            }
        }
        else
        {
            assert(counter == 1);
            if (((int) (swifted_choices & 0x1) != 0) == guess)
                counter = 0;
            else if (((int) (swifted_choices & 0x2) != 0) == guess)
                counter = 1;
            else
            {
                assert(((int) (swifted_choices & 0x4) != 0) == guess);
                counter = 2;
            }
        }
    }
    else
    {
        assert(counter == 1);
        if (((int) (choices & 0x1) != 0) == guess)
            counter = 0;
        else if (((int) (choices & 0x2) != 0) == guess)
            counter = 1;
        else
        {
            assert(((int) (choices & 0x4) != 0) == guess);
            counter = 2;
        }
    }
    // +++ Computing 3^i ... I tried using mp_mul() but I failed!
    felm_t t = {0}, three = {0};
    fpcopy((digit_t*)&Montgomery_one, t);

    fpadd(t, t, three);     // 2
    fpadd(t, three,three);  // 3
    for(i = 0; i < iteration; i++)
        fpmul_mont(t, three, t);
    from_mont(t, t);        // 3^iteration

    // +++ Adding the guessing radix-3 coeff
    decode_to_digits(GuessedKeyB, SecretKeyB, SECRETKEY_B_BYTES, NWORDS_ORDER);
    for(i = 0; i < counter; i++)
        mp_add(SecretKeyB, t, SecretKeyB, NWORDS_ORDER);

    encode_to_bytes(SecretKeyB, GuessedKeyB, SECRETKEY_B_BYTES);
    // Next two lines are for printing the current guessed radix-3 coefficient
    printf("%d", counter);
    fflush(stdout);
    return 0;
}

int IterativeAttack_EVE(unsigned char* GuessedKeyB, const unsigned char* PrivateKeyB)
{
    ORACLE_CALLS = 0;
    // This function calls (OBOB_EXPON - 1) times GuessingSecretBits_EVE()
    int j;
    unsigned char zero[SIDH_SECRETKEYBYTES_B] = {0};
    memcpy(GuessedKeyB, zero, SIDH_SECRETKEYBYTES_B);
    for(j = 0; j < ((int)OBOB_EXPON - 1); j++)
        GuessingSecretBits_EVE(GuessedKeyB, PrivateKeyB, j);

    return 0;
}

int LastIsogenyRecovery_EVE(unsigned char* GuessedKeyB, const unsigned char* PublicKeyB)
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
    unsigned char GuessedPublicKeyB[SIDH_PUBLICKEYBYTES];
    decode_to_digits(GuessedKeyB, SecretKeyB, SECRETKEY_B_BYTES, NWORDS_ORDER);

    // ---
    EphemeralKeyGeneration_B(GuessedKeyB, GuessedPublicKeyB);
    if (memcmp(GuessedPublicKeyB, PublicKeyB, SIDH_PUBLICKEYBYTES) == 0)
        return 0;

    // ---
    mp_add(SecretKeyB, t, SecretKeyB, NWORDS_ORDER);
    encode_to_bytes(SecretKeyB, GuessedKeyB, SECRETKEY_B_BYTES);
    EphemeralKeyGeneration_B(GuessedKeyB, GuessedPublicKeyB);
    if (memcmp(GuessedPublicKeyB, PublicKeyB, SIDH_PUBLICKEYBYTES) == 0)
        return 0;

    // ---
    mp_add(SecretKeyB, t, SecretKeyB, NWORDS_ORDER);
    encode_to_bytes(SecretKeyB, GuessedKeyB, SECRETKEY_B_BYTES);
    EphemeralKeyGeneration_B(GuessedKeyB, GuessedPublicKeyB);
    if (memcmp(GuessedPublicKeyB, PublicKeyB, SIDH_PUBLICKEYBYTES) == 0)
        return 0;

    return 1;
}