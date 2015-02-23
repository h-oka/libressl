//
// kcipher-2.c
//
//  Created by h-oka on 2014/11/18.
//  Renamed by tetsu on 2015/02/13

#include "kcipher-2.h"

/* Global variables */

// State S
uint32_t A[5];              // five 32-bit units
uint32_t B[11];             // eleven 32-bit units
uint32_t L1, R1, L2, R2;    // one 32-bit unit for each
uint32_t pL1, pL2, pR1, pR2; //32-bit unit pre two stream
uint32_t A0, B0;
uint32_t nA[5], nB[5];

// The internal key (IK) and the initialization vector (IV)
uint32_t IK[12];    // (12*32) bits
uint32_t IV[4];     // (4*32) bits





/**
 * Do substitution on a given input. See Section 2.4.2.
 * @param    t   : (INPUT), (1*32) bits
 * @return       : (OUTPUT), (1*32) bits
 */

inline static uint32_t sub_k2 (uint32_t in) {
    uint32_t out;
    
    
    out = T_0[in & 0x000000ff] ^ T_1[(in >> 8) & 0x000000ff] ^ T_2[(in >> 16) & 0x000000ff] ^ T_3[(in >> 24) & 0x000000ff];

    
    return out;
}

/**
 * Expand a given 128-bit key (K) to a 384-bit internal key
 * information (IK).
 * See Step 1 of init() in Section 2.3.2.
 * @param    key[4]  : (INPUT), (4*32) bits
 * @param    iv[4]   : (INPUT), (4*32) bits
 * @modify   IK[12]  : (OUTPUT), (12*32) bits
 * @modify   IV[12]  : (OUTPUT), (4*32) bits
 */

inline static void key_expansion (uint32_t *key, uint32_t *iv) {
    // copy iv to IV
    IV[0] = iv[0];  IV[1] = iv[1];  IV[2] = iv[2];  IV[3] = iv[3];
    
    // m = 0 ... 3
    IK[0] = key[0];     IK[1] = key[1];
    IK[2] = key[2];     IK[3] = key[3];
    // m = 4
    IK[4] = IK[0] ^ sub_k2((IK[3] << 8) ^ (IK[3] >> 24)) ^
    0x01000000;
    // m = 4 ... 11, but not 4 nor 8
    IK[5] = IK[1] ^ IK[4];  IK[6] = IK[2] ^ IK[5];
    IK[7] = IK[3] ^ IK[6];
    
    // m = 8
    IK[8] = IK[4] ^ sub_k2((IK[7] << 8) ^ (IK[7] >> 24)) ^
    0x02000000;
    
    // m = 4 ... 11, but not 4 nor 8
    IK[9] = IK[5] ^ IK[8];  IK[10] = IK[6] ^ IK[9];
    IK[11] = IK[7] ^ IK[10];
}

/**
 * Set up the initial state value using IK and IV. See Step 2 of
 * init() in Section 2.3.2.
 * @param    key[4]  : (INPUT), (4*32) bits
 * @param    iv[4]   : (INPUT), (4*32) bits
 * @modify   S       : (OUTPUT), (A, B, L1, R1, L2, R2)
 */

inline static void setup_state_values (uint32_t *key, uint32_t *iv) {
    // setting up IK and IV by calling key_expansion(key, iv)
    key_expansion(key, iv);
    
    // setting up the internal state values
    A[0] = IK[4];   A[1] = IK[3];   A[2] = IK[2];
    A[3] = IK[1];   A[4] = IK[0];
    
    B[0] = IK[10];  B[1] = IK[11];  B[2] = IV[0];   B[3] = IV[1];
    B[4] = IK[8];   B[5] = IK[9];   B[6] = IV[2];   B[7] = IV[3];
    B[8] = IK[7];   B[9] = IK[5];   B[10] = IK[6];
    
    L1 = R1 = L2 = R2 = 0x00000000;
}

/**
 * Initialize the system with a 128-bit key (K) and a 128-bit
 * initialization vector (IV). It sets up the internal state value
 * and invokes next(INIT) iteratively 24 times. After this,
 * the system is ready to produce key streams. See Section 2.3.2.
 * @param    key[12] : (INPUT), (4*32) bits
 * @param    iv[4]   : (INPUT), (4*32) bits
 * @modify   IK      : (12*32) bits, by calling setup_state_values()
 * @modify   IV      : (4*32) bits,  by calling setup_state_values()
 * @modify   S       : (OUTPUT), (A, B, L1, R1, L2, R2)
 */

inline static void init (uint32_t *k, uint32_t *iv) {
    int i;

    setup_state_values(k, iv);

    
        nextinit(); nextinit(); nextinit(); nextinit(); 
        nextinit(); nextinit(); nextinit(); nextinit(); 
        nextinit(); nextinit(); nextinit(); nextinit();
    
}

/**
 * Non-linear function. 
 * @param    A   : (INPUT), 8 bits
 * @param    B   : (INPUT), 8 bits
 * @param    C   : (INPUT), 8 bits
 * @param    D   : (INPUT), 8 bits
 * @return       : (OUTPUT), 8 bits
 */

/**
 * Derive a new state from the current state values.
 * @param    mode    : (INPUT) INIT (= 0) or NORMAL (= 1)
 * @modify   S       : (OUTPUT)
 */
inline static void nextinit () {
    uint32_t temp1[2], temp2[2];
    
    
    pL1 = sub_k2(R2 + B[4]);
    pR1 = sub_k2(L2 + B[9]);
    pL2 = sub_k2(L1);
    pR2 = sub_k2(R1);
    
    // m = 0 
    A0 = A[1];
    
    // m = 0 
    B0 = B[1];

    // update nA[4]
    temp1[0] = (A[0] << 8) ^ amul0[(A[0] >> 24)];

    nA[0] = temp1[0] ^ A[3];
    
    nA[0] ^= NLF(B[0], R2, R1, A[4]);

    temp1[1] = (A[1] << 8) ^ amul0[(A[1] >> 24)];

    nA[1] = temp1[1] ^ A[4];
    
    nA[1] ^= NLF(B0, pR2, pR1, nA[0]);
    

    temp1[0] = A[2] & 0x40000000 ? (B[0] << 8) ^ amul1[(B[0] >> 24)] 
                                      : (B[0] << 8) ^ amul2[(B[0] >> 24)];

    temp2[0] = A[2] & 0x80000000 ? (B[8] << 8) ^ amul3[(B[8] >> 24)]
                                      : B[8];
    
    nB[0] = temp1[0] ^ B[1] ^ B[6] ^ temp2[0];
    
    
    nB[0] ^= NLF(B[10], L2, L1, A[0]);
    //printf("b[10] = %x\n", B10);

    temp1[1] = A[3] & 0x40000000 ? (B[1] << 8) ^ amul1[(B[1] >> 24)] 
                                      : (B[1] << 8) ^ amul2[(B[1] >> 24)];

    temp2[1] = A[3] & 0x80000000 ? (B[9] << 8) ^ amul3[(B[9] >> 24)]
                                      : B[9];
    
    nB[1] = temp1[1] ^ B[2] ^ B[7] ^ temp2[1];
    
    
    nB[1] ^= NLF(nB[0], pL2, pL1, A0);
    //printf("b[10] = %x\n", nB10);



    L1 = sub_k2(pR2 + B[5]);
    R1 = sub_k2(pL2 + B[10]);
    L2 = sub_k2(pL1);
    R2 = sub_k2(pR1);


    /* copy S' to S */
    A[0] = A[2];   A[1] = A[3];   A[2] = A[4];
    A[3] = nA[0];   A[4] = nA[1];
    
    B[0] = B[2];   B[1] = B[3];   B[2] = B[4];   B[3] = B[5];
    B[4] = B[6];   B[5] = B[7];   B[6] = B[8];   B[7] = B[9];
    B[8] = B[10];   B[9] = nB[0];   B[10] = nB[1];
    
    //L1 = nL1;   R1 = nR1;   L2 = nL2;   R2 = nR2;
    
    
    
}

inline static void nextnormal (uint32_t *encode) {
    
    uint32_t temp1[2], temp2[2];
    //int j, i;

    
    uint32_t nlf1[8] __attribute__((aligned(32)));
    uint32_t nlf2[8] __attribute__((aligned(32)));
    uint32_t nlf3[8] __attribute__((aligned(32)));
    uint32_t nlf4[8] __attribute__((aligned(32)));
    //uint32_t keystream[8] __attribute__((aligned(32)));
    
    
    pL1 = sub_k2(R2 + B[4]);
    pR1 = sub_k2(L2 + B[9]);
    pL2 = sub_k2(L1);
    pR2 = sub_k2(R1);
    
    
    
    L1 = sub_k2(pR2 + B[5]);
    R1 = sub_k2(pL2 + B[10]);
    L2 = sub_k2(pL1);
    R2 = sub_k2(pR1);
    

    // first m = 0 ... 3
    A0 = A[1];
    

    // first m = 0 ... 9
    B0 = B[1];


    // update nA[0][4]
    temp1[0] = (A[0] << 8) ^ amul0[(A[0] >> 24)];
    temp1[1] = (A[1] << 8) ^ amul0[(A[1] >> 24)];

    nA[0] = temp1[0] ^ A[3];
    nA[1] = temp1[1] ^ A[4];




    temp1[0] = A[2] & 0x40000000 ? (B[0] << 8) ^ amul1[(B[0] >> 24)] 
                                      : (B[0] << 8) ^ amul2[(B[0] >> 24)];

    temp2[0] = A[2] & 0x80000000 ? (B[8] << 8) ^ amul3[(B[8] >> 24)]
                                      : B[8];
    
    nB[0] = temp1[0] ^ B[1] ^ B[6] ^ temp2[0];


    temp1[1] = A[3] & 0x40000000 ? (B[1] << 8) ^ amul1[(B[1] >> 24)] 
                                      : (B[1] << 8) ^ amul2[(B[1] >> 24)];

    temp2[1] = A[3] & 0x80000000 ? (B[9] << 8) ^ amul3[(B[9] >> 24)]
                                      : B[9];

    nB[1] = temp1[1] ^ B[2] ^ B[7] ^ temp2[1];


    nlf1[0] = nB[0]; nlf1[1] = B0;   nlf1[2] = nB[1]; nlf1[3] = B[2];
    nlf2[0] = pL2;  nlf2[1] = pR2;  nlf2[2] = L2;    nlf2[3] = R2;
    nlf3[0] = pL1;  nlf3[1] = pR1;  nlf3[2] = L1;    nlf3[3] = R1;
    nlf4[0] = A0;   nlf4[1] = nA[0]; nlf4[2] = A[2];  nlf4[3] = nA[1];

    //L1 = pL1; L2 = pL2; R1 = pR1; R2 = pR2;



    
    pL1 = sub_k2(R2 + B[6]);
    pR1 = sub_k2(L2 + nB[0]);
    pL2 = sub_k2(L1);
    pR2 = sub_k2(R1);
    
    
    
    L1 = sub_k2(pR2 + B[7]);
    R1 = sub_k2(pL2 + nB[1]);
    L2 = sub_k2(pL1);
    R2 = sub_k2(pR1);
    
    
    
    // first m = 0 ... 3
    A0 = A[3];
    

    // first m = 0 ... 9
    B0 = B[3];

    // update nA[0][4]
    temp1[0] = (A[2] << 8) ^ amul0[(A[2] >> 24)];
    temp1[1] = (A[3] << 8) ^ amul0[(A[3] >> 24)];

    nA[2] = temp1[0] ^ nA[0];
    nA[3] = temp1[1] ^ nA[1];


    temp1[0] = A[4] & 0x40000000 ? (B[2] << 8) ^ amul1[(B[2] >> 24)] 
                                      : (B[2] << 8) ^ amul2[(B[2] >> 24)];

    temp2[0] = A[4] & 0x80000000 ? (B[10] << 8) ^ amul3[(B[10] >> 24)]
                                      : B[10];
    
    nB[2] = temp1[0] ^ B[3] ^ B[8] ^ temp2[0];


    temp1[1] = nA[0] & 0x40000000 ? (B[3] << 8) ^ amul1[(B[3] >> 24)] 
                                      : (B[3] << 8) ^ amul2[(B[3] >> 24)];

    temp2[1] = nA[0] & 0x80000000 ? (nB[0] << 8) ^ amul3[(nB[0] >> 24)]
                                      : nB[0];

    nB[3] = temp1[1] ^ B[4] ^ B[9] ^ temp2[1];

    /* copy S' to S */
    A[0] = A[4];   
    A[1] = nA[0];   
    A[2] = nA[1];
    A[3] = nA[2];   
    A[4] = nA[3];
    
    B[0] = B[4];   B[1] = B[5];   B[2] = B[6];   B[3] = B[7];
    B[4] = B[8];   B[5] = B[9];   B[6] = B[10];   B[7] = nB[0];
    B[8] = nB[1];   B[9] = nB[2];   
    B[10] = nB[3];

    nlf1[4] = B[9]; nlf1[5] = B0;   nlf1[6] = B[10]; nlf1[7] = B[0];
    nlf2[4] = pL2;  nlf2[5] = pR2;  nlf2[6] = L2;    nlf2[7] = R2;
    nlf3[4] = pL1;  nlf3[5] = pR1;  nlf3[6] = L1;    nlf3[7] = R1;
    nlf4[4] = A0;   nlf4[5] = A[3]; nlf4[6] = A[0];  nlf4[7] = A[4];


    
    __m256i inlf1 = _mm256_load_si256((__m256i *)nlf1);
    __m256i inlf2 = _mm256_load_si256((__m256i *)nlf2);
    __m256i inlf3 = _mm256_load_si256((__m256i *)nlf3);
    __m256i inlf4 = _mm256_load_si256((__m256i *)nlf4);
    __m256i icode = _mm256_load_si256((__m256i *)encode);

    __m256i rus1 = _mm256_add_epi32(inlf1,inlf2);
    __m256i rus2 = _mm256_xor_si256(rus1, inlf3);
    __m256i rus3 = _mm256_xor_si256(rus2, inlf4);
    __m256i rus4 = _mm256_xor_si256(rus3, icode);

    //_mm256_store_si256((__m256i *)keystream, rus3);

    //for (i = 0; i < 8; i++) {
    //    printf("keystream[%d] : %x\n", i, keystream[i]);
    //}


    
}



/**
 * Obtain a key stream = (ZH, ZL) from the current state values.
 * See Section 2.3.3.
 * @param    ZH  : (OUTPUT) (1 * 32)-bit
 * @modify   ZL  : (OUTPUT) (1 * 32)-bit
 */
void stream (uint32_t *ZH, uint32_t *ZL, uint32_t *encode) {

    uint32_t cip1, cip2;

    *ZH = NLF(B[10], L2, L1, A[0]);
    *ZL = NLF(B[0], R2, R1, A[4]);
    //printf("ZH = %x\n", *ZH);
    //printf("ZL = %x\n", *ZL);
    cip1 = encode[0] ^ *ZH;
    cip2 = encode[1] ^ *ZL;

}