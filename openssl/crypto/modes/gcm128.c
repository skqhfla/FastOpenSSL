/*
 * Copyright 2010-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "modes_lcl.h"
#include <string.h>
#include <stdatomic.h>

#if defined(BSWAP4) && defined(STRICT_ALIGNMENT)
/* redefine, because alignment is ensured */
# undef  GETU32
# define GETU32(p)       BSWAP4(*(const u32 *)(p))
# undef  PUTU32
# define PUTU32(p,v)     *(u32 *)(p) = BSWAP4(v)
#endif

#define PACK(s)         ((size_t)(s)<<(sizeof(size_t)*8-16))
#define REDUCE1BIT(V)   do { \
        if (sizeof(size_t)==8) { \
                u64 T = U64(0xe100000000000000) & (0-(V.lo&1)); \
                V.lo  = (V.hi<<63)|(V.lo>>1); \
                V.hi  = (V.hi>>1 )^T; \
        } \
        else { \
                u32 T = 0xe1000000U & (0-(u32)(V.lo&1)); \
                V.lo  = (V.hi<<63)|(V.lo>>1); \
                V.hi  = (V.hi>>1 )^((u64)T<<32); \
        } \
} while(0)

/*-
 * Even though permitted values for TABLE_BITS are 8, 4 and 1, it should
 * never be set to 8. 8 is effectively reserved for testing purposes.
 * TABLE_BITS>1 are lookup-table-driven implementations referred to as
 * "Shoup's" in GCM specification. In other words OpenSSL does not cover
 * whole spectrum of possible table driven implementations. Why? In
 * non-"Shoup's" case memory access pattern is segmented in such manner,
 * that it's trivial to see that cache timing information can reveal
 * fair portion of intermediate hash value. Given that ciphertext is
 * always available to attacker, it's possible for him to attempt to
 * deduce secret parameter H and if successful, tamper with messages
 * [which is nothing but trivial in CTR mode]. In "Shoup's" case it's
 * not as trivial, but there is no reason to believe that it's resistant
 * to cache-timing attack. And the thing about "8-bit" implementation is
 * that it consumes 16 (sixteen) times more memory, 4KB per individual
 * key + 1KB shared. Well, on pros side it should be twice as fast as
 * "4-bit" version. And for gcc-generated x86[_64] code, "8-bit" version
 * was observed to run ~75% faster, closer to 100% for commercial
 * compilers... Yet "4-bit" procedure is preferred, because it's
 * believed to provide better security-performance balance and adequate
 * all-round performance. "All-round" refers to things like:
 *
 * - shorter setup time effectively improves overall timing for
 *   handling short messages;
 * - larger table allocation can become unbearable because of VM
 *   subsystem penalties (for example on Windows large enough free
 *   results in VM working set trimming, meaning that consequent
 *   malloc would immediately incur working set expansion);
 * - larger table has larger cache footprint, which can affect
 *   performance of other code paths (not necessarily even from same
 *   thread in Hyper-Threading world);
 *
 * Value of 1 is not appropriate for performance reasons.
 */
#if     TABLE_BITS==8

static void gcm_init_8bit(u128 Htable[256], u64 H[2])
{
    int i, j;
    u128 V;

    Htable[0].hi = 0;
    Htable[0].lo = 0;
    V.hi = H[0];
    V.lo = H[1];

    for (Htable[128] = V, i = 64; i > 0; i >>= 1) {
        REDUCE1BIT(V);
        Htable[i] = V;
    }

    for (i = 2; i < 256; i <<= 1) {
        u128 *Hi = Htable + i, H0 = *Hi;
        for (j = 1; j < i; ++j) {
            Hi[j].hi = H0.hi ^ Htable[j].hi;
            Hi[j].lo = H0.lo ^ Htable[j].lo;
        }
    }
}

static void gcm_gmult_8bit(u64 Xi[2], const u128 Htable[256])
{
    u128 Z = { 0, 0 };
    const u8 *xi = (const u8 *)Xi + 15;
    size_t rem, n = *xi;
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    static const size_t rem_8bit[256] = {
        PACK(0x0000), PACK(0x01C2), PACK(0x0384), PACK(0x0246),
        PACK(0x0708), PACK(0x06CA), PACK(0x048C), PACK(0x054E),
        PACK(0x0E10), PACK(0x0FD2), PACK(0x0D94), PACK(0x0C56),
        PACK(0x0918), PACK(0x08DA), PACK(0x0A9C), PACK(0x0B5E),
        PACK(0x1C20), PACK(0x1DE2), PACK(0x1FA4), PACK(0x1E66),
        PACK(0x1B28), PACK(0x1AEA), PACK(0x18AC), PACK(0x196E),
        PACK(0x1230), PACK(0x13F2), PACK(0x11B4), PACK(0x1076),
        PACK(0x1538), PACK(0x14FA), PACK(0x16BC), PACK(0x177E),
        PACK(0x3840), PACK(0x3982), PACK(0x3BC4), PACK(0x3A06),
        PACK(0x3F48), PACK(0x3E8A), PACK(0x3CCC), PACK(0x3D0E),
        PACK(0x3650), PACK(0x3792), PACK(0x35D4), PACK(0x3416),
        PACK(0x3158), PACK(0x309A), PACK(0x32DC), PACK(0x331E),
        PACK(0x2460), PACK(0x25A2), PACK(0x27E4), PACK(0x2626),
        PACK(0x2368), PACK(0x22AA), PACK(0x20EC), PACK(0x212E),
        PACK(0x2A70), PACK(0x2BB2), PACK(0x29F4), PACK(0x2836),
        PACK(0x2D78), PACK(0x2CBA), PACK(0x2EFC), PACK(0x2F3E),
        PACK(0x7080), PACK(0x7142), PACK(0x7304), PACK(0x72C6),
        PACK(0x7788), PACK(0x764A), PACK(0x740C), PACK(0x75CE),
        PACK(0x7E90), PACK(0x7F52), PACK(0x7D14), PACK(0x7CD6),
        PACK(0x7998), PACK(0x785A), PACK(0x7A1C), PACK(0x7BDE),
        PACK(0x6CA0), PACK(0x6D62), PACK(0x6F24), PACK(0x6EE6),
        PACK(0x6BA8), PACK(0x6A6A), PACK(0x682C), PACK(0x69EE),
        PACK(0x62B0), PACK(0x6372), PACK(0x6134), PACK(0x60F6),
        PACK(0x65B8), PACK(0x647A), PACK(0x663C), PACK(0x67FE),
        PACK(0x48C0), PACK(0x4902), PACK(0x4B44), PACK(0x4A86),
        PACK(0x4FC8), PACK(0x4E0A), PACK(0x4C4C), PACK(0x4D8E),
        PACK(0x46D0), PACK(0x4712), PACK(0x4554), PACK(0x4496),
        PACK(0x41D8), PACK(0x401A), PACK(0x425C), PACK(0x439E),
        PACK(0x54E0), PACK(0x5522), PACK(0x5764), PACK(0x56A6),
        PACK(0x53E8), PACK(0x522A), PACK(0x506C), PACK(0x51AE),
        PACK(0x5AF0), PACK(0x5B32), PACK(0x5974), PACK(0x58B6),
        PACK(0x5DF8), PACK(0x5C3A), PACK(0x5E7C), PACK(0x5FBE),
        PACK(0xE100), PACK(0xE0C2), PACK(0xE284), PACK(0xE346),
        PACK(0xE608), PACK(0xE7CA), PACK(0xE58C), PACK(0xE44E),
        PACK(0xEF10), PACK(0xEED2), PACK(0xEC94), PACK(0xED56),
        PACK(0xE818), PACK(0xE9DA), PACK(0xEB9C), PACK(0xEA5E),
        PACK(0xFD20), PACK(0xFCE2), PACK(0xFEA4), PACK(0xFF66),
        PACK(0xFA28), PACK(0xFBEA), PACK(0xF9AC), PACK(0xF86E),
        PACK(0xF330), PACK(0xF2F2), PACK(0xF0B4), PACK(0xF176),
        PACK(0xF438), PACK(0xF5FA), PACK(0xF7BC), PACK(0xF67E),
        PACK(0xD940), PACK(0xD882), PACK(0xDAC4), PACK(0xDB06),
        PACK(0xDE48), PACK(0xDF8A), PACK(0xDDCC), PACK(0xDC0E),
        PACK(0xD750), PACK(0xD692), PACK(0xD4D4), PACK(0xD516),
        PACK(0xD058), PACK(0xD19A), PACK(0xD3DC), PACK(0xD21E),
        PACK(0xC560), PACK(0xC4A2), PACK(0xC6E4), PACK(0xC726),
        PACK(0xC268), PACK(0xC3AA), PACK(0xC1EC), PACK(0xC02E),
        PACK(0xCB70), PACK(0xCAB2), PACK(0xC8F4), PACK(0xC936),
        PACK(0xCC78), PACK(0xCDBA), PACK(0xCFFC), PACK(0xCE3E),
        PACK(0x9180), PACK(0x9042), PACK(0x9204), PACK(0x93C6),
        PACK(0x9688), PACK(0x974A), PACK(0x950C), PACK(0x94CE),
        PACK(0x9F90), PACK(0x9E52), PACK(0x9C14), PACK(0x9DD6),
        PACK(0x9898), PACK(0x995A), PACK(0x9B1C), PACK(0x9ADE),
        PACK(0x8DA0), PACK(0x8C62), PACK(0x8E24), PACK(0x8FE6),
        PACK(0x8AA8), PACK(0x8B6A), PACK(0x892C), PACK(0x88EE),
        PACK(0x83B0), PACK(0x8272), PACK(0x8034), PACK(0x81F6),
        PACK(0x84B8), PACK(0x857A), PACK(0x873C), PACK(0x86FE),
        PACK(0xA9C0), PACK(0xA802), PACK(0xAA44), PACK(0xAB86),
        PACK(0xAEC8), PACK(0xAF0A), PACK(0xAD4C), PACK(0xAC8E),
        PACK(0xA7D0), PACK(0xA612), PACK(0xA454), PACK(0xA596),
        PACK(0xA0D8), PACK(0xA11A), PACK(0xA35C), PACK(0xA29E),
        PACK(0xB5E0), PACK(0xB422), PACK(0xB664), PACK(0xB7A6),
        PACK(0xB2E8), PACK(0xB32A), PACK(0xB16C), PACK(0xB0AE),
        PACK(0xBBF0), PACK(0xBA32), PACK(0xB874), PACK(0xB9B6),
        PACK(0xBCF8), PACK(0xBD3A), PACK(0xBF7C), PACK(0xBEBE)
    };

    while (1) {
        Z.hi ^= Htable[n].hi;
        Z.lo ^= Htable[n].lo;

        if ((u8 *)Xi == xi)
            break;

        n = *(--xi);

        rem = (size_t)Z.lo & 0xff;
        Z.lo = (Z.hi << 56) | (Z.lo >> 8);
        Z.hi = (Z.hi >> 8);
        if (sizeof(size_t) == 8)
            Z.hi ^= rem_8bit[rem];
        else
            Z.hi ^= (u64)rem_8bit[rem] << 32;
    }

    if (is_endian.little) {
# ifdef BSWAP8
        Xi[0] = BSWAP8(Z.hi);
        Xi[1] = BSWAP8(Z.lo);
# else
        u8 *p = (u8 *)Xi;
        u32 v;
        v = (u32)(Z.hi >> 32);
        PUTU32(p, v);
        v = (u32)(Z.hi);
        PUTU32(p + 4, v);
        v = (u32)(Z.lo >> 32);
        PUTU32(p + 8, v);
        v = (u32)(Z.lo);
        PUTU32(p + 12, v);
# endif
    } else {
        Xi[0] = Z.hi;
        Xi[1] = Z.lo;
    }
}

# define GCM_MUL(ctx,Xi)   gcm_gmult_8bit(ctx->Xi.u,ctx->Htable)

#elif   TABLE_BITS==4

static void gcm_init_4bit(u128 Htable[16], u64 H[2])
{
    u128 V;
# if defined(OPENSSL_SMALL_FOOTPRINT)
    int i;
# endif

    Htable[0].hi = 0;
    Htable[0].lo = 0;
    V.hi = H[0];
    V.lo = H[1];

# if defined(OPENSSL_SMALL_FOOTPRINT)
    for (Htable[8] = V, i = 4; i > 0; i >>= 1) {
        REDUCE1BIT(V);
        Htable[i] = V;
    }

    for (i = 2; i < 16; i <<= 1) {
        u128 *Hi = Htable + i;
        int j;
        for (V = *Hi, j = 1; j < i; ++j) {
            Hi[j].hi = V.hi ^ Htable[j].hi;
            Hi[j].lo = V.lo ^ Htable[j].lo;
        }
    }
# else
    Htable[8] = V;
    REDUCE1BIT(V);
    Htable[4] = V;
    REDUCE1BIT(V);
    Htable[2] = V;
    REDUCE1BIT(V);
    Htable[1] = V;
    Htable[3].hi = V.hi ^ Htable[2].hi, Htable[3].lo = V.lo ^ Htable[2].lo;
    V = Htable[4];
    Htable[5].hi = V.hi ^ Htable[1].hi, Htable[5].lo = V.lo ^ Htable[1].lo;
    Htable[6].hi = V.hi ^ Htable[2].hi, Htable[6].lo = V.lo ^ Htable[2].lo;
    Htable[7].hi = V.hi ^ Htable[3].hi, Htable[7].lo = V.lo ^ Htable[3].lo;
    V = Htable[8];
    Htable[9].hi = V.hi ^ Htable[1].hi, Htable[9].lo = V.lo ^ Htable[1].lo;
    Htable[10].hi = V.hi ^ Htable[2].hi, Htable[10].lo = V.lo ^ Htable[2].lo;
    Htable[11].hi = V.hi ^ Htable[3].hi, Htable[11].lo = V.lo ^ Htable[3].lo;
    Htable[12].hi = V.hi ^ Htable[4].hi, Htable[12].lo = V.lo ^ Htable[4].lo;
    Htable[13].hi = V.hi ^ Htable[5].hi, Htable[13].lo = V.lo ^ Htable[5].lo;
    Htable[14].hi = V.hi ^ Htable[6].hi, Htable[14].lo = V.lo ^ Htable[6].lo;
    Htable[15].hi = V.hi ^ Htable[7].hi, Htable[15].lo = V.lo ^ Htable[7].lo;
# endif
# if defined(GHASH_ASM) && (defined(__arm__) || defined(__arm))
    /*
     * ARM assembler expects specific dword order in Htable.
     */
    {
        int j;
        const union {
            long one;
            char little;
        } is_endian = { 1 };

        if (is_endian.little)
            for (j = 0; j < 16; ++j) {
                V = Htable[j];
                Htable[j].hi = V.lo;
                Htable[j].lo = V.hi;
        } else
            for (j = 0; j < 16; ++j) {
                V = Htable[j];
                Htable[j].hi = V.lo << 32 | V.lo >> 32;
                Htable[j].lo = V.hi << 32 | V.hi >> 32;
            }
    }
# endif
}

# ifndef GHASH_ASM
static const size_t rem_4bit[16] = {
    PACK(0x0000), PACK(0x1C20), PACK(0x3840), PACK(0x2460),
    PACK(0x7080), PACK(0x6CA0), PACK(0x48C0), PACK(0x54E0),
    PACK(0xE100), PACK(0xFD20), PACK(0xD940), PACK(0xC560),
    PACK(0x9180), PACK(0x8DA0), PACK(0xA9C0), PACK(0xB5E0)
};

static void gcm_gmult_4bit(u64 Xi[2], const u128 Htable[16])
{
    u128 Z;
    int cnt = 15;
    size_t rem, nlo, nhi;
    const union {
        long one;
        char little;
    } is_endian = { 1 };

    nlo = ((const u8 *)Xi)[15];
    nhi = nlo >> 4;
    nlo &= 0xf;

    Z.hi = Htable[nlo].hi;
    Z.lo = Htable[nlo].lo;

    while (1) {
        rem = (size_t)Z.lo & 0xf;
        Z.lo = (Z.hi << 60) | (Z.lo >> 4);
        Z.hi = (Z.hi >> 4);
        if (sizeof(size_t) == 8)
            Z.hi ^= rem_4bit[rem];
        else
            Z.hi ^= (u64)rem_4bit[rem] << 32;

        Z.hi ^= Htable[nhi].hi;
        Z.lo ^= Htable[nhi].lo;

        if (--cnt < 0)
            break;

        nlo = ((const u8 *)Xi)[cnt];
        nhi = nlo >> 4;
        nlo &= 0xf;

        rem = (size_t)Z.lo & 0xf;
        Z.lo = (Z.hi << 60) | (Z.lo >> 4);
        Z.hi = (Z.hi >> 4);
        if (sizeof(size_t) == 8)
            Z.hi ^= rem_4bit[rem];
        else
            Z.hi ^= (u64)rem_4bit[rem] << 32;

        Z.hi ^= Htable[nlo].hi;
        Z.lo ^= Htable[nlo].lo;
    }

    if (is_endian.little) {
#  ifdef BSWAP8
        Xi[0] = BSWAP8(Z.hi);
        Xi[1] = BSWAP8(Z.lo);
#  else
        u8 *p = (u8 *)Xi;
        u32 v;
        v = (u32)(Z.hi >> 32);
        PUTU32(p, v);
        v = (u32)(Z.hi);
        PUTU32(p + 4, v);
        v = (u32)(Z.lo >> 32);
        PUTU32(p + 8, v);
        v = (u32)(Z.lo);
        PUTU32(p + 12, v);
#  endif
    } else {
        Xi[0] = Z.hi;
        Xi[1] = Z.lo;
    }
}

#  if !defined(OPENSSL_SMALL_FOOTPRINT)
/*
 * Streamed gcm_mult_4bit, see CRYPTO_gcm128_[en|de]crypt for
 * details... Compiler-generated code doesn't seem to give any
 * performance improvement, at least not on x86[_64]. It's here
 * mostly as reference and a placeholder for possible future
 * non-trivial optimization[s]...
 */
static void gcm_ghash_4bit(u64 Xi[2], const u128 Htable[16],
                           const u8 *inp, size_t len)
{
    u128 Z;
    int cnt;
    size_t rem, nlo, nhi;
    const union {
        long one;
        char little;
    } is_endian = { 1 };

#   if 1
    do {
        cnt = 15;
        nlo = ((const u8 *)Xi)[15];
        nlo ^= inp[15];
        nhi = nlo >> 4;
        nlo &= 0xf;

        Z.hi = Htable[nlo].hi;
        Z.lo = Htable[nlo].lo;

        while (1) {
            rem = (size_t)Z.lo & 0xf;
            Z.lo = (Z.hi << 60) | (Z.lo >> 4);
            Z.hi = (Z.hi >> 4);
            if (sizeof(size_t) == 8)
                Z.hi ^= rem_4bit[rem];
            else
                Z.hi ^= (u64)rem_4bit[rem] << 32;

            Z.hi ^= Htable[nhi].hi;
            Z.lo ^= Htable[nhi].lo;

            if (--cnt < 0)
                break;

            nlo = ((const u8 *)Xi)[cnt];
            nlo ^= inp[cnt];
            nhi = nlo >> 4;
            nlo &= 0xf;

            rem = (size_t)Z.lo & 0xf;
            Z.lo = (Z.hi << 60) | (Z.lo >> 4);
            Z.hi = (Z.hi >> 4);
            if (sizeof(size_t) == 8)
                Z.hi ^= rem_4bit[rem];
            else
                Z.hi ^= (u64)rem_4bit[rem] << 32;

            Z.hi ^= Htable[nlo].hi;
            Z.lo ^= Htable[nlo].lo;
        }
#   else
    /*
     * Extra 256+16 bytes per-key plus 512 bytes shared tables
     * [should] give ~50% improvement... One could have PACK()-ed
     * the rem_8bit even here, but the priority is to minimize
     * cache footprint...
     */
    u128 Hshr4[16];             /* Htable shifted right by 4 bits */
    u8 Hshl4[16];               /* Htable shifted left by 4 bits */
    static const unsigned short rem_8bit[256] = {
        0x0000, 0x01C2, 0x0384, 0x0246, 0x0708, 0x06CA, 0x048C, 0x054E,
        0x0E10, 0x0FD2, 0x0D94, 0x0C56, 0x0918, 0x08DA, 0x0A9C, 0x0B5E,
        0x1C20, 0x1DE2, 0x1FA4, 0x1E66, 0x1B28, 0x1AEA, 0x18AC, 0x196E,
        0x1230, 0x13F2, 0x11B4, 0x1076, 0x1538, 0x14FA, 0x16BC, 0x177E,
        0x3840, 0x3982, 0x3BC4, 0x3A06, 0x3F48, 0x3E8A, 0x3CCC, 0x3D0E,
        0x3650, 0x3792, 0x35D4, 0x3416, 0x3158, 0x309A, 0x32DC, 0x331E,
        0x2460, 0x25A2, 0x27E4, 0x2626, 0x2368, 0x22AA, 0x20EC, 0x212E,
        0x2A70, 0x2BB2, 0x29F4, 0x2836, 0x2D78, 0x2CBA, 0x2EFC, 0x2F3E,
        0x7080, 0x7142, 0x7304, 0x72C6, 0x7788, 0x764A, 0x740C, 0x75CE,
        0x7E90, 0x7F52, 0x7D14, 0x7CD6, 0x7998, 0x785A, 0x7A1C, 0x7BDE,
        0x6CA0, 0x6D62, 0x6F24, 0x6EE6, 0x6BA8, 0x6A6A, 0x682C, 0x69EE,
        0x62B0, 0x6372, 0x6134, 0x60F6, 0x65B8, 0x647A, 0x663C, 0x67FE,
        0x48C0, 0x4902, 0x4B44, 0x4A86, 0x4FC8, 0x4E0A, 0x4C4C, 0x4D8E,
        0x46D0, 0x4712, 0x4554, 0x4496, 0x41D8, 0x401A, 0x425C, 0x439E,
        0x54E0, 0x5522, 0x5764, 0x56A6, 0x53E8, 0x522A, 0x506C, 0x51AE,
        0x5AF0, 0x5B32, 0x5974, 0x58B6, 0x5DF8, 0x5C3A, 0x5E7C, 0x5FBE,
        0xE100, 0xE0C2, 0xE284, 0xE346, 0xE608, 0xE7CA, 0xE58C, 0xE44E,
        0xEF10, 0xEED2, 0xEC94, 0xED56, 0xE818, 0xE9DA, 0xEB9C, 0xEA5E,
        0xFD20, 0xFCE2, 0xFEA4, 0xFF66, 0xFA28, 0xFBEA, 0xF9AC, 0xF86E,
        0xF330, 0xF2F2, 0xF0B4, 0xF176, 0xF438, 0xF5FA, 0xF7BC, 0xF67E,
        0xD940, 0xD882, 0xDAC4, 0xDB06, 0xDE48, 0xDF8A, 0xDDCC, 0xDC0E,
        0xD750, 0xD692, 0xD4D4, 0xD516, 0xD058, 0xD19A, 0xD3DC, 0xD21E,
        0xC560, 0xC4A2, 0xC6E4, 0xC726, 0xC268, 0xC3AA, 0xC1EC, 0xC02E,
        0xCB70, 0xCAB2, 0xC8F4, 0xC936, 0xCC78, 0xCDBA, 0xCFFC, 0xCE3E,
        0x9180, 0x9042, 0x9204, 0x93C6, 0x9688, 0x974A, 0x950C, 0x94CE,
        0x9F90, 0x9E52, 0x9C14, 0x9DD6, 0x9898, 0x995A, 0x9B1C, 0x9ADE,
        0x8DA0, 0x8C62, 0x8E24, 0x8FE6, 0x8AA8, 0x8B6A, 0x892C, 0x88EE,
        0x83B0, 0x8272, 0x8034, 0x81F6, 0x84B8, 0x857A, 0x873C, 0x86FE,
        0xA9C0, 0xA802, 0xAA44, 0xAB86, 0xAEC8, 0xAF0A, 0xAD4C, 0xAC8E,
        0xA7D0, 0xA612, 0xA454, 0xA596, 0xA0D8, 0xA11A, 0xA35C, 0xA29E,
        0xB5E0, 0xB422, 0xB664, 0xB7A6, 0xB2E8, 0xB32A, 0xB16C, 0xB0AE,
        0xBBF0, 0xBA32, 0xB874, 0xB9B6, 0xBCF8, 0xBD3A, 0xBF7C, 0xBEBE
    };
    /*
     * This pre-processing phase slows down procedure by approximately
     * same time as it makes each loop spin faster. In other words
     * single block performance is approximately same as straightforward
     * "4-bit" implementation, and then it goes only faster...
     */
    for (cnt = 0; cnt < 16; ++cnt) {
        Z.hi = Htable[cnt].hi;
        Z.lo = Htable[cnt].lo;
        Hshr4[cnt].lo = (Z.hi << 60) | (Z.lo >> 4);
        Hshr4[cnt].hi = (Z.hi >> 4);
        Hshl4[cnt] = (u8)(Z.lo << 4);
    }

    do {
        for (Z.lo = 0, Z.hi = 0, cnt = 15; cnt; --cnt) {
            nlo = ((const u8 *)Xi)[cnt];
            nlo ^= inp[cnt];
            nhi = nlo >> 4;
            nlo &= 0xf;

            Z.hi ^= Htable[nlo].hi;
            Z.lo ^= Htable[nlo].lo;

            rem = (size_t)Z.lo & 0xff;

            Z.lo = (Z.hi << 56) | (Z.lo >> 8);
            Z.hi = (Z.hi >> 8);

            Z.hi ^= Hshr4[nhi].hi;
            Z.lo ^= Hshr4[nhi].lo;
            Z.hi ^= (u64)rem_8bit[rem ^ Hshl4[nhi]] << 48;
        }

        nlo = ((const u8 *)Xi)[0];
        nlo ^= inp[0];
        nhi = nlo >> 4;
        nlo &= 0xf;

        Z.hi ^= Htable[nlo].hi;
        Z.lo ^= Htable[nlo].lo;

        rem = (size_t)Z.lo & 0xf;

        Z.lo = (Z.hi << 60) | (Z.lo >> 4);
        Z.hi = (Z.hi >> 4);

        Z.hi ^= Htable[nhi].hi;
        Z.lo ^= Htable[nhi].lo;
        Z.hi ^= ((u64)rem_8bit[rem << 4]) << 48;
#   endif

        if (is_endian.little) {
#   ifdef BSWAP8
            Xi[0] = BSWAP8(Z.hi);
            Xi[1] = BSWAP8(Z.lo);
#   else
            u8 *p = (u8 *)Xi;
            u32 v;
            v = (u32)(Z.hi >> 32);
            PUTU32(p, v);
            v = (u32)(Z.hi);
            PUTU32(p + 4, v);
            v = (u32)(Z.lo >> 32);
            PUTU32(p + 8, v);
            v = (u32)(Z.lo);
            PUTU32(p + 12, v);
#   endif
        } else {
            Xi[0] = Z.hi;
            Xi[1] = Z.lo;
        }
    } while (inp += 16, len -= 16);
}
#  endif
# else
void gcm_gmult_4bit(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_4bit(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                    size_t len);
# endif

# define GCM_MUL(ctx,Xi)   gcm_gmult_4bit(ctx->Xi.u,ctx->Htable)
# if defined(GHASH_ASM) || !defined(OPENSSL_SMALL_FOOTPRINT)
#  define GHASH(ctx,in,len) gcm_ghash_4bit((ctx)->Xi.u,(ctx)->Htable,in,len)
/*
 * GHASH_CHUNK is "stride parameter" missioned to mitigate cache trashing
 * effect. In other words idea is to hash data while it's still in L1 cache
 * after encryption pass...
 */
#  define GHASH_CHUNK       (3*1024)
# endif

#else                           /* TABLE_BITS */

static void gcm_gmult_1bit(u64 Xi[2], const u64 H[2])
{
    u128 V, Z = { 0, 0 };
    long X;
    int i, j;
    const long *xi = (const long *)Xi;
    const union {
        long one;
        char little;
    } is_endian = { 1 };

    V.hi = H[0];                /* H is in host byte order, no byte swapping */
    V.lo = H[1];

    for (j = 0; j < 16 / sizeof(long); ++j) {
        if (is_endian.little) {
            if (sizeof(long) == 8) {
# ifdef BSWAP8
                X = (long)(BSWAP8(xi[j]));
# else
                const u8 *p = (const u8 *)(xi + j);
                X = (long)((u64)GETU32(p) << 32 | GETU32(p + 4));
# endif
            } else {
                const u8 *p = (const u8 *)(xi + j);
                X = (long)GETU32(p);
            }
        } else
            X = xi[j];

        for (i = 0; i < 8 * sizeof(long); ++i, X <<= 1) {
            u64 M = (u64)(X >> (8 * sizeof(long) - 1));
            Z.hi ^= V.hi & M;
            Z.lo ^= V.lo & M;

            REDUCE1BIT(V);
        }
    }

    if (is_endian.little) {
# ifdef BSWAP8
        Xi[0] = BSWAP8(Z.hi);
        Xi[1] = BSWAP8(Z.lo);
# else
        u8 *p = (u8 *)Xi;
        u32 v;
        v = (u32)(Z.hi >> 32);
        PUTU32(p, v);
        v = (u32)(Z.hi);
        PUTU32(p + 4, v);
        v = (u32)(Z.lo >> 32);
        PUTU32(p + 8, v);
        v = (u32)(Z.lo);
        PUTU32(p + 12, v);
# endif
    } else {
        Xi[0] = Z.hi;
        Xi[1] = Z.lo;
    }
}

# define GCM_MUL(ctx,Xi)   gcm_gmult_1bit(ctx->Xi.u,ctx->H.u)

#endif

#if     TABLE_BITS==4 && (defined(GHASH_ASM) || defined(OPENSSL_CPUID_OBJ))
# if    !defined(I386_ONLY) && \
        (defined(__i386)        || defined(__i386__)    || \
         defined(__x86_64)      || defined(__x86_64__)  || \
         defined(_M_IX86)       || defined(_M_AMD64)    || defined(_M_X64))
#  define GHASH_ASM_X86_OR_64
#  define GCM_FUNCREF_4BIT
extern unsigned int OPENSSL_ia32cap_P[];

void gcm_init_clmul(u128 Htable[16], const u64 Xi[2]);
void gcm_gmult_clmul(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_clmul(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                     size_t len);

#  if defined(__i386) || defined(__i386__) || defined(_M_IX86)
#   define gcm_init_avx   gcm_init_clmul
#   define gcm_gmult_avx  gcm_gmult_clmul
#   define gcm_ghash_avx  gcm_ghash_clmul
#  else
void gcm_init_avx(u128 Htable[16], const u64 Xi[2]);
void gcm_gmult_avx(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_avx(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                   size_t len);
#  endif

#  if   defined(__i386) || defined(__i386__) || defined(_M_IX86)
#   define GHASH_ASM_X86
void gcm_gmult_4bit_mmx(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_4bit_mmx(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                        size_t len);

void gcm_gmult_4bit_x86(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_4bit_x86(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                        size_t len);
#  endif
# elif defined(__arm__) || defined(__arm) || defined(__aarch64__)
#  include "arm_arch.h"
#  if __ARM_MAX_ARCH__>=7
#   define GHASH_ASM_ARM
#   define GCM_FUNCREF_4BIT
#   define PMULL_CAPABLE        (OPENSSL_armcap_P & ARMV8_PMULL)
#   if defined(__arm__) || defined(__arm)
#    define NEON_CAPABLE        (OPENSSL_armcap_P & ARMV7_NEON)
#   endif
void gcm_init_neon(u128 Htable[16], const u64 Xi[2]);
void gcm_gmult_neon(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_neon(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                    size_t len);
void gcm_init_v8(u128 Htable[16], const u64 Xi[2]);
void gcm_gmult_v8(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_v8(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                  size_t len);
#  endif
# elif defined(__sparc__) || defined(__sparc)
#  include "sparc_arch.h"
#  define GHASH_ASM_SPARC
#  define GCM_FUNCREF_4BIT
extern unsigned int OPENSSL_sparcv9cap_P[];
void gcm_init_vis3(u128 Htable[16], const u64 Xi[2]);
void gcm_gmult_vis3(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_vis3(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                    size_t len);
# elif defined(OPENSSL_CPUID_OBJ) && (defined(__powerpc__) || defined(__ppc__) || defined(_ARCH_PPC))
#  include "ppc_arch.h"
#  define GHASH_ASM_PPC
#  define GCM_FUNCREF_4BIT
void gcm_init_p8(u128 Htable[16], const u64 Xi[2]);
void gcm_gmult_p8(u64 Xi[2], const u128 Htable[16]);
void gcm_ghash_p8(u64 Xi[2], const u128 Htable[16], const u8 *inp,
                  size_t len);
# endif
#endif

#ifdef GCM_FUNCREF_4BIT
# undef  GCM_MUL
# define GCM_MUL(ctx,Xi)        (*gcm_gmult_p)(ctx->Xi.u,ctx->Htable)
# ifdef GHASH
#  undef  GHASH
#  define GHASH(ctx,in,len)     (*gcm_ghash_p)(ctx->Xi.u,ctx->Htable,in,len)
# endif
#endif

void CRYPTO_gcm128_init(GCM128_CONTEXT *ctx, void *key, block128_f block)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };

    memset(ctx, 0, sizeof(*ctx));
    ctx->block = block;
    ctx->key = key;

    (*block) (ctx->H.c, ctx->H.c, key);

    if (is_endian.little) {
        /* H is stored in host byte order */
#ifdef BSWAP8
        ctx->H.u[0] = BSWAP8(ctx->H.u[0]);
        ctx->H.u[1] = BSWAP8(ctx->H.u[1]);
#else
        u8 *p = ctx->H.c;
        u64 hi, lo;
        hi = (u64)GETU32(p) << 32 | GETU32(p + 4);
        lo = (u64)GETU32(p + 8) << 32 | GETU32(p + 12);
        ctx->H.u[0] = hi;
        ctx->H.u[1] = lo;
#endif
    }
#if     TABLE_BITS==8
    gcm_init_8bit(ctx->Htable, ctx->H.u);
#elif   TABLE_BITS==4
# if    defined(GHASH)
#  define CTX__GHASH(f) (ctx->ghash = (f))
# else
#  define CTX__GHASH(f) (ctx->ghash = NULL)
# endif
# if    defined(GHASH_ASM_X86_OR_64)
#  if   !defined(GHASH_ASM_X86) || defined(OPENSSL_IA32_SSE2)
    if (OPENSSL_ia32cap_P[1] & (1 << 1)) { /* check PCLMULQDQ bit */
        if (((OPENSSL_ia32cap_P[1] >> 22) & 0x41) == 0x41) { /* AVX+MOVBE */
            gcm_init_avx(ctx->Htable, ctx->H.u);
            ctx->gmult = gcm_gmult_avx;
            CTX__GHASH(gcm_ghash_avx);
        } else {
            gcm_init_clmul(ctx->Htable, ctx->H.u);
            ctx->gmult = gcm_gmult_clmul;
            CTX__GHASH(gcm_ghash_clmul);
        }
        return;
    }
#  endif
    gcm_init_4bit(ctx->Htable, ctx->H.u);
#  if   defined(GHASH_ASM_X86)  /* x86 only */
#   if  defined(OPENSSL_IA32_SSE2)
    if (OPENSSL_ia32cap_P[0] & (1 << 25)) { /* check SSE bit */
#   else
    if (OPENSSL_ia32cap_P[0] & (1 << 23)) { /* check MMX bit */
#   endif
        ctx->gmult = gcm_gmult_4bit_mmx;
        CTX__GHASH(gcm_ghash_4bit_mmx);
    } else {
        ctx->gmult = gcm_gmult_4bit_x86;
        CTX__GHASH(gcm_ghash_4bit_x86);
    }
#  else
    ctx->gmult = gcm_gmult_4bit;
    CTX__GHASH(gcm_ghash_4bit);
#  endif
# elif  defined(GHASH_ASM_ARM)
#  ifdef PMULL_CAPABLE
    if (PMULL_CAPABLE) {
        gcm_init_v8(ctx->Htable, ctx->H.u);
        ctx->gmult = gcm_gmult_v8;
        CTX__GHASH(gcm_ghash_v8);
    } else
#  endif
#  ifdef NEON_CAPABLE
    if (NEON_CAPABLE) {
        gcm_init_neon(ctx->Htable, ctx->H.u);
        ctx->gmult = gcm_gmult_neon;
        CTX__GHASH(gcm_ghash_neon);
    } else
#  endif
    {
        gcm_init_4bit(ctx->Htable, ctx->H.u);
        ctx->gmult = gcm_gmult_4bit;
        CTX__GHASH(gcm_ghash_4bit);
    }
# elif  defined(GHASH_ASM_SPARC)
    if (OPENSSL_sparcv9cap_P[0] & SPARCV9_VIS3) {
        gcm_init_vis3(ctx->Htable, ctx->H.u);
        ctx->gmult = gcm_gmult_vis3;
        CTX__GHASH(gcm_ghash_vis3);
    } else {
        gcm_init_4bit(ctx->Htable, ctx->H.u);
        ctx->gmult = gcm_gmult_4bit;
        CTX__GHASH(gcm_ghash_4bit);
    }
# elif  defined(GHASH_ASM_PPC)
    if (OPENSSL_ppccap_P & PPC_CRYPTO207) {
        gcm_init_p8(ctx->Htable, ctx->H.u);
        ctx->gmult = gcm_gmult_p8;
        CTX__GHASH(gcm_ghash_p8);
    } else {
        gcm_init_4bit(ctx->Htable, ctx->H.u);
        ctx->gmult = gcm_gmult_4bit;
        CTX__GHASH(gcm_ghash_4bit);
    }
# else
    gcm_init_4bit(ctx->Htable, ctx->H.u);
# endif
# undef CTX__GHASH
#endif
}

// JINHO CUSTOM FUNCTION FOR DEBUG
void print_keystream(FILE *out, unsigned char *keystream, int ctr_start, int len) {
  for (size_t i=0; i<len; i++) {
    unsigned ctr = ctr_start + i;
    fprintf(out, "(CTR = %08d) ", ctr);
    for (size_t j=0; j<16; j++) {
      fprintf(out, "%02x ", keystream[i * 16 + j]);
    }
    fprintf(out, "\n");
  }
}

void CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx, const unsigned char *iv,
                         size_t len)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int ctr;
#ifdef GCM_FUNCREF_4BIT
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
#endif

    ctx->Yi.u[0] = 0;
    ctx->Yi.u[1] = 0;
    ctx->Xi.u[0] = 0;
    ctx->Xi.u[1] = 0;
    ctx->len.u[0] = 0;          /* AAD length */
    ctx->len.u[1] = 0;          /* message length */
    ctx->ares = 0;
    ctx->mres = 0;

    if (len == 12) {
        memcpy(ctx->Yi.c, iv, 12);
        ctx->Yi.c[15] = 1;
        ctr = 1;
    } else {
        size_t i;
        u64 len0 = len;

        while (len >= 16) {
            for (i = 0; i < 16; ++i)
                ctx->Yi.c[i] ^= iv[i];
            GCM_MUL(ctx, Yi);
            iv += 16;
            len -= 16;
        }
        if (len) {
            for (i = 0; i < len; ++i)
                ctx->Yi.c[i] ^= iv[i];
            GCM_MUL(ctx, Yi);
        }
        len0 <<= 3;
        if (is_endian.little) {
#ifdef BSWAP8
            ctx->Yi.u[1] ^= BSWAP8(len0);
#else
            ctx->Yi.c[8] ^= (u8)(len0 >> 56);
            ctx->Yi.c[9] ^= (u8)(len0 >> 48);
            ctx->Yi.c[10] ^= (u8)(len0 >> 40);
            ctx->Yi.c[11] ^= (u8)(len0 >> 32);
            ctx->Yi.c[12] ^= (u8)(len0 >> 24);
            ctx->Yi.c[13] ^= (u8)(len0 >> 16);
            ctx->Yi.c[14] ^= (u8)(len0 >> 8);
            ctx->Yi.c[15] ^= (u8)(len0);
#endif
        } else
            ctx->Yi.u[1] ^= len0;

        GCM_MUL(ctx, Yi);

        if (is_endian.little)
#ifdef BSWAP4
            ctr = BSWAP4(ctx->Yi.d[3]);
#else
            ctr = GETU32(ctx->Yi.c + 12);
#endif
        else
            ctr = ctx->Yi.d[3];
    }

    (*ctx->block) (ctx->Yi.c, ctx->EK0.c, ctx->key);
    ++ctr;
    if (is_endian.little)
#ifdef BSWAP4
        ctx->Yi.d[3] = BSWAP4(ctr);
#else
        PUTU32(ctx->Yi.c + 12, ctr);
#endif
    else
        ctx->Yi.d[3] = ctr;
}

int CRYPTO_gcm128_aad(GCM128_CONTEXT *ctx, const unsigned char *aad,
                      size_t len)
{
    size_t i;
    unsigned int n;
    u64 alen = ctx->len.u[0];
#ifdef GCM_FUNCREF_4BIT
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
# ifdef GHASH
    void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx->ghash;
# endif
#endif

    if (ctx->len.u[1])
        return -2;

    alen += len;
    if (alen > (U64(1) << 61) || (sizeof(len) == 8 && alen < len))
        return -1;
    ctx->len.u[0] = alen;

    n = ctx->ares;
    if (n) {
        while (n && len) {
            ctx->Xi.c[n] ^= *(aad++);
            --len;
            n = (n + 1) % 16;
        }
        if (n == 0)
            GCM_MUL(ctx, Xi);
        else {
            ctx->ares = n;
            return 0;
        }
    }
#ifdef GHASH
    if ((i = (len & (size_t)-16))) {
        GHASH(ctx, aad, i);
        aad += i;
        len -= i;
    }
#else
    while (len >= 16) {
        for (i = 0; i < 16; ++i)
            ctx->Xi.c[i] ^= aad[i];
        GCM_MUL(ctx, Xi);
        aad += 16;
        len -= 16;
    }
#endif
    if (len) {
        n = (unsigned int)len;
        for (i = 0; i < len; ++i)
            ctx->Xi.c[i] ^= aad[i];
    }

    ctx->ares = n;
    return 0;
}

int CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx,
                          const unsigned char *in, unsigned char *out,
                          size_t len)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int n, ctr;
    size_t i;
    u64 mlen = ctx->len.u[1];
    block128_f block = ctx->block;
    void *key = ctx->key;
#ifdef GCM_FUNCREF_4BIT
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
# if defined(GHASH) && !defined(OPENSSL_SMALL_FOOTPRINT)
    void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx->ghash;
# endif
#endif
    // fprintf(stdout, "CRYPTO_gcm128_encrypt\n\n");

    mlen += len;
    if (mlen > ((U64(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    if (ctx->ares) {
        /* First call to encrypt finalizes GHASH(AAD) */
        GCM_MUL(ctx, Xi);
        ctx->ares = 0;
    }

    if (is_endian.little)
#ifdef BSWAP4
        ctr = BSWAP4(ctx->Yi.d[3]);
#else
        ctr = GETU32(ctx->Yi.c + 12);
#endif
    else
        ctr = ctx->Yi.d[3];

    n = ctx->mres;
#if !defined(OPENSSL_SMALL_FOOTPRINT)
    if (16 % sizeof(size_t) == 0) { /* always true actually */
        do {
            if (n) {
                while (n && len) {
                    ctx->Xi.c[n] ^= *(out++) = *(in++) ^ ctx->EKi.c[n];
                    --len;
                    n = (n + 1) % 16;
                }
                if (n == 0)
                    GCM_MUL(ctx, Xi);
                else {
                    ctx->mres = n;
                    return 0;
                }
            }
# if defined(STRICT_ALIGNMENT)
            if (((size_t)in | (size_t)out) % sizeof(size_t) != 0)
                break;
# endif
# if defined(GHASH)
#  if defined(GHASH_CHUNK)
            while (len >= GHASH_CHUNK) {
                size_t j = GHASH_CHUNK;

                while (j) {
                    size_t *out_t = (size_t *)out;
                    const size_t *in_t = (const size_t *)in;

                    (*block) (ctx->Yi.c, ctx->EKi.c, key);
                    ++ctr;
                    if (is_endian.little)
#   ifdef BSWAP4
                        ctx->Yi.d[3] = BSWAP4(ctr);
#   else
                        PUTU32(ctx->Yi.c + 12, ctr);
#   endif
                    else
                        ctx->Yi.d[3] = ctr;
                    for (i = 0; i < 16 / sizeof(size_t); ++i)
                        out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                    out += 16;
                    in += 16;
                    j -= 16;
                }
                GHASH(ctx, out - GHASH_CHUNK, GHASH_CHUNK);
                len -= GHASH_CHUNK;
            }
#  endif
            if ((i = (len & (size_t)-16))) {
                size_t j = i;

                while (len >= 16) {
                    size_t *out_t = (size_t *)out;
                    const size_t *in_t = (const size_t *)in;

                    (*block) (ctx->Yi.c, ctx->EKi.c, key);
                    ++ctr;
                    if (is_endian.little)
#  ifdef BSWAP4
                        ctx->Yi.d[3] = BSWAP4(ctr);
#  else
                        PUTU32(ctx->Yi.c + 12, ctr);
#  endif
                    else
                        ctx->Yi.d[3] = ctr;
                    for (i = 0; i < 16 / sizeof(size_t); ++i)
                        out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                    out += 16;
                    in += 16;
                    len -= 16;
                }
                GHASH(ctx, out - j, j);
            }
# else
            while (len >= 16) {
                size_t *out_t = (size_t *)out;
                const size_t *in_t = (const size_t *)in;

                (*block) (ctx->Yi.c, ctx->EKi.c, key);
                ++ctr;
                if (is_endian.little)
#  ifdef BSWAP4
                    ctx->Yi.d[3] = BSWAP4(ctr);
#  else
                    PUTU32(ctx->Yi.c + 12, ctr);
#  endif
                else
                    ctx->Yi.d[3] = ctr;
                for (i = 0; i < 16 / sizeof(size_t); ++i)
                    ctx->Xi.t[i] ^= out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                GCM_MUL(ctx, Xi);
                out += 16;
                in += 16;
                len -= 16;
            }
# endif
            if (len) {
                (*block) (ctx->Yi.c, ctx->EKi.c, key);
                ++ctr;
                if (is_endian.little)
# ifdef BSWAP4
                    ctx->Yi.d[3] = BSWAP4(ctr);
# else
                    PUTU32(ctx->Yi.c + 12, ctr);
# endif
                else
                    ctx->Yi.d[3] = ctr;
                while (len--) {
                    ctx->Xi.c[n] ^= out[n] = in[n] ^ ctx->EKi.c[n];
                    ++n;
                }
            }

            ctx->mres = n;
            return 0;
        } while (0);
    }
#endif
    for (i = 0; i < len; ++i) {
        if (n == 0) {
            (*block) (ctx->Yi.c, ctx->EKi.c, key);
            ++ctr;
            if (is_endian.little)
#ifdef BSWAP4
                ctx->Yi.d[3] = BSWAP4(ctr);
#else
                PUTU32(ctx->Yi.c + 12, ctr);
#endif
            else
                ctx->Yi.d[3] = ctr;
        }
        ctx->Xi.c[n] ^= out[i] = in[i] ^ ctx->EKi.c[n];
        n = (n + 1) % 16;
        if (n == 0)
            GCM_MUL(ctx, Xi);
    }

    ctx->mres = n;
    return 0;
}

int jinho_CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx,
                          const unsigned char *in, unsigned char *out,
                          size_t len)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int ctr;
    block128_f block = ctx->block;
    void *key = ctx->key;

    if (is_endian.little)
#ifdef BSWAP4
        ctr = BSWAP4(ctx->Yi.d[3]);
#else
        ctr = GETU32(ctx->Yi.c + 12);
#endif
    else
        ctr = ctx->Yi.d[3];

    (*block) (ctx->Yi.c, out, key);
    ++ctr;
    if (is_endian.little)
#ifdef BSWAP4
	ctx->Yi.d[3] = BSWAP4(ctr);
#else
	PUTU32(ctx->Yi.c + 12, ctr);
#endif
    else
	ctx->Yi.d[3] = ctr;
    return 0;
}
#define borim_BUFFER_SIZE 8192
#define borim_AES_GCM_BLOCK_SIZE 16
unsigned char generated_keystreams[borim_BUFFER_SIZE][borim_AES_GCM_BLOCK_SIZE];

typedef struct
{
    unsigned char keystreams[borim_BUFFER_SIZE][borim_AES_GCM_BLOCK_SIZE];
    atomic_int head;
    atomic_int tail;
} CircularBuffer;

int CB_used(head, tail, buf_size) {
    return (tail - head + buf_size) % buf_size;
}

int borim_processKeystream(void *keystruct, unsigned char *buf, int len) {
    int cnt = 0, res = len;
    int head_index, item_len, tail_index;
    if (keystruct != NULL && buf != NULL) {
        CircularBuffer *keybuffer = (CircularBuffer *)keystruct;

        while (1) {
            item_len = CB_used(keybuffer->head, keybuffer->tail, borim_BUFFER_SIZE);
            if (item_len <= 0) {
                usleep(100);
                continue;
            } else {
                /*
                head_index = atomic_load(&keybuffer->head);
                tail_index = atomic_load(&keybuffer->tail);
                */
                head_index = keybuffer->head;
                tail_index = keybuffer->tail;
                break;
            }
        }

        if (item_len < len) 
            res = item_len;

        int space_end = head_index + res;
        if (space_end <= borim_BUFFER_SIZE) {
            memcpy(buf, keybuffer->keystreams[head_index], borim_AES_GCM_BLOCK_SIZE * res);
        } else {
            int end = borim_BUFFER_SIZE - head_index;
            int rest = (head_index + res) % borim_BUFFER_SIZE;

            memcpy(buf, keybuffer->keystreams[head_index], borim_AES_GCM_BLOCK_SIZE * end);
            memcpy(buf + (borim_AES_GCM_BLOCK_SIZE * end), keybuffer->keystreams[0], borim_AES_GCM_BLOCK_SIZE * rest);
        }
        
        /*
        atomic_store(&keybuffer->head, (head_index + res) % borim_BUFFER_SIZE);
        */
        keybuffer->head = (head_index + res) % borim_BUFFER_SIZE;
        return res;
    }
    return -1;
}

int borim_CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx,
                          const unsigned char *in, unsigned char *out,
                          size_t len, void *keystruct)
{
    // fprintf(stdout, "borim_CRYPTO_gcm128_encrypt\n\n");
    unsigned int n, ctr;
    size_t i;
    u64 mlen = ctx->len.u[1];
    block128_f block = ctx->block;
#ifdef GCM_FUNCREF_4BIT
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
# if defined(GHASH) && !defined(OPENSSL_SMALL_FOOTPRINT)
    void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx->ghash;
# endif
#endif

    mlen += len;
    if (mlen > ((U64(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    if (ctx->ares) {
        /* First call to encrypt finalizes GHASH(AAD) */
        GCM_MUL(ctx, Xi);
        ctx->ares = 0;
    }

    n = ctx->mres;
#if !defined(OPENSSL_SMALL_FOOTPRINT)
    if (16 % sizeof(size_t) == 0) { /* always true actually */
        do {
            if (n) {
		int cnt = 0;
                while (n && len) {
                    ctx->Xi.c[n] ^= *(out++) = *(in++) ^ ctx->EKi.c[n];
                    --len;
                    n = (n + 1) % 16;
		    cnt++;
                }
                if (n == 0)
                    GCM_MUL(ctx, Xi);
                else {
                    ctx->mres = n;
                    return 0;
                }
            }
# if defined(STRICT_ALIGNMENT)
            if (((size_t)in | (size_t)out) % sizeof(size_t) != 0)
                break;
# endif
# if defined(GHASH)
#  if defined(GHASH_CHUNK)
            while (len >= GHASH_CHUNK) {
                size_t j = GHASH_CHUNK;

                while (j) {
                    size_t *out_t = (size_t *)out;
                    const size_t *in_t = (const size_t *)in;
                    borim_processKeystream(keystruct, ctx->EKi.c, 1);
                    for (i = 0; i < 16 / sizeof(size_t); ++i)
                        out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                    out += 16;
                    in += 16;
                    j -= 16;
                }

		size_t *out_t = (size_t *)out;
		const size_t *in_t = (const size_t *)in;
		
                GHASH(ctx, out - GHASH_CHUNK, GHASH_CHUNK);
                len -= GHASH_CHUNK;
            }
#  endif
            if ((i = (len & (size_t)-16))) {
                size_t j = i;

                while (len >= 16) {
                    size_t *out_t = (size_t *)out;
                    const size_t *in_t = (const size_t *)in;

    		    borim_processKeystream(keystruct, ctx->EKi.c, 1);

                    for (i = 0; i < 16 / sizeof(size_t); ++i)
                        out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                    out += 16;
                    in += 16;
                    len -= 16;
                }
                GHASH(ctx, out - j, j);
            }
# else
            while (len >= 16) {
                size_t *out_t = (size_t *)out;
                const size_t *in_t = (const size_t *)in;
		
    		borim_processKeystream(keystruct, ctxEKi.c, 1);

                for (i = 0; i < 16 / sizeof(size_t); ++i)
                    ctx->Xi.t[i] ^= out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                GCM_MUL(ctx, Xi);
                out += 16;
                in += 16;
                len -= 16;
	    }
# endif
            if (len) {

                borim_processKeystream(keystruct, ctx->EKi.c, 1);
                
                int cnt = 0;
                while (len--) {
                    ctx->Xi.c[n] ^= out[n] = in[n] ^ ctx->EKi.c[n];
                    ++n;
                    cnt++;
                }

            }

            ctx->mres = n;
            return 0;
        } while (0);
    }
#endif
    for (i = 0; i < len; ++i) {

	if(n == 0){
    	    borim_processKeystream(keystruct, ctx->EKi.c, 1);
	}

        ctx->Xi.c[n] ^= out[i] = in[i] ^ ctx->EKi.c[n];
        n = (n + 1) % 16;
        if (n == 0)
            GCM_MUL(ctx, Xi);
    }

    ctx->mres = n;
    return 0;
}



int CRYPTO_gcm128_decrypt(GCM128_CONTEXT *ctx,
                          const unsigned char *in, unsigned char *out,
                          size_t len)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int n, ctr;
    size_t i;
    u64 mlen = ctx->len.u[1];
    block128_f block = ctx->block;
    void *key = ctx->key;
#ifdef GCM_FUNCREF_4BIT
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
# if defined(GHASH) && !defined(OPENSSL_SMALL_FOOTPRINT)
    void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx->ghash;
# endif
#endif

    mlen += len;
    if (mlen > ((U64(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    if (ctx->ares) {
        /* First call to decrypt finalizes GHASH(AAD) */
        GCM_MUL(ctx, Xi);
        ctx->ares = 0;
    }

    if (is_endian.little)
#ifdef BSWAP4
        ctr = BSWAP4(ctx->Yi.d[3]);
#else
        ctr = GETU32(ctx->Yi.c + 12);
#endif
    else
        ctr = ctx->Yi.d[3];

    n = ctx->mres;
#if !defined(OPENSSL_SMALL_FOOTPRINT)
    if (16 % sizeof(size_t) == 0) { /* always true actually */
        do {
            if (n) {
                while (n && len) {
                    u8 c = *(in++);
                    *(out++) = c ^ ctx->EKi.c[n];
                    ctx->Xi.c[n] ^= c;
                    --len;
                    n = (n + 1) % 16;
                }
                if (n == 0)
                    GCM_MUL(ctx, Xi);
                else {
                    ctx->mres = n;
                    return 0;
                }
            }
# if defined(STRICT_ALIGNMENT)
            if (((size_t)in | (size_t)out) % sizeof(size_t) != 0)
                break;
# endif
# if defined(GHASH)
#  if defined(GHASH_CHUNK)
            while (len >= GHASH_CHUNK) {
                size_t j = GHASH_CHUNK;

                GHASH(ctx, in, GHASH_CHUNK);
                while (j) {
                    size_t *out_t = (size_t *)out;
                    const size_t *in_t = (const size_t *)in;

                    (*block) (ctx->Yi.c, ctx->EKi.c, key);
                    ++ctr;
                    if (is_endian.little)
#   ifdef BSWAP4
                        ctx->Yi.d[3] = BSWAP4(ctr);
#   else
                        PUTU32(ctx->Yi.c + 12, ctr);
#   endif
                    else
                        ctx->Yi.d[3] = ctr;
                    for (i = 0; i < 16 / sizeof(size_t); ++i)
                        out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                    out += 16;
                    in += 16;
                    j -= 16;
                }
                len -= GHASH_CHUNK;
            }
#  endif
            if ((i = (len & (size_t)-16))) {
                GHASH(ctx, in, i);
                while (len >= 16) {
                    size_t *out_t = (size_t *)out;
                    const size_t *in_t = (const size_t *)in;

                    (*block) (ctx->Yi.c, ctx->EKi.c, key);
                    ++ctr;
                    if (is_endian.little)
#  ifdef BSWAP4
                        ctx->Yi.d[3] = BSWAP4(ctr);
#  else
                        PUTU32(ctx->Yi.c + 12, ctr);
#  endif
                    else
                        ctx->Yi.d[3] = ctr;
                    for (i = 0; i < 16 / sizeof(size_t); ++i)
                        out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                    out += 16;
                    in += 16;
                    len -= 16;
                }
            }
# else
            while (len >= 16) {
                size_t *out_t = (size_t *)out;
                const size_t *in_t = (const size_t *)in;

                (*block) (ctx->Yi.c, ctx->EKi.c, key);
                ++ctr;
                if (is_endian.little)
#  ifdef BSWAP4
                    ctx->Yi.d[3] = BSWAP4(ctr);
#  else
                    PUTU32(ctx->Yi.c + 12, ctr);
#  endif
                else
                    ctx->Yi.d[3] = ctr;
                for (i = 0; i < 16 / sizeof(size_t); ++i) {
                    size_t c = in[i];
                    out[i] = c ^ ctx->EKi.t[i];
                    ctx->Xi.t[i] ^= c;
                }
                GCM_MUL(ctx, Xi);
                out += 16;
                in += 16;
                len -= 16;
            }
# endif
            if (len) {
                (*block) (ctx->Yi.c, ctx->EKi.c, key);
                ++ctr;
                if (is_endian.little)
# ifdef BSWAP4
                    ctx->Yi.d[3] = BSWAP4(ctr);
# else
                    PUTU32(ctx->Yi.c + 12, ctr);
# endif
                else
                    ctx->Yi.d[3] = ctr;
                while (len--) {
                    u8 c = in[n];
                    ctx->Xi.c[n] ^= c;
                    out[n] = c ^ ctx->EKi.c[n];
                    ++n;
                }
            }

            ctx->mres = n;
            return 0;
        } while (0);
    }
#endif
    for (i = 0; i < len; ++i) {
        u8 c;
        if (n == 0) {
            (*block) (ctx->Yi.c, ctx->EKi.c, key);
            ++ctr;
            if (is_endian.little)
#ifdef BSWAP4
                ctx->Yi.d[3] = BSWAP4(ctr);
#else
                PUTU32(ctx->Yi.c + 12, ctr);
#endif
            else
                ctx->Yi.d[3] = ctr;
        }
        c = in[i];
        out[i] = c ^ ctx->EKi.c[n];
        ctx->Xi.c[n] ^= c;
        n = (n + 1) % 16;
        if (n == 0)
            GCM_MUL(ctx, Xi);
    }

    ctx->mres = n;
    return 0;
}

#if 0
int CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx,
                                const unsigned char *in, unsigned char *out,
                                size_t len, ctr128_f stream)
{
#if defined(OPENSSL_SMALL_FOOTPRINT)
    return CRYPTO_gcm128_encrypt(ctx, in, out, len);
#else
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int n, ctr;
    size_t i;
    u64 mlen = ctx->len.u[1];
    void *key = ctx->key;
# ifdef GCM_FUNCREF_4BIT
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
#  ifdef GHASH
    void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx->ghash;
#  endif
# endif

    mlen += len;
    if (mlen > ((U64(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    if (ctx->ares) {
        /* First call to encrypt finalizes GHASH(AAD) */
        GCM_MUL(ctx, Xi);
        ctx->ares = 0;
    }

    if (is_endian.little)
# ifdef BSWAP4
        ctr = BSWAP4(ctx->Yi.d[3]);
# else
        ctr = GETU32(ctx->Yi.c + 12);
# endif
    else
        ctr = ctx->Yi.d[3];

    n = ctx->mres;
    if (n) {
        while (n && len) {
            ctx->Xi.c[n] ^= *(out++) = *(in++) ^ ctx->EKi.c[n];
            --len;
            n = (n + 1) % 16;
        }
        if (n == 0)
            GCM_MUL(ctx, Xi);
        else {
            ctx->mres = n;
            return 0;
        }
    }
    /*
# if defined(GHASH) && defined(GHASH_CHUNK)
    while (len >= GHASH_CHUNK) {
        (*stream) (in, out, GHASH_CHUNK / 16, key, ctx->Yi.c);
        ctr += GHASH_CHUNK / 16;
        if (is_endian.little)
#  ifdef BSWAP4
            ctx->Yi.d[3] = BSWAP4(ctr);
#  else
            PUTU32(ctx->Yi.c + 12, ctr);
#  endif
        else
            ctx->Yi.d[3] = ctr;
        GHASH(ctx, out, GHASH_CHUNK);
        out += GHASH_CHUNK;
        in += GHASH_CHUNK;
        len -= GHASH_CHUNK;
    }
# endif
*/
    /*
    if ((i = (len & (size_t)-16))) {
        size_t j = i / 16;

        (*stream) (in, out, j, key, ctx->Yi.c);
        ctr += (unsigned int)j;
        if (is_endian.little)
# ifdef BSWAP4
            ctx->Yi.d[3] = BSWAP4(ctr);
# else
            PUTU32(ctx->Yi.c + 12, ctr);
# endif
        else
            ctx->Yi.d[3] = ctr;
        in += i;
        len -= i;
# if defined(GHASH)
        GHASH(ctx, out, i);
        out += i;
# else
        while (j--) {
            for (i = 0; i < 16; ++i)
                ctx->Xi.c[i] ^= out[i];
            GCM_MUL(ctx, Xi);
            out += 16;
        }
# endif
    }
    */
    if ((i = (len & (size_t)-16))) {
        size_t j = len / 16;

        for(int k = 0; k < j; k++){
            (*ctx->block) (ctx->Yi.c, ctx->EKi.c, key);
            ++ctr;
            // print_keystream(ctx->EKi.c, ctr - 1, 1);
            if (is_endian.little)
# ifdef BSWAP4
                ctx->Yi.d[3] = BSWAP4(ctr);
# else
            PUTU32(ctx->Yi.c + 12, ctr);
# endif
            else
                ctx->Yi.d[3] = ctr;

            for(int a = 0; a < 16; a++){
                ctx->Xi.c[a] ^= out[a] = in[a] ^ ctx->EKi.c[a];
            } 
            GCM_MUL(ctx, Xi);
            len -= 16;
            out += 16;
            in += 16;
        }

        }
    if (len) {
        (*ctx->block) (ctx->Yi.c, ctx->EKi.c, key);
        ++ctr;
        if (is_endian.little)
# ifdef BSWAP4
            ctx->Yi.d[3] = BSWAP4(ctr);
# else
        PUTU32(ctx->Yi.c + 12, ctr);
# endif
        else
            ctx->Yi.d[3] = ctr;
        while (len--) {
            ctx->Xi.c[n] ^= out[n] = in[n] ^ ctx->EKi.c[n];
            ++n;
        }
    }
    ctx->mres = n;
    return 0;
#endif
}
#endif

int CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx,
                                const unsigned char *in, unsigned char *out,
                                size_t len, ctr128_f stream)
{
    // fprintf(stdout, "CRYPTO_gcm128_encrypt_ctr32\n\n");
#if defined(OPENSSL_SMALL_FOOTPRINT)
    return CRYPTO_gcm128_encrypt(ctx, in, out, len);
#else
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int n, ctr;
    size_t i;
    u64 mlen = ctx->len.u[1];
    void *key = ctx->key;
# ifdef GCM_FUNCREF_4BIT
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
#  ifdef GHASH
    void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx->ghash;
#  endif
# endif

    mlen += len;
    if (mlen > ((U64(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    if (ctx->ares) {
        /* First call to encrypt finalizes GHASH(AAD) */
        GCM_MUL(ctx, Xi);
        ctx->ares = 0;
    }

    if (is_endian.little)
# ifdef BSWAP4
        ctr = BSWAP4(ctx->Yi.d[3]);
# else
        ctr = GETU32(ctx->Yi.c + 12);
# endif
    else
        ctr = ctx->Yi.d[3];

    n = ctx->mres;
    if (n) {
        while (n && len) {
            ctx->Xi.c[n] ^= *(out++) = *(in++) ^ ctx->EKi.c[n];
            --len;
            n = (n + 1) % 16;
        }
        if (n == 0)
            GCM_MUL(ctx, Xi);
        else {
            ctx->mres = n;
            return 0;
        }
    }
# if defined(GHASH) && defined(GHASH_CHUNK)
    while (len >= GHASH_CHUNK) {
        /*
        fprintf(stderr,"Plain Text\n");
        print_keystream(stderr, in, 0, GHASH_CHUNK/16);
        */

        (*stream) (in, out, GHASH_CHUNK / 16, key, ctx->Yi.c);
        ctr += GHASH_CHUNK / 16;
        if (is_endian.little)
#  ifdef BSWAP4
            ctx->Yi.d[3] = BSWAP4(ctr);
#  else
            PUTU32(ctx->Yi.c + 12, ctr);
#  endif
        else
            ctx->Yi.d[3] = ctr;
        /*
        fprintf(stderr,"Cipher Text\n");
        print_keystream(stderr, out, 0, GHASH_CHUNK/16);
        fprintf(stderr, "\n");
        */

        GHASH(ctx, out, GHASH_CHUNK);
        out += GHASH_CHUNK;
        in += GHASH_CHUNK;
        len -= GHASH_CHUNK;
    }
# endif
    if ((i = (len & (size_t)-16))) {
        size_t j = i / 16;

        (*stream) (in, out, j, key, ctx->Yi.c);
        ctr += (unsigned int)j;
        if (is_endian.little)
# ifdef BSWAP4
            ctx->Yi.d[3] = BSWAP4(ctr);
# else
            PUTU32(ctx->Yi.c + 12, ctr);
# endif
        else
            ctx->Yi.d[3] = ctr;
        in += i;
        len -= i;
# if defined(GHASH)
        GHASH(ctx, out, i);
        out += i;
# else
        while (j--) {
            for (i = 0; i < 16; ++i)
                ctx->Xi.c[i] ^= out[i];
            GCM_MUL(ctx, Xi);
            out += 16;
        }
# endif
    }
    if (len) {
        (*ctx->block) (ctx->Yi.c, ctx->EKi.c, key);
        ++ctr;
        if (is_endian.little)
# ifdef BSWAP4
            ctx->Yi.d[3] = BSWAP4(ctr);
# else
            PUTU32(ctx->Yi.c + 12, ctr);
# endif
        else
            ctx->Yi.d[3] = ctr;
        /*
        fprintf(stdout,"Plain Text\n");
        print_keystream(stdout, in, 0, 1);

        fprintf(stdout,"Key Stream\n");
        print_keystream(stdout, ctx->EKi.c, 0, 1);
        */
        while (len--) {
            ctx->Xi.c[n] ^= out[n] = in[n] ^ ctx->EKi.c[n];
            ++n;
        }
        /*
        fprintf(stdout,"Cipher Text\n");
        print_keystream(stdout, out, 0, 1);
        fprintf(stdout, "\n");
        */
    }

    ctx->mres = n;
    return 0;
#endif
}



int jinho_CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx,
                                const unsigned char *in, unsigned char *out,
                                size_t len, ctr128_f stream)
{
    // fprintf(stdout, "Length: %d\n", len);
#if defined(OPENSSL_SMALL_FOOTPRINT)
    return jinho_CRYPTO_gcm128_encrypt(ctx, in, out, len);
#else
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int ctr;
    void *key = ctx->key;
    int i, j, res = 16;

# ifdef GCM_FUNCREF_4BIT
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
#  ifdef GHASH
    void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx->ghash;
#  endif
# endif

    if (is_endian.little)
# ifdef BSWAP4
        ctr = BSWAP4(ctx->Yi.d[3]);
# else
        ctr = GETU32(ctx->Yi.c + 12);
# endif
    else
        ctr = ctx->Yi.d[3];

    // fprintf(stdout, "Before stream function: %d\n", strlen(out));
    if (len >= 16) {
        // ADD JINHO FOR STREAM
# if defined(GHASH) && defined(GHASH_CHUNK)
        (*stream) (in, out, 16, key, ctx->Yi.c);
        ctr += 16;
        if (is_endian.little)
#  ifdef BSWAP4
        ctx->Yi.d[3] = BSWAP4(ctr);
#  else
        PUTU32(ctx->Yi.c + 12, ctr);
#  endif
        else
        ctx->Yi.d[3] = ctr;
# endif
    } else {
        res = len % 16;
        (*stream) (in, out, res, key, ctx->Yi.c);
        ctr += res;
        if (is_endian.little)
#  ifdef BSWAP4
        ctx->Yi.d[3] = BSWAP4(ctr);
#  else
        PUTU32(ctx->Yi.c + 12, ctr);
#  endif
        else
        ctx->Yi.d[3] = ctr;
    }
    // fprintf(stdout, "After stream function: %d\n", strlen(out));
    // fprintf(stdout, "Return: %d\n\n", res);
/*
    if ((i = (len & (size_t)-16))) {
        size_t j = i / 16;

        (*stream) (in, out, j, key, ctx->Yi.c);
        ctr += (unsigned int)j;
        if (is_endian.little)
# ifdef BSWAP4
        ctx->Yi.d[3] = BSWAP4(ctr);
# else
        PUTU32(ctx->Yi.c + 12, ctr);
# endif
        else
        ctx->Yi.d[3] = ctr;
        in += i;
        len -= i;
# if defined(GHASH)
        GHASH(ctx, out, i);
        out += i;
# else
        while (j--) {
            for (i = 0; i < 16; ++i)
                ctx->Xi.c[i] ^= out[i];
            GCM_MUL(ctx, Xi);
            out += 16;
        }
# endif
    }
    */
    /*

    if (len) {
        (*ctx->block) (ctx->Yi.c, out, key);
        ++ctr;
        if (is_endian.little)
# ifdef BSWAP4
        ctx->Yi.d[3] = BSWAP4(ctr);
# else
        PUTU32(ctx->Yi.c + 12, ctr);
# endif
        else
        ctx->Yi.d[3] = ctr;
    }
    */

    return res;
#endif
}

int borim_CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx,
                                const unsigned char *in, unsigned char *out,
                                size_t len, ctr128_f stream, void *keystruct)
{
    // fprintf(stdout, "borim_CRYPTO_gcm128_encrypt_ctr32\n\n");
#if defined(OPENSSL_SMALL_FOOTPRINT)
    return borim_CRYPTO_gcm128_encrypt(ctx, in, out, len, keystruct);
#else
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int n, ctr, cnt;
    size_t i;
    u64 mlen = ctx->len.u[1];
    void *key = ctx->key;
# ifdef GCM_FUNCREF_4BIT
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
#  ifdef GHASH
    void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx->ghash;
#  endif
# endif

    mlen += len;
    if (mlen > ((U64(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    if (ctx->ares) {
        /* First call to encrypt finalizes GHASH(AAD) */
        GCM_MUL(ctx, Xi);
        ctx->ares = 0;
    }

    n = ctx->mres;
    if (n) {
        while (n && len) {
            ctx->Xi.c[n] ^= *(out++) = *(in++) ^ ctx->EKi.c[n];
            --len;
            n = (n + 1) % 16;
        }
        if (n == 0)
            GCM_MUL(ctx, Xi);
        else {
            ctx->mres = n;
            return 0;
        }
    }
    /*
# if defined(GHASH) && defined(GHASH_CHUNK)
    while (len >= GHASH_CHUNK) {
	    (*stream) (in, out, GHASH_CHUNK / 16, key, ctx->Yi.c);
	    ctr += GHASH_CHUNK / 16;
	    if (is_endian.little)
#  ifdef BSWAP4
		    ctx->Yi.d[3] = BSWAP4(ctr);
#  else
	    PUTU32(ctx->Yi.c + 12, ctr);
#  endif
	    else
		    ctx->Yi.d[3] = ctr;
	    GHASH(ctx, out, GHASH_CHUNK);
	    out += GHASH_CHUNK;
	    in += GHASH_CHUNK;
	    len -= GHASH_CHUNK;
    }
# endif
*/
    int block_cnt = 0;
    while (len >= 16) {
        size_t cnt = len / 16;
        
        block_cnt = borim_processKeystream(keystruct, generated_keystreams, cnt);
        if (block_cnt == -1) 
            return -1;
        /*
        fprintf(stdout,"Plain Text\n");
        print_keystream(stdout, in, 0, block_cnt);

        fprintf(stdout,"Key Stream\n");
        print_keystream(stdout, generated_keystreams, 0, block_cnt);
        */

        (*stream) (in, out, block_cnt, generated_keystreams, NULL);
        /*
        fprintf(stdout,"Cipher Text\n");
        print_keystream(stdout, out, 0, block_cnt);
        fprintf(stdout, "\n");
        */

        GHASH(ctx, out, block_cnt * 16);
        out += block_cnt * 16;
        in += block_cnt * 16;
	    len -= block_cnt * 16;
    }
    /*
    if ((i = (len & (size_t)-16))) {
        fprintf(stderr, "In 16 LEN: %d\n", len);
        size_t j = i / 16;
        int block_cnt = 0;
        block_cnt = borim_processKeystream(keystruct, generated_keystreams, j);
        fprintf(stderr, "[16 Block] Block cnt: %d\n", block_cnt);
        if (block_cnt == -1)
            return -1;
        (*stream) (in, out, j, generated_keystreams, NULL);
        GHASH(ctx, out, i);
        out += block_cnt * 16;
        in += block_cnt * 16;
        len -= block_cnt * 16;

    }
    */
    if (len) {
        block_cnt = borim_processKeystream(keystruct, ctx->EKi.c, 1);
        if (block_cnt == -1)
            return -1;

        /*
        fprintf(stdout,"Plain Text\n");
        print_keystream(stdout, in, 0, 1);

        fprintf(stdout,"Key Stream\n");
        print_keystream(stdout, ctx->EKi.c, 0, 1);
        */
        while (len--) {
            ctx->Xi.c[n] ^= out[n] = in[n] ^ ctx->EKi.c[n];
            ++n;
        }

        /*
        fprintf(stdout,"Cipher Text\n");
        print_keystream(stdout, out, 0, 1);
        fprintf(stdout, "\n");
        */
    }


#if 0

    if ((i = (len & (size_t)-16))) {
        size_t j = i / 16;

        // org: Stream function 
        
        for(int k = 0; k < j; k++) {
            borim_processKeystream(keystruct, ctx);
            for(int a = 0; a < 16; a++) 
                ctx->Xi.c[a] ^= out[a] = in[a] ^ ctx->EKi.c[a];
            in += 16;
            len -= 16;
            GCM_MUL(ctx, Xi);
            out +=16;
        }
    }
    if (len) {
        borim_processKeystream(keystruct, ctx);

        while (len--) {
            ctx->Xi.c[n] ^= out[n] = in[n] ^ ctx->EKi.c[n];
            ++n;
        }
    }
#endif

    ctx->mres = n;
    return 0;
#endif
}

#if 0
int CRYPTO_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx,
                                const unsigned char *in, unsigned char *out,
                                size_t len, ctr128_f stream)
{
#if defined(OPENSSL_SMALL_FOOTPRINT)
    return CRYPTO_gcm128_decrypt(ctx, in, out, len);
#else
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int n, ctr;
    size_t i;
    u64 mlen = ctx->len.u[1];
    void *key = ctx->key;
# ifdef GCM_FUNCREF_4BIT
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
#  ifdef GHASH
    void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx->ghash;
#  endif
# endif

    mlen += len;
    if (mlen > ((U64(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    if (ctx->ares) {
        /* First call to decrypt finalizes GHASH(AAD) */
        GCM_MUL(ctx, Xi);
        ctx->ares = 0;
    }

    if (is_endian.little)
# ifdef BSWAP4
        ctr = BSWAP4(ctx->Yi.d[3]);
# else
        ctr = GETU32(ctx->Yi.c + 12);
# endif
    else
        ctr = ctx->Yi.d[3];

    n = ctx->mres;
    if (n) {
        while (n && len) {
            u8 c = *(in++);
            *(out++) = c ^ ctx->EKi.c[n];
            ctx->Xi.c[n] ^= c;
            --len;
            n = (n + 1) % 16;
        }
        if (n == 0)
            GCM_MUL(ctx, Xi);
        else {
            ctx->mres = n;
            return 0;
        }
    }
    /*
# if defined(GHASH) && defined(GHASH_CHUNK)
    while (len >= GHASH_CHUNK) {
        GHASH(ctx, in, GHASH_CHUNK);
        (*stream) (in, out, GHASH_CHUNK / 16, key, ctx->Yi.c);
        ctr += GHASH_CHUNK / 16;
        if (is_endian.little)
#  ifdef BSWAP4
            ctx->Yi.d[3] = BSWAP4(ctr);
#  else
            PUTU32(ctx->Yi.c + 12, ctr);
#  endif
        else
            ctx->Yi.d[3] = ctr;
        out += GHASH_CHUNK;
        in += GHASH_CHUNK;
        len -= GHASH_CHUNK;
    }
# endif
*/
    /*
    if ((i = (len & (size_t)-16))) {
        size_t j = i / 16;

# if defined(GHASH)
        GHASH(ctx, in, i);
# else
        while (j--) {
            size_t k;
            for (k = 0; k < 16; ++k)
                ctx->Xi.c[k] ^= in[k];
            GCM_MUL(ctx, Xi);
            in += 16;
        }
        j = i / 16;
        in -= i;
# endif
        (*stream) (in, out, j, key, ctx->Yi.c);
        ctr += (unsigned int)j;
        if (is_endian.little)
# ifdef BSWAP4
            ctx->Yi.d[3] = BSWAP4(ctr);
# else
            PUTU32(ctx->Yi.c + 12, ctr);
# endif
        else
            ctx->Yi.d[3] = ctr;
        out += i;
        in += i;
        len -= i;
    }
    */
    if ((i = (len & (size_t)-16))) {
        size_t j = len / 16;

        for(int k = 0; k < j; k++){
            (*ctx->block) (ctx->Yi.c, ctx->EKi.c, key);
            ++ctr;
            if (is_endian.little)
# ifdef BSWAP4
                ctx->Yi.d[3] = BSWAP4(ctr);
# else
            PUTU32(ctx->Yi.c + 12, ctr);
# endif
            else
                ctx->Yi.d[3] = ctr;

            for(int a = 0; a < 16; a++){
                u8 c = in[a];
                ctx->Xi.c[a] ^= c;
                out[a] = c ^ ctx->EKi.c[a];

            } 
            GCM_MUL(ctx, Xi);
            len -= 16;
            out += 16;
            in += 16;
        }

        }
    if (len) {
        (*ctx->block) (ctx->Yi.c, ctx->EKi.c, key);
        ++ctr;
        if (is_endian.little)
# ifdef BSWAP4
            ctx->Yi.d[3] = BSWAP4(ctr);
# else
            PUTU32(ctx->Yi.c + 12, ctr);
# endif
        else
            ctx->Yi.d[3] = ctr;
        while (len--) {

            
            ++n;
        }
    }

    ctx->mres = n;
    return 0;
#endif
}
#endif

int CRYPTO_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx,
                                const unsigned char *in, unsigned char *out,
                                size_t len, ctr128_f stream)
{
#if defined(OPENSSL_SMALL_FOOTPRINT)
    return CRYPTO_gcm128_decrypt(ctx, in, out, len);
#else
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    unsigned int n, ctr;
    size_t i;
    u64 mlen = ctx->len.u[1];
    void *key = ctx->key;
# ifdef GCM_FUNCREF_4BIT
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
#  ifdef GHASH
    void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx->ghash;
#  endif
# endif

    mlen += len;
    if (mlen > ((U64(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    if (ctx->ares) {
        /* First call to decrypt finalizes GHASH(AAD) */
        GCM_MUL(ctx, Xi);
        ctx->ares = 0;
    }

    if (is_endian.little)
# ifdef BSWAP4
        ctr = BSWAP4(ctx->Yi.d[3]);
# else
        ctr = GETU32(ctx->Yi.c + 12);
# endif
    else
        ctr = ctx->Yi.d[3];

    n = ctx->mres;
    if (n) {
        while (n && len) {
            u8 c = *(in++);
            *(out++) = c ^ ctx->EKi.c[n];
            ctx->Xi.c[n] ^= c;
            --len;
            n = (n + 1) % 16;
        }
        if (n == 0)
            GCM_MUL(ctx, Xi);
        else {
            ctx->mres = n;
            return 0;
        }
    }
# if defined(GHASH) && defined(GHASH_CHUNK)
    while (len >= GHASH_CHUNK) {
        GHASH(ctx, in, GHASH_CHUNK);
        (*stream) (in, out, GHASH_CHUNK / 16, key, ctx->Yi.c);
        ctr += GHASH_CHUNK / 16;
        if (is_endian.little)
#  ifdef BSWAP4
            ctx->Yi.d[3] = BSWAP4(ctr);
#  else
            PUTU32(ctx->Yi.c + 12, ctr);
#  endif
        else
            ctx->Yi.d[3] = ctr;
        out += GHASH_CHUNK;
        in += GHASH_CHUNK;
        len -= GHASH_CHUNK;
    }
# endif
    if ((i = (len & (size_t)-16))) {
        size_t j = i / 16;

# if defined(GHASH)
        GHASH(ctx, in, i);
# else
        while (j--) {
            size_t k;
            for (k = 0; k < 16; ++k)
                ctx->Xi.c[k] ^= in[k];
            GCM_MUL(ctx, Xi);
            in += 16;
        }
        j = i / 16;
        in -= i;
# endif
        (*stream) (in, out, j, key, ctx->Yi.c);
        ctr += (unsigned int)j;
        if (is_endian.little)
# ifdef BSWAP4
            ctx->Yi.d[3] = BSWAP4(ctr);
# else
            PUTU32(ctx->Yi.c + 12, ctr);
# endif
        else
            ctx->Yi.d[3] = ctr;
        out += i;
        in += i;
        len -= i;
    }
    if (len) {
        (*ctx->block) (ctx->Yi.c, ctx->EKi.c, key);
        ++ctr;
        if (is_endian.little)
# ifdef BSWAP4
            ctx->Yi.d[3] = BSWAP4(ctr);
# else
            PUTU32(ctx->Yi.c + 12, ctr);
# endif
        else
            ctx->Yi.d[3] = ctr;
        while (len--) {
            u8 c = in[n];
            ctx->Xi.c[n] ^= c;
            out[n] = c ^ ctx->EKi.c[n];
            ++n;
        }
    }

    ctx->mres = n;
    return 0;
#endif
}

int CRYPTO_gcm128_finish(GCM128_CONTEXT *ctx, const unsigned char *tag,
                         size_t len)
{
    const union {
        long one;
        char little;
    } is_endian = { 1 };
    u64 alen = ctx->len.u[0] << 3;
    u64 clen = ctx->len.u[1] << 3;
#ifdef GCM_FUNCREF_4BIT
    void (*gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx->gmult;
#endif

    if (ctx->mres || ctx->ares)
        GCM_MUL(ctx, Xi);

    if (is_endian.little) {
#ifdef BSWAP8
        alen = BSWAP8(alen);
        clen = BSWAP8(clen);
#else
        u8 *p = ctx->len.c;

        ctx->len.u[0] = alen;
        ctx->len.u[1] = clen;

        alen = (u64)GETU32(p) << 32 | GETU32(p + 4);
        clen = (u64)GETU32(p + 8) << 32 | GETU32(p + 12);
#endif
    }

    ctx->Xi.u[0] ^= alen;
    ctx->Xi.u[1] ^= clen;
    GCM_MUL(ctx, Xi);

    ctx->Xi.u[0] ^= ctx->EK0.u[0];
    ctx->Xi.u[1] ^= ctx->EK0.u[1];

    if (tag && len <= sizeof(ctx->Xi))
        return CRYPTO_memcmp(ctx->Xi.c, tag, len);
    else
        return -1;
}

void CRYPTO_gcm128_tag(GCM128_CONTEXT *ctx, unsigned char *tag, size_t len)
{
    CRYPTO_gcm128_finish(ctx, NULL, 0);
    memcpy(tag, ctx->Xi.c,
           len <= sizeof(ctx->Xi.c) ? len : sizeof(ctx->Xi.c));
}

GCM128_CONTEXT *CRYPTO_gcm128_new(void *key, block128_f block)
{
    GCM128_CONTEXT *ret;

    if ((ret = OPENSSL_malloc(sizeof(*ret))) != NULL)
        CRYPTO_gcm128_init(ret, key, block);

    return ret;
}

void CRYPTO_gcm128_release(GCM128_CONTEXT *ctx)
{
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

#if defined(SELFTEST)
# include <stdio.h>
# include <openssl/aes.h>

/* Test Case 1 */
static const u8 K1[16], *P1 = NULL, *A1 = NULL, IV1[12], *C1 = NULL;
static const u8 T1[] = {
    0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
    0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a
};

/* Test Case 2 */
# define K2 K1
# define A2 A1
# define IV2 IV1
static const u8 P2[16];
static const u8 C2[] = {
    0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
    0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
};

static const u8 T2[] = {
    0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
    0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
};

/* Test Case 3 */
# define A3 A2
static const u8 K3[] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};

static const u8 P3[] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55
};

static const u8 IV3[] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xde, 0xca, 0xf8, 0x88
};

static const u8 C3[] = {
    0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
    0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
    0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
    0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
    0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
    0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
    0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
    0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85
};

static const u8 T3[] = {
    0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd, 0x64, 0xa6,
    0x2c, 0xf3, 0x5a, 0xbd, 0x2b, 0xa6, 0xfa, 0xb4
};

/* Test Case 4 */
# define K4 K3
# define IV4 IV3
static const u8 P4[] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39
};

static const u8 A4[] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2
};

static const u8 C4[] = {
    0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
    0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
    0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
    0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
    0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
    0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
    0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
    0x3d, 0x58, 0xe0, 0x91
};

static const u8 T4[] = {
    0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
    0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47
};

/* Test Case 5 */
# define K5 K4
# define P5 P4
# define A5 A4
static const u8 IV5[] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad
};

static const u8 C5[] = {
    0x61, 0x35, 0x3b, 0x4c, 0x28, 0x06, 0x93, 0x4a,
    0x77, 0x7f, 0xf5, 0x1f, 0xa2, 0x2a, 0x47, 0x55,
    0x69, 0x9b, 0x2a, 0x71, 0x4f, 0xcd, 0xc6, 0xf8,
    0x37, 0x66, 0xe5, 0xf9, 0x7b, 0x6c, 0x74, 0x23,
    0x73, 0x80, 0x69, 0x00, 0xe4, 0x9f, 0x24, 0xb2,
    0x2b, 0x09, 0x75, 0x44, 0xd4, 0x89, 0x6b, 0x42,
    0x49, 0x89, 0xb5, 0xe1, 0xeb, 0xac, 0x0f, 0x07,
    0xc2, 0x3f, 0x45, 0x98
};

static const u8 T5[] = {
    0x36, 0x12, 0xd2, 0xe7, 0x9e, 0x3b, 0x07, 0x85,
    0x56, 0x1b, 0xe1, 0x4a, 0xac, 0xa2, 0xfc, 0xcb
};

/* Test Case 6 */
# define K6 K5
# define P6 P5
# define A6 A5
static const u8 IV6[] = {
    0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5,
    0x55, 0x90, 0x9c, 0x5a, 0xff, 0x52, 0x69, 0xaa,
    0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d, 0xa1,
    0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28,
    0xc3, 0xc0, 0xc9, 0x51, 0x56, 0x80, 0x95, 0x39,
    0xfc, 0xf0, 0xe2, 0x42, 0x9a, 0x6b, 0x52, 0x54,
    0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57,
    0xa6, 0x37, 0xb3, 0x9b
};

static const u8 C6[] = {
    0x8c, 0xe2, 0x49, 0x98, 0x62, 0x56, 0x15, 0xb6,
    0x03, 0xa0, 0x33, 0xac, 0xa1, 0x3f, 0xb8, 0x94,
    0xbe, 0x91, 0x12, 0xa5, 0xc3, 0xa2, 0x11, 0xa8,
    0xba, 0x26, 0x2a, 0x3c, 0xca, 0x7e, 0x2c, 0xa7,
    0x01, 0xe4, 0xa9, 0xa4, 0xfb, 0xa4, 0x3c, 0x90,
    0xcc, 0xdc, 0xb2, 0x81, 0xd4, 0x8c, 0x7c, 0x6f,
    0xd6, 0x28, 0x75, 0xd2, 0xac, 0xa4, 0x17, 0x03,
    0x4c, 0x34, 0xae, 0xe5
};

static const u8 T6[] = {
    0x61, 0x9c, 0xc5, 0xae, 0xff, 0xfe, 0x0b, 0xfa,
    0x46, 0x2a, 0xf4, 0x3c, 0x16, 0x99, 0xd0, 0x50
};

/* Test Case 7 */
static const u8 K7[24], *P7 = NULL, *A7 = NULL, IV7[12], *C7 = NULL;
static const u8 T7[] = {
    0xcd, 0x33, 0xb2, 0x8a, 0xc7, 0x73, 0xf7, 0x4b,
    0xa0, 0x0e, 0xd1, 0xf3, 0x12, 0x57, 0x24, 0x35
};

/* Test Case 8 */
# define K8 K7
# define IV8 IV7
# define A8 A7
static const u8 P8[16];
static const u8 C8[] = {
    0x98, 0xe7, 0x24, 0x7c, 0x07, 0xf0, 0xfe, 0x41,
    0x1c, 0x26, 0x7e, 0x43, 0x84, 0xb0, 0xf6, 0x00
};

static const u8 T8[] = {
    0x2f, 0xf5, 0x8d, 0x80, 0x03, 0x39, 0x27, 0xab,
    0x8e, 0xf4, 0xd4, 0x58, 0x75, 0x14, 0xf0, 0xfb
};

/* Test Case 9 */
# define A9 A8
static const u8 K9[] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c
};

static const u8 P9[] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55
};

static const u8 IV9[] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xde, 0xca, 0xf8, 0x88
};

static const u8 C9[] = {
    0x39, 0x80, 0xca, 0x0b, 0x3c, 0x00, 0xe8, 0x41,
    0xeb, 0x06, 0xfa, 0xc4, 0x87, 0x2a, 0x27, 0x57,
    0x85, 0x9e, 0x1c, 0xea, 0xa6, 0xef, 0xd9, 0x84,
    0x62, 0x85, 0x93, 0xb4, 0x0c, 0xa1, 0xe1, 0x9c,
    0x7d, 0x77, 0x3d, 0x00, 0xc1, 0x44, 0xc5, 0x25,
    0xac, 0x61, 0x9d, 0x18, 0xc8, 0x4a, 0x3f, 0x47,
    0x18, 0xe2, 0x44, 0x8b, 0x2f, 0xe3, 0x24, 0xd9,
    0xcc, 0xda, 0x27, 0x10, 0xac, 0xad, 0xe2, 0x56
};

static const u8 T9[] = {
    0x99, 0x24, 0xa7, 0xc8, 0x58, 0x73, 0x36, 0xbf,
    0xb1, 0x18, 0x02, 0x4d, 0xb8, 0x67, 0x4a, 0x14
};

/* Test Case 10 */
# define K10 K9
# define IV10 IV9
static const u8 P10[] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39
};

static const u8 A10[] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2
};

static const u8 C10[] = {
    0x39, 0x80, 0xca, 0x0b, 0x3c, 0x00, 0xe8, 0x41,
    0xeb, 0x06, 0xfa, 0xc4, 0x87, 0x2a, 0x27, 0x57,
    0x85, 0x9e, 0x1c, 0xea, 0xa6, 0xef, 0xd9, 0x84,
    0x62, 0x85, 0x93, 0xb4, 0x0c, 0xa1, 0xe1, 0x9c,
    0x7d, 0x77, 0x3d, 0x00, 0xc1, 0x44, 0xc5, 0x25,
    0xac, 0x61, 0x9d, 0x18, 0xc8, 0x4a, 0x3f, 0x47,
    0x18, 0xe2, 0x44, 0x8b, 0x2f, 0xe3, 0x24, 0xd9,
    0xcc, 0xda, 0x27, 0x10
};

static const u8 T10[] = {
    0x25, 0x19, 0x49, 0x8e, 0x80, 0xf1, 0x47, 0x8f,
    0x37, 0xba, 0x55, 0xbd, 0x6d, 0x27, 0x61, 0x8c
};

/* Test Case 11 */
# define K11 K10
# define P11 P10
# define A11 A10
static const u8 IV11[] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad };

static const u8 C11[] = {
    0x0f, 0x10, 0xf5, 0x99, 0xae, 0x14, 0xa1, 0x54,
    0xed, 0x24, 0xb3, 0x6e, 0x25, 0x32, 0x4d, 0xb8,
    0xc5, 0x66, 0x63, 0x2e, 0xf2, 0xbb, 0xb3, 0x4f,
    0x83, 0x47, 0x28, 0x0f, 0xc4, 0x50, 0x70, 0x57,
    0xfd, 0xdc, 0x29, 0xdf, 0x9a, 0x47, 0x1f, 0x75,
    0xc6, 0x65, 0x41, 0xd4, 0xd4, 0xda, 0xd1, 0xc9,
    0xe9, 0x3a, 0x19, 0xa5, 0x8e, 0x8b, 0x47, 0x3f,
    0xa0, 0xf0, 0x62, 0xf7
};

static const u8 T11[] = {
    0x65, 0xdc, 0xc5, 0x7f, 0xcf, 0x62, 0x3a, 0x24,
    0x09, 0x4f, 0xcc, 0xa4, 0x0d, 0x35, 0x33, 0xf8
};

/* Test Case 12 */
# define K12 K11
# define P12 P11
# define A12 A11
static const u8 IV12[] = {
    0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5,
    0x55, 0x90, 0x9c, 0x5a, 0xff, 0x52, 0x69, 0xaa,
    0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d, 0xa1,
    0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28,
    0xc3, 0xc0, 0xc9, 0x51, 0x56, 0x80, 0x95, 0x39,
    0xfc, 0xf0, 0xe2, 0x42, 0x9a, 0x6b, 0x52, 0x54,
    0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57,
    0xa6, 0x37, 0xb3, 0x9b
};

static const u8 C12[] = {
    0xd2, 0x7e, 0x88, 0x68, 0x1c, 0xe3, 0x24, 0x3c,
    0x48, 0x30, 0x16, 0x5a, 0x8f, 0xdc, 0xf9, 0xff,
    0x1d, 0xe9, 0xa1, 0xd8, 0xe6, 0xb4, 0x47, 0xef,
    0x6e, 0xf7, 0xb7, 0x98, 0x28, 0x66, 0x6e, 0x45,
    0x81, 0xe7, 0x90, 0x12, 0xaf, 0x34, 0xdd, 0xd9,
    0xe2, 0xf0, 0x37, 0x58, 0x9b, 0x29, 0x2d, 0xb3,
    0xe6, 0x7c, 0x03, 0x67, 0x45, 0xfa, 0x22, 0xe7,
    0xe9, 0xb7, 0x37, 0x3b
};

static const u8 T12[] = {
    0xdc, 0xf5, 0x66, 0xff, 0x29, 0x1c, 0x25, 0xbb,
    0xb8, 0x56, 0x8f, 0xc3, 0xd3, 0x76, 0xa6, 0xd9
};

/* Test Case 13 */
static const u8 K13[32], *P13 = NULL, *A13 = NULL, IV13[12], *C13 = NULL;
static const u8 T13[] = {
    0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
    0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b
};

/* Test Case 14 */
# define K14 K13
# define A14 A13
static const u8 P14[16], IV14[12];
static const u8 C14[] = {
    0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
    0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18
};

static const u8 T14[] = {
    0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
    0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19
};

/* Test Case 15 */
# define A15 A14
static const u8 K15[] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};

static const u8 P15[] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55
};

static const u8 IV15[] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xde, 0xca, 0xf8, 0x88
};

static const u8 C15[] = {
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
    0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
    0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
    0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
    0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
    0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
    0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
    0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad
};

static const u8 T15[] = {
    0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd,
    0xec, 0x1a, 0x50, 0x22, 0x70, 0xe3, 0xcc, 0x6c
};

/* Test Case 16 */
# define K16 K15
# define IV16 IV15
static const u8 P16[] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39
};

static const u8 A16[] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2
};

static const u8 C16[] = {
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
    0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
    0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
    0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
    0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
    0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
    0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
    0xbc, 0xc9, 0xf6, 0x62
};

static const u8 T16[] = {
    0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
    0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b
};

/* Test Case 17 */
# define K17 K16
# define P17 P16
# define A17 A16
static const u8 IV17[] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad };

static const u8 C17[] = {
    0xc3, 0x76, 0x2d, 0xf1, 0xca, 0x78, 0x7d, 0x32,
    0xae, 0x47, 0xc1, 0x3b, 0xf1, 0x98, 0x44, 0xcb,
    0xaf, 0x1a, 0xe1, 0x4d, 0x0b, 0x97, 0x6a, 0xfa,
    0xc5, 0x2f, 0xf7, 0xd7, 0x9b, 0xba, 0x9d, 0xe0,
    0xfe, 0xb5, 0x82, 0xd3, 0x39, 0x34, 0xa4, 0xf0,
    0x95, 0x4c, 0xc2, 0x36, 0x3b, 0xc7, 0x3f, 0x78,
    0x62, 0xac, 0x43, 0x0e, 0x64, 0xab, 0xe4, 0x99,
    0xf4, 0x7c, 0x9b, 0x1f
};

static const u8 T17[] = {
    0x3a, 0x33, 0x7d, 0xbf, 0x46, 0xa7, 0x92, 0xc4,
    0x5e, 0x45, 0x49, 0x13, 0xfe, 0x2e, 0xa8, 0xf2
};

/* Test Case 18 */
# define K18 K17
# define P18 P17
# define A18 A17
static const u8 IV18[] = {
    0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5,
    0x55, 0x90, 0x9c, 0x5a, 0xff, 0x52, 0x69, 0xaa,
    0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d, 0xa1,
    0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28,
    0xc3, 0xc0, 0xc9, 0x51, 0x56, 0x80, 0x95, 0x39,
    0xfc, 0xf0, 0xe2, 0x42, 0x9a, 0x6b, 0x52, 0x54,
    0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57,
    0xa6, 0x37, 0xb3, 0x9b
};

static const u8 C18[] = {
    0x5a, 0x8d, 0xef, 0x2f, 0x0c, 0x9e, 0x53, 0xf1,
    0xf7, 0x5d, 0x78, 0x53, 0x65, 0x9e, 0x2a, 0x20,
    0xee, 0xb2, 0xb2, 0x2a, 0xaf, 0xde, 0x64, 0x19,
    0xa0, 0x58, 0xab, 0x4f, 0x6f, 0x74, 0x6b, 0xf4,
    0x0f, 0xc0, 0xc3, 0xb7, 0x80, 0xf2, 0x44, 0x45,
    0x2d, 0xa3, 0xeb, 0xf1, 0xc5, 0xd8, 0x2c, 0xde,
    0xa2, 0x41, 0x89, 0x97, 0x20, 0x0e, 0xf8, 0x2e,
    0x44, 0xae, 0x7e, 0x3f
};

static const u8 T18[] = {
    0xa4, 0x4a, 0x82, 0x66, 0xee, 0x1c, 0x8e, 0xb0,
    0xc8, 0xb5, 0xd4, 0xcf, 0x5a, 0xe9, 0xf1, 0x9a
};

/* Test Case 19 */
# define K19 K1
# define P19 P1
# define IV19 IV1
# define C19 C1
static const u8 A19[] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
    0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
    0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
    0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
    0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
    0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
    0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
    0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad
};

static const u8 T19[] = {
    0x5f, 0xea, 0x79, 0x3a, 0x2d, 0x6f, 0x97, 0x4d,
    0x37, 0xe6, 0x8e, 0x0c, 0xb8, 0xff, 0x94, 0x92
};

/* Test Case 20 */
# define K20 K1
# define A20 A1
/* this results in 0xff in counter LSB */
static const u8 IV20[64] = { 0xff, 0xff, 0xff, 0xff };

static const u8 P20[288];
static const u8 C20[] = {
    0x56, 0xb3, 0x37, 0x3c, 0xa9, 0xef, 0x6e, 0x4a,
    0x2b, 0x64, 0xfe, 0x1e, 0x9a, 0x17, 0xb6, 0x14,
    0x25, 0xf1, 0x0d, 0x47, 0xa7, 0x5a, 0x5f, 0xce,
    0x13, 0xef, 0xc6, 0xbc, 0x78, 0x4a, 0xf2, 0x4f,
    0x41, 0x41, 0xbd, 0xd4, 0x8c, 0xf7, 0xc7, 0x70,
    0x88, 0x7a, 0xfd, 0x57, 0x3c, 0xca, 0x54, 0x18,
    0xa9, 0xae, 0xff, 0xcd, 0x7c, 0x5c, 0xed, 0xdf,
    0xc6, 0xa7, 0x83, 0x97, 0xb9, 0xa8, 0x5b, 0x49,
    0x9d, 0xa5, 0x58, 0x25, 0x72, 0x67, 0xca, 0xab,
    0x2a, 0xd0, 0xb2, 0x3c, 0xa4, 0x76, 0xa5, 0x3c,
    0xb1, 0x7f, 0xb4, 0x1c, 0x4b, 0x8b, 0x47, 0x5c,
    0xb4, 0xf3, 0xf7, 0x16, 0x50, 0x94, 0xc2, 0x29,
    0xc9, 0xe8, 0xc4, 0xdc, 0x0a, 0x2a, 0x5f, 0xf1,
    0x90, 0x3e, 0x50, 0x15, 0x11, 0x22, 0x13, 0x76,
    0xa1, 0xcd, 0xb8, 0x36, 0x4c, 0x50, 0x61, 0xa2,
    0x0c, 0xae, 0x74, 0xbc, 0x4a, 0xcd, 0x76, 0xce,
    0xb0, 0xab, 0xc9, 0xfd, 0x32, 0x17, 0xef, 0x9f,
    0x8c, 0x90, 0xbe, 0x40, 0x2d, 0xdf, 0x6d, 0x86,
    0x97, 0xf4, 0xf8, 0x80, 0xdf, 0xf1, 0x5b, 0xfb,
    0x7a, 0x6b, 0x28, 0x24, 0x1e, 0xc8, 0xfe, 0x18,
    0x3c, 0x2d, 0x59, 0xe3, 0xf9, 0xdf, 0xff, 0x65,
    0x3c, 0x71, 0x26, 0xf0, 0xac, 0xb9, 0xe6, 0x42,
    0x11, 0xf4, 0x2b, 0xae, 0x12, 0xaf, 0x46, 0x2b,
    0x10, 0x70, 0xbe, 0xf1, 0xab, 0x5e, 0x36, 0x06,
    0x87, 0x2c, 0xa1, 0x0d, 0xee, 0x15, 0xb3, 0x24,
    0x9b, 0x1a, 0x1b, 0x95, 0x8f, 0x23, 0x13, 0x4c,
    0x4b, 0xcc, 0xb7, 0xd0, 0x32, 0x00, 0xbc, 0xe4,
    0x20, 0xa2, 0xf8, 0xeb, 0x66, 0xdc, 0xf3, 0x64,
    0x4d, 0x14, 0x23, 0xc1, 0xb5, 0x69, 0x90, 0x03,
    0xc1, 0x3e, 0xce, 0xf4, 0xbf, 0x38, 0xa3, 0xb6,
    0x0e, 0xed, 0xc3, 0x40, 0x33, 0xba, 0xc1, 0x90,
    0x27, 0x83, 0xdc, 0x6d, 0x89, 0xe2, 0xe7, 0x74,
    0x18, 0x8a, 0x43, 0x9c, 0x7e, 0xbc, 0xc0, 0x67,
    0x2d, 0xbd, 0xa4, 0xdd, 0xcf, 0xb2, 0x79, 0x46,
    0x13, 0xb0, 0xbe, 0x41, 0x31, 0x5e, 0xf7, 0x78,
    0x70, 0x8a, 0x70, 0xee, 0x7d, 0x75, 0x16, 0x5c
};

static const u8 T20[] = {
    0x8b, 0x30, 0x7f, 0x6b, 0x33, 0x28, 0x6d, 0x0a,
    0xb0, 0x26, 0xa9, 0xed, 0x3f, 0xe1, 0xe8, 0x5f
};

# define TEST_CASE(n)    do {                                    \
        u8 out[sizeof(P##n)];                                   \
        AES_set_encrypt_key(K##n,sizeof(K##n)*8,&key);          \
        CRYPTO_gcm128_init(&ctx,&key,(block128_f)AES_encrypt);  \
        CRYPTO_gcm128_setiv(&ctx,IV##n,sizeof(IV##n));          \
        memset(out,0,sizeof(out));                              \
        if (A##n) CRYPTO_gcm128_aad(&ctx,A##n,sizeof(A##n));    \
        if (P##n) CRYPTO_gcm128_encrypt(&ctx,P##n,out,sizeof(out));     \
        if (CRYPTO_gcm128_finish(&ctx,T##n,16) ||               \
            (C##n && memcmp(out,C##n,sizeof(out))))             \
                ret++, printf ("encrypt test#%d failed.\n",n);  \
        CRYPTO_gcm128_setiv(&ctx,IV##n,sizeof(IV##n));          \
        memset(out,0,sizeof(out));                              \
        if (A##n) CRYPTO_gcm128_aad(&ctx,A##n,sizeof(A##n));    \
        if (C##n) CRYPTO_gcm128_decrypt(&ctx,C##n,out,sizeof(out));     \
        if (CRYPTO_gcm128_finish(&ctx,T##n,16) ||               \
            (P##n && memcmp(out,P##n,sizeof(out))))             \
                ret++, printf ("decrypt test#%d failed.\n",n);  \
        } while(0)

int main()
{
    GCM128_CONTEXT ctx;
    AES_KEY key;
    int ret = 0;

    TEST_CASE(1);
    TEST_CASE(2);
    TEST_CASE(3);
    TEST_CASE(4);
    TEST_CASE(5);
    TEST_CASE(6);
    TEST_CASE(7);
    TEST_CASE(8);
    TEST_CASE(9);
    TEST_CASE(10);
    TEST_CASE(11);
    TEST_CASE(12);
    TEST_CASE(13);
    TEST_CASE(14);
    TEST_CASE(15);
    TEST_CASE(16);
    TEST_CASE(17);
    TEST_CASE(18);
    TEST_CASE(19);
    TEST_CASE(20);

# ifdef OPENSSL_CPUID_OBJ
    {
        size_t start, stop, gcm_t, ctr_t, OPENSSL_rdtsc();
        union {
            u64 u;
            u8 c[1024];
        } buf;
        int i;

        AES_set_encrypt_key(K1, sizeof(K1) * 8, &key);
        CRYPTO_gcm128_init(&ctx, &key, (block128_f) AES_encrypt);
        CRYPTO_gcm128_setiv(&ctx, IV1, sizeof(IV1));

        CRYPTO_gcm128_encrypt(&ctx, buf.c, buf.c, sizeof(buf));
        start = OPENSSL_rdtsc();
        CRYPTO_gcm128_encrypt(&ctx, buf.c, buf.c, sizeof(buf));
        gcm_t = OPENSSL_rdtsc() - start;

        CRYPTO_ctr128_encrypt(buf.c, buf.c, sizeof(buf),
                              &key, ctx.Yi.c, ctx.EKi.c, &ctx.mres,
                              (block128_f) AES_encrypt);
        start = OPENSSL_rdtsc();
        CRYPTO_ctr128_encrypt(buf.c, buf.c, sizeof(buf),
                              &key, ctx.Yi.c, ctx.EKi.c, &ctx.mres,
                              (block128_f) AES_encrypt);
        ctr_t = OPENSSL_rdtsc() - start;

        printf("%.2f-%.2f=%.2f\n",
               gcm_t / (double)sizeof(buf),
               ctr_t / (double)sizeof(buf),
               (gcm_t - ctr_t) / (double)sizeof(buf));
#  ifdef GHASH
        {
            void (*gcm_ghash_p) (u64 Xi[2], const u128 Htable[16],
                                 const u8 *inp, size_t len) = ctx.ghash;

            GHASH((&ctx), buf.c, sizeof(buf));
            start = OPENSSL_rdtsc();
            for (i = 0; i < 100; ++i)
                GHASH((&ctx), buf.c, sizeof(buf));
            gcm_t = OPENSSL_rdtsc() - start;
            printf("%.2f\n", gcm_t / (double)sizeof(buf) / (double)i);
        }
#  endif
    }
# endif

    return ret;
}
#endif
