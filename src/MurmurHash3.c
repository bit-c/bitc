#include <stdlib.h>

#include "basic_defs.h"
#include "MurmurHash3.h"


/*
 *-------------------------------------------------------------------------
 *
 * ROTL32 --
 *
 *-------------------------------------------------------------------------
 */

static inline uint32
ROTL32(uint32 x, int8 r)
{
  return (x << r) | (x >> (32 - r));
}


/*
 *-------------------------------------------------------------------------
 *
 * MurmurHash3 --
 *
 *      http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp
 *
 *-------------------------------------------------------------------------
 */

uint32
MurmurHash3(const void *key,
            size_t len,
            uint32 seed)
{
   const uint8 *data = (const uint8 *)key;
   uint32 h1 = seed;
   const uint32 c1 = 0xcc9e2d51;
   const uint32 c2 = 0x1b873593;
   const int nblocks = len / 4;
   const uint32 * blocks = (const uint32 *)(&data[0] + nblocks * 4);
   int i;

   for (i = -nblocks; i; i++) {
      uint32 k1 = blocks[i];

      k1 *= c1;
      k1 = ROTL32(k1,15);
      k1 *= c2;

      h1 ^= k1;
      h1 = ROTL32(h1,13);
      h1 = h1 * 5 + 0xe6546b64;
   }

   const uint8 * tail = (const uint8*)(&data[0] + nblocks * 4);
   uint32 k1 = 0;

   switch (len & 3) {
   case 3: k1 ^= tail[2] << 16;
   case 2: k1 ^= tail[1] << 8;
   case 1: k1 ^= tail[0];
           k1 *= c1;
           k1 = ROTL32(k1,15);
           k1 *= c2;
           h1 ^= k1;
   }

   h1 ^= len;
   h1 ^= h1 >> 16;
   h1 *= 0x85ebca6b;
   h1 ^= h1 >> 13;
   h1 *= 0xc2b2ae35;
   h1 ^= h1 >> 16;

   return h1;
}
