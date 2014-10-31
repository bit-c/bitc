#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>

#include "util.h"
#include "key.h"
#include "hash.h"

#define LGPFX "KEY:"


struct key {
   EC_KEY       *key;
   uint8        *pub_key;
   size_t        pub_len;
};



/*
 *------------------------------------------------------------------------
 *
 * key_get_privkey --
 *
 *------------------------------------------------------------------------
 */

bool
key_get_privkey(struct key *k,
                uint8     **priv,
                size_t     *len)
{
   ASSERT(priv);
   *priv = NULL;
   *len = 0;

   if (!EC_KEY_check_key(k->key)) {
      return 0;
   }

   const BIGNUM *bn = EC_KEY_get0_private_key(k->key);
   if (bn == NULL) {
      return 0;
   }
   *len = BN_num_bytes(bn) + 1;
   *priv = safe_malloc(*len);
   BN_bn2bin(bn, *priv);

   /*
    * Compressed key.
    */
   (*priv)[*len - 1] = 1;

   return 1;
}


/*
 *------------------------------------------------------------------------
 *
 * key_get_pubkey_int --
 *
 *------------------------------------------------------------------------
 */

static bool
key_get_pubkey_int(struct key *k,
                   uint8     **pub,
                   size_t    *len)
{
   uint8 *data;

   ASSERT(pub);
   *pub = NULL;
   *len = 0;

   if (!EC_KEY_check_key(k->key)) {
      NOT_TESTED();
      return 0;
   }

   *len = i2o_ECPublicKey(k->key, 0);
   ASSERT(*len <= 65);
   data = safe_malloc(*len);
   *pub = data;
   i2o_ECPublicKey(k->key, &data);

   return 1;
}


/*
 *------------------------------------------------------------------------
 *
 * key_get_pubkey --
 *
 *------------------------------------------------------------------------
 */

void
key_get_pubkey(struct key *k,
               uint8     **pub,
               size_t    *len)
{
   ASSERT(pub);
   *pub = safe_malloc(k->pub_len);
   *len = k->pub_len;

   memcpy(*pub, k->pub_key, *len);
}


/*
 *------------------------------------------------------------------------
 *
 * key_regenerate --
 *
 *------------------------------------------------------------------------
 */

static int
key_regenerate(struct key *k,
               const BIGNUM *bn)
{
   const EC_GROUP *grp;
   EC_KEY *key = k->key;
   EC_POINT *pub_key;
   BN_CTX *ctx;
   int res;

   ASSERT(key);

   grp = EC_KEY_get0_group(key);
   ctx = BN_CTX_new();

   ASSERT(grp);
   ASSERT(ctx);

   pub_key = EC_POINT_new(grp);
   ASSERT(pub_key);

   res = EC_POINT_mul(grp, pub_key, bn, NULL, NULL, ctx);
   ASSERT(res == 1);

   res = EC_KEY_set_private_key(key, bn);
   ASSERT(res == 1);

   res = EC_KEY_set_public_key(key, pub_key);
   ASSERT(res == 1);

   EC_POINT_free(pub_key);
   BN_CTX_free(ctx);

   return EC_KEY_check_key(k->key);
}


/*
 *------------------------------------------------------------------------
 *
 * key_free --
 *
 *------------------------------------------------------------------------
 */

void
key_free(struct key *k)
{
   if (k == NULL) {
      return;
   }
   free(k->pub_key);
   EC_KEY_free(k->key);
   free(k);
}


/*
 *------------------------------------------------------------------------
 *
 * key_generate_new --
 *
 *------------------------------------------------------------------------
 */

struct key *
key_generate_new(void)
{
   struct key *k;
   int s;

   k = key_alloc();

   s = EC_KEY_generate_key(k->key);
   if (s == 0) {
      Log(LGPFX" EC_KEY_generate_key failed.\n");
      goto exit;
   }
   s = EC_KEY_check_key(k->key);
   if (s == 0) {
      Log(LGPFX" EC_KEY_check_key failed.\n");
      goto exit;
   }

   EC_KEY_set_conv_form(k->key, POINT_CONVERSION_COMPRESSED);

   ASSERT(k->pub_key == NULL);
   ASSERT(k->pub_len == 0);
   key_get_pubkey_int(k, &k->pub_key, &k->pub_len);

   return k;
exit:
   key_free(k);
   return NULL;
}


/*
 *------------------------------------------------------------------------
 *
 * key_set_privkey --
 *
 *------------------------------------------------------------------------
 */

bool
key_set_privkey(struct key *k,
                const void *privkey,
                size_t len)
{
   BIGNUM *res;
   BIGNUM bn;
   int s;

   /*
    * Cf bitcoin/src/base58.h
    *    bitcoin/src/key.h
    *
    * If len == 33 and privkey[32] == 1, then:
    *   "the public key corresponding to this private key is (to be)
    *   compressed."
    */
   ASSERT(len == 32 || len == 33);

   BN_init(&bn);
   res = BN_bin2bn(privkey, 32, &bn);
   ASSERT(res);

   s = key_regenerate(k, &bn);
   ASSERT(s);
   ASSERT(EC_KEY_check_key(k->key));

   EC_KEY_set_conv_form(k->key, POINT_CONVERSION_COMPRESSED);

   ASSERT(k->pub_key == NULL);
   ASSERT(k->pub_len == 0);
   key_get_pubkey_int(k, &k->pub_key, &k->pub_len);

   BN_clear_free(&bn);
   ASSERT(EC_KEY_check_key(k->key));

   return 1;
}


/*
 *------------------------------------------------------------------------
 *
 * key_verify --
 *
 *------------------------------------------------------------------------
 */

bool
key_verify(struct key *k,
           const void *data,
           size_t      datalen,
           const void *sig,
           size_t      siglen)
{
   int res;

   res = ECDSA_verify(0, data, datalen, sig, siglen, k->key);

   return res == 1;
}


/*
 *------------------------------------------------------------------------
 *
 * key_sign --
 *
 *------------------------------------------------------------------------
 */

bool
key_sign(struct key *k,
         const void *data,
         size_t      datalen,
         uint8     **sig,
         size_t     *siglen)

{
   unsigned int len;
   uint8 *sig0;
   int res;

   ASSERT(sig);
   ASSERT(siglen);

   len = ECDSA_size(k->key);
   sig0 = safe_calloc(1, len);

   res = ECDSA_sign(0, data, datalen, sig0, &len, k->key);
   if (res != 1) {
      NOT_TESTED();
      free(sig0);
      return 0;
   }
   *sig = sig0;
   *siglen = len;

   return 1;
}


/*
 *------------------------------------------------------------------------
 *
 * key_alloc --
 *
 *------------------------------------------------------------------------
 */

struct key *
key_alloc(void)
{
   struct key *k;

   k = safe_malloc(sizeof *k);
   k->key = EC_KEY_new_by_curve_name(NID_secp256k1);
   k->pub_key = NULL;
   k->pub_len = 0;

   return k;
}


/*
 *------------------------------------------------------------------------
 *
 * key_get_pubkey_hash160 --
 *
 *------------------------------------------------------------------------
 */

void
key_get_pubkey_hash160(const struct key *k,
                       uint160          *hash)
{
   ASSERT(k->pub_key);
   ASSERT(k->pub_len > 0);

   Log_Bytes(LGPFX" pubkey: ", k->pub_key, k->pub_len);

   hash160_calc(k->pub_key, k->pub_len, hash);
}
