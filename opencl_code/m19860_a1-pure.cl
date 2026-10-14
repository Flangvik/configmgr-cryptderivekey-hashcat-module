/**
 * Author......: Christopher Panayi, MWR CyberSec (original AES-128 module)
 * AES-256.....: Flangvik / TrustedSec (adapted for CALG_AES_256)
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#endif

// Combinator attack variant: left password from pws, right password from combs_buf
// Computes both ipad and opad for AES-256 (32-byte key)
DECLSPEC void crypt_derive_key_aes256 (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS sha1_ctx_t *pwsorig, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  //Add right side password to left side password with a second call to sha1_update_global_utf16le_swap
  PRIVATE_AS sha1_ctx_t *tmp = pwsorig;

  sha1_update_global_utf16le_swap (tmp, w, len);

  sha1_final (tmp);

  w0[0] = tmp->h[0];
  w0[1] = tmp->h[1];
  w0[2] = tmp->h[2];
  w0[3] = tmp->h[3];
  w1[0] = tmp->h[4];
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];

  // ipad

  t0[0] = w0[0] ^ 0x36363636;
  t0[1] = w0[1] ^ 0x36363636;
  t0[2] = w0[2] ^ 0x36363636;
  t0[3] = w0[3] ^ 0x36363636;
  t1[0] = w1[0] ^ 0x36363636;
  t1[1] = w1[1] ^ 0x36363636;
  t1[2] = w1[2] ^ 0x36363636;
  t1[3] = w1[3] ^ 0x36363636;
  t2[0] = w2[0] ^ 0x36363636;
  t2[1] = w2[1] ^ 0x36363636;
  t2[2] = w2[2] ^ 0x36363636;
  t2[3] = w2[3] ^ 0x36363636;
  t3[0] = w3[0] ^ 0x36363636;
  t3[1] = w3[1] ^ 0x36363636;
  t3[2] = w3[2] ^ 0x36363636;
  t3[3] = w3[3] ^ 0x36363636;

  sha1_init (&ctx->ipad);

  sha1_update_64 (&ctx->ipad, t0, t1, t2, t3, 64);

  sha1_final (&ctx->ipad);

  // opad

  t0[0] = w0[0] ^ 0x5c5c5c5c;
  t0[1] = w0[1] ^ 0x5c5c5c5c;
  t0[2] = w0[2] ^ 0x5c5c5c5c;
  t0[3] = w0[3] ^ 0x5c5c5c5c;
  t1[0] = w1[0] ^ 0x5c5c5c5c;
  t1[1] = w1[1] ^ 0x5c5c5c5c;
  t1[2] = w1[2] ^ 0x5c5c5c5c;
  t1[3] = w1[3] ^ 0x5c5c5c5c;
  t2[0] = w2[0] ^ 0x5c5c5c5c;
  t2[1] = w2[1] ^ 0x5c5c5c5c;
  t2[2] = w2[2] ^ 0x5c5c5c5c;
  t2[3] = w2[3] ^ 0x5c5c5c5c;
  t3[0] = w3[0] ^ 0x5c5c5c5c;
  t3[1] = w3[1] ^ 0x5c5c5c5c;
  t3[2] = w3[2] ^ 0x5c5c5c5c;
  t3[3] = w3[3] ^ 0x5c5c5c5c;

  sha1_init (&ctx->opad);

  sha1_update_64 (&ctx->opad, t0, t1, t2, t3, 64);

  sha1_final (&ctx->opad);
}

KERNEL_FQ KERNEL_FA void m19860_mxx (KERN_ATTR_BASIC())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  //First call to sha1_update_global_utf16le_swap for the left hand side password (pws)
  sha1_ctx_t tmp;

  sha1_init (&tmp);

  sha1_update_global_utf16le_swap (&tmp, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha1_hmac_ctx_t sha1_hmac_ctx;
    sha1_ctx_t pwsorig = tmp; //Make a copy of the existing sha1_ctx_t object already calculated for pws, per loop iteration

    //Call to crypt_derive_key, with the right hand side password (combs_buf) passed as a parameter
    crypt_derive_key_aes256 (&sha1_hmac_ctx, &pwsorig, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    u32 aes_key[8];

    aes_key[0] = sha1_hmac_ctx.ipad.h[0];
    aes_key[1] = sha1_hmac_ctx.ipad.h[1];
    aes_key[2] = sha1_hmac_ctx.ipad.h[2];
    aes_key[3] = sha1_hmac_ctx.ipad.h[3];
    aes_key[4] = sha1_hmac_ctx.ipad.h[4];
    aes_key[5] = sha1_hmac_ctx.opad.h[0];
    aes_key[6] = sha1_hmac_ctx.opad.h[1];
    aes_key[7] = sha1_hmac_ctx.opad.h[2];

    u32 aes_ks[60];
    u32 encrypted_block[4];

    AES256_set_encrypt_key (aes_ks, aes_key, s_te0, s_te1, s_te2, s_te3);

    const u32 enc_blocks[4] = {1006649088U, 2013293824U, 1811947520U, 1979737344U}; // UTF-16LE "<?xml ve"

    AES256_encrypt (aes_ks, enc_blocks, encrypted_block, s_te0, s_te1, s_te2, s_te3, s_te4);

    const u32 r0 = encrypted_block[DGST_R0];
    const u32 r1 = encrypted_block[DGST_R1];
    const u32 r2 = encrypted_block[DGST_R2];
    const u32 r3 = encrypted_block[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m19860_sxx (KERN_ATTR_BASIC())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  sha1_ctx_t tmp;

  sha1_init (&tmp);

  sha1_update_global_utf16le_swap (&tmp, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha1_hmac_ctx_t sha1_hmac_ctx;
    sha1_ctx_t pwsorig = tmp;

    crypt_derive_key_aes256 (&sha1_hmac_ctx, &pwsorig, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    u32 aes_key[8];

    aes_key[0] = sha1_hmac_ctx.ipad.h[0];
    aes_key[1] = sha1_hmac_ctx.ipad.h[1];
    aes_key[2] = sha1_hmac_ctx.ipad.h[2];
    aes_key[3] = sha1_hmac_ctx.ipad.h[3];
    aes_key[4] = sha1_hmac_ctx.ipad.h[4];
    aes_key[5] = sha1_hmac_ctx.opad.h[0];
    aes_key[6] = sha1_hmac_ctx.opad.h[1];
    aes_key[7] = sha1_hmac_ctx.opad.h[2];

    u32 aes_ks[60];
    u32 encrypted_block[4];

    AES256_set_encrypt_key (aes_ks, aes_key, s_te0, s_te1, s_te2, s_te3);

    const u32 enc_blocks[4] = {1006649088U, 2013293824U, 1811947520U, 1979737344U}; // UTF-16LE "<?xml ve"

    AES256_encrypt (aes_ks, enc_blocks, encrypted_block, s_te0, s_te1, s_te2, s_te3, s_te4);

    const u32 r0 = encrypted_block[DGST_R0];
    const u32 r1 = encrypted_block[DGST_R1];
    const u32 r2 = encrypted_block[DGST_R2];
    const u32 r3 = encrypted_block[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
