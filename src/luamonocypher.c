// Copyright (c) 2021 Phil Leblanc  -- License: MIT
// ---------------------------------------------------------------------
/*
luamonocypher - a Lua wrapping for the Monocypher library

*/
// ---------------------------------------------------------------------
// lua binding

#define LIBNAME luamonocypher
#define VERSION "luamonocypher-0.1"

#include <assert.h>
#include <string.h>	// memcpy()

#include "lua.h"
#include "lauxlib.h"

#include "monocypher.h"


// compatibility with Lua 5.2  --and lua 5.3, added 150621
// (from roberto's lpeg 0.10.1 dated 101203)
//
#if (LUA_VERSION_NUM >= 502)

#undef lua_equal
#define lua_equal(L,idx1,idx2)  lua_compare(L,(idx1),(idx2),LUA_OPEQ)

#undef lua_getfenv
#define lua_getfenv	lua_getuservalue
#undef lua_setfenv
#define lua_setfenv	lua_setuservalue

#undef lua_objlen
#define lua_objlen	lua_rawlen

#undef luaL_register
#define luaL_register(L,n,f) \
	{ if ((n) == NULL) luaL_setfuncs(L,f,0); else luaL_newlib(L,f); }

#endif


//----------------------------------------------------------------------
// lua binding   (all exposed functions are prefixed with "mc_")

# define LERR(msg) return luaL_error(L, msg)


//----------------------------------------------------------------------
// randombytes()

extern int randombytes(unsigned char *x,unsigned long long xlen); 

static int mc_randombytes(lua_State *L) {
	// Lua API:   randombytes(n)  returns a string with n random bytes 
	// n must be 256 or less.
	// randombytes return nil, error msg  if the RNG fails or if n > 256
	//	
    size_t bufln; 
	unsigned char buf[256];
	lua_Integer li = luaL_checkinteger(L, 1);  // 1st arg
	if ((li > 256 ) || (li < 0)) {
		lua_pushnil (L);
		lua_pushliteral(L, "invalid byte number");
		return 2;      		
	}
	int r = randombytes(buf, li);
	if (r != 0) { 
		lua_pushnil (L);
		lua_pushliteral(L, "random generator error");
		return 2;         
	} 	
    lua_pushlstring (L, buf, li); 
	return 1;
}//mc_randombytes()

//----------------------------------------------------------------------
// xchacha / poly1305 authenticated encryption


static int mc_encrypt(lua_State *L) {
	// Lua API: encrypt(k, n, m [, npf])
	//  k: key string (32 bytes)
	//  n: nonce string (24 bytes)
	//  m: message (plain text) string 
	//  npf: optional flag - if true, nonce is prepended to the 
	//       encrypted text. Default is false.
	//  return encrypted text string
	int r;
	size_t mln, nln, kln, pfxln, bufln;
	const char *k = luaL_checklstring(L,1,&kln);
	const char *n = luaL_checklstring(L,2,&nln);	
	const char *m = luaL_checklstring(L,3,&mln);	
	int npf = lua_toboolean(L,4);
	if (nln != 24) LERR("bad nonce size");
	if (kln != 32) LERR("bad key size");
	pfxln = npf ? 24 : 0;
	bufln = pfxln + 16 + mln;  // nonce-prefix | mac | encrypted msg
	unsigned char * buf = lua_newuserdata(L, bufln);
	// mac is prepended to the encr text buffer
	crypto_lock(buf+pfxln, buf+pfxln+16, k, n, m, mln);
	if (pfxln > 0) {
		memcpy(buf, n, pfxln); // copy the nonce if needed
	}
	lua_pushlstring (L, buf, bufln); 
	return 1;
} // lock()

static int mc_decrypt(lua_State *L) {
	// Lua API: decrypt(k, [n,] c)
	//  k: key string (32 bytes)
	//  n: optional nonce string (24 bytes)
	//	if the nonce is not present, ie 'decrypt(k, c)',
	//      it is assumed to be prepended to the encrypted string c
	//  c: encrypted message string 
	//  return plain text string 
	//      or (nil, error msg if MAC is not valid)
	int r = 0;
	size_t cln, nln, kln, boxln;
	const char *k = luaL_checklstring(L,1,&kln);
	const char *n = luaL_checklstring(L,2,&nln);	
	const char *c = luaL_optlstring(L,3, "",&cln);	
	if (cln == 0) {
		// n is the encrypted string with prepended nonce
		// so the encrypted string starts at n + 24
		c = n + 24;  
		cln = nln - 24;
		nln = 24;
	}
	if (nln != 24) LERR("bad nonce size");
	if (kln != 32) LERR("bad key size");
	if (cln < 16) LERR("bad msg size");

	unsigned char * buf = lua_newuserdata(L, cln);
	// so now, mac is at c, encrypted text is at c+16
	r = crypto_unlock(buf, k, n, c, c+16, cln-16);
	if (r != 0) { 
		lua_pushnil (L);
		lua_pushliteral(L, "decrypt error");
		return 2;         
	} 
	lua_pushlstring (L, buf, cln-16); 
	return 1;
} // mc_decrypt()


//----------------------------------------------------------------------
// blake2b hash and argon2i KDF

static int mc_blake2b(lua_State *L) {
	// compute the blake2b hash of a string
	// lua api:  blake2b(m, diglen, key) return digest
	// m: the string to be hashed
	// diglen: the optional length of the digest to be computed 
	//    (between 1 and 64) - default value is 64
	// key: an optional secret key, allowing blake2b to work as a MAC 
	//    (if provided, key length must be between 1 and 64)
	//    default is no key	
	// digest: the blake2b hash (a <diglen>-byte string)
	size_t mln; 
	size_t keyln = 0; 
	char digest[64];
	const char *m = luaL_checklstring (L, 1, &mln);
	int digln = luaL_optinteger(L, 2, 64);
	const char *key = luaL_optlstring(L, 3, NULL, &keyln);
	if ((keyln < 0)||(keyln > 64)) LERR("bad key size");
	if ((digln < 1)||(digln > 64)) LERR("bad digest size");
	crypto_blake2b_general(digest, digln, key, keyln, m, mln);
	lua_pushlstring (L, digest, digln); 
	return 1;
}// mc_blake2b

static int mc_argon2i(lua_State *L) {
	// Lua API: argon2i(pw, salt, nkb, niters) => k
	// pw: the password string
	// salt: some entropy as a string (typically 16 bytes)
	// nkb:  number of kilobytes used in RAM (as large as possible)
	// niters: number of iterations (as large as possible, >= 10)
	//  return k, a key string (32 bytes)
	size_t pwln, saltln, kln, mln;
	const char *pw = luaL_checklstring(L,1,&pwln);
	const char *salt = luaL_checklstring(L,2,&saltln);	
	int nkb = luaL_checkinteger(L,3);	
	int niters = luaL_checkinteger(L,4);	
	unsigned char k[32];
	size_t worksize = nkb * 1024;
	unsigned char *work= lua_newuserdata(L, worksize); 
	crypto_argon2i_general(	
		k, 32, work, nkb, niters,
		pw, pwln, salt, saltln, 
		"", 0, "", 0 	// optional key and additional data
	);
	lua_pushlstring (L, k, 32); 
	return 1;
} // mc_argon2i()


//----------------------------------------------------------------------
// key exchange (ec25519)

static int mc_x25519_public_key(lua_State *L) {
	// return the public key associated to a secret key
	// lua api:  x25519_public_key(sk) return pk
	// sk: a secret key (can be any 32-byte random value)
	// pk: the matching public key
	size_t skln;
	unsigned char pk[32];
	const char *sk = luaL_checklstring(L,1,&skln); // secret key
	if (skln != 32) LERR("bad sk size");
	crypto_x25519_public_key(pk, sk);
	lua_pushlstring (L, pk, 32); 
	return 1;
}//mc_x25519_public_key()

static int mc_key_exchange(lua_State *L) {
	// DH key exchange: compute a session key
	// lua api:  key_exchange(sk, pk) => k
	// !! beware, reversed order compared to nacl box_beforenm() !!
	// sk: "your" secret key
	// pk: "their" public key
	// return the session key k
	size_t pkln, skln;
	unsigned char k[32];
	const char *sk = luaL_checklstring(L,1,&skln); // your secret key
	const char *pk = luaL_checklstring(L,2,&pkln); // their public key
	if (pkln != 32) LERR("bad pk size");
	if (skln != 32) LERR("bad sk size");
	crypto_key_exchange(k, sk, pk);
	lua_pushlstring(L, k, 32); 
	return 1;   
}// mc_key_exchange()
 
//----------------------------------------------------------------------
// signature

static int mc_sign_public_key(lua_State *L) {
	// return the public key associated to an ed25519 secret key
	// lua api:  sign_public_key(sk) return pk
	// sk: a secret key (can be any 32-byte random string)
	// pk: the matching public key
	size_t skln;
	unsigned char pk[32];
	const char *sk = luaL_checklstring(L,1,&skln); // secret key
	if (skln != 32) LERR("bad sk size");
	crypto_sign_public_key(pk, sk);
	lua_pushlstring (L, pk, 32); 
	return 1;
}//mc_sign_public_key()

static int mc_sign(lua_State *L) {
	// sign a text with a secret key
	// Lua API: sign(sk, pk, m) return sig
	//  sk: key string (32 bytes)
	//  pk: associated public key string (32 bytes)
	//	m: message to sign (string)
	//  return signature (a 64-byte string)
	size_t mln, skln, pkln;
	const char *sk = luaL_checklstring(L,1,&skln);
	const char *pk = luaL_checklstring(L,2,&pkln);
	const char *m = luaL_checklstring(L,3,&mln);	
	if (skln != 32) LERR("bad key size");
	if (pkln != 32) LERR("bad pub key size");
	unsigned char sig[64];
	crypto_sign(sig, sk, pk, m, mln);
	lua_pushlstring (L, sig, 64); 
	return 1;
} // mc_sign()

static int mc_check(lua_State *L) {
	// check a text signature with a public key
	// Lua API: check(sig, pk, m) return boolean
	//  sig: signature string (64 bytes)
	//  pk: public key string (32 bytes)
	//	m: message to verify (string)
	//  return true if the signature match, or false
	int r;
	size_t mln, pkln, sigln;
	const char *sig = luaL_checklstring(L,1,&sigln);
	const char *pk = luaL_checklstring(L,2,&pkln);
	const char *m = luaL_checklstring(L,3,&mln);	
	if (sigln != 64) LERR("bad signature size");
	if (pkln != 32) LERR("bad key size");
	r = crypto_check(sig, pk, m, mln);
	// r == 0 if the signature matches
	lua_pushboolean (L, (r == 0)); 
	return 1;
} // mc_check()




//----------------------------------------------------------------------
// lua library declaration
//
static const struct luaL_Reg mclib[] = {
	{"randombytes", mc_randombytes},
	//
	{"encrypt", mc_encrypt},
	{"decrypt", mc_decrypt},
	//
	{"x25519_public_key", mc_x25519_public_key},
	{"public_key", mc_x25519_public_key},  // alias
	{"key_exchange", mc_key_exchange},
	//
	{"blake2b", mc_blake2b},
	{"argon2i", mc_argon2i},	
	//
	{"sign_public_key", mc_sign_public_key},	
	{"sign", mc_sign},	
	{"check", mc_check},	
	//
	{NULL, NULL},
};

//----------------------------------------------------------------------
// library registration

int luaopen_luamonocypher (lua_State *L) {
	luaL_register (L, "luamonocypher", mclib);
	lua_pushliteral (L, "VERSION");
	lua_pushliteral (L, VERSION); 
	lua_settable (L, -3);
	return 1;
}
