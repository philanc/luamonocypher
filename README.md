# LuaMonocypher

A Lua wrapper for the excellent Monocypher crypto library by Loup Vaillant -  https://monocypher.org/

The Monocypher library source is included here (currently version 3.1.2)

Monocypher implements:

* Authenticated encryption with Chacha20 (more precisely XChacha20, ie. Chacha with a 24-byte nonce) and Poly1305 MAC  (RFC 8439), 
* Blake2b hash function (RFC 7693), as secure as SHA-3, and as fast as MD5
* Curve25519-based Diffie-Hellman key exchange (RFC 7748),
* EdDSA signature (RFC 8032) based on the Ed25519 curve and using Blake2b hash instead of SHA512,
* SHA2-512 hash function
* Ed25519 signature using SHA512 hash (compatible with the original ed25519 signature functions in NaCl  by Dan Bernstein)
* Argon2i  (RFC 9106), a modern key derivation function based on Blake2b. Like scrypt, it is designed to be expensive in both CPU and memory.

The complete documentation of the Monocypher library is available at https://monocypher.org/manual/


## The Lua wrapper

It includes an interface to an OS random generator (it uses getrandom() or /dev/urandom on Linux, or CryptGenRandom on Windows)

LuaMonocypher API summary:

```
randombytes(n)
	return a string containing n random bytes


--- Authenticated encryption

encrypt(key, nonce, plain [, ninc]) => crypted
	authenticated encryption using Xchacha20 and a Poly1305 MAC
	key must be a 32-byte string
	nonce must be a 24-byte string
	plain is the text to encrypt as a string
	ninc: optional nonce increment (useful when encrypting a long text
	   as a sequence of block). The same parameter n can be used for 
	   the sequence. ninc is added to n for each block, so the actual
	   nonce used for each block encryption is distinct.
	   ninc defaults to 0 (the nonce n is used as-is)
	return the encrypted text as a string. The encrypted text includes 
	the 16-byte MAC. So  #crypted == #plain + 16
	
decrypt(key, nonce, crypted [, ninc]) => plain
	authenticated decryption - verification of the Poly1305 MAC
	and decryption with Xcahcha20.
	key must be a 32-byte string
	nonce must be a 24-byte string
	crypted is the text to decrypt as a string
	ninc: optional nonce increment (see above. defaults to 0)
	return the decrypted plain text as a string or nil if the MAC 
	verification fails.


--- Blake2b cryptographic hash

blake2b(text, [digest_size [, key]]) => digest
	digest_size is the optional length of the expected digest. 
	If provided, it must be an integer between 1 and 64. 
	It defaults to 64.
	key is an optional key allowing to use blake2b as a MAC function.
	If provided, key is a string with a length that must be between 
	1 and 64. The default is no key.
	The returned digest is a binary string. Default length is 64 bytes.


--- Argon2i password derivation 

argon2i(pw, salt, nkb, niter) => k
	compute a key given a password and some salt
	This is a password key derivation function similar to scrypt.
	It is intended to make derivation expensive in both CPU and memory.
	pw: the password string
	salt: some entropy as a string (typically 16 bytes)
	nkb:  number of kilobytes used in RAM (as large as possible)
	niter: number of iterations (as large as possible, >= 10)
	Return k, a key string (32 bytes).

	For example: on a i5-8250U CPU @ 1.60GHz laptop,
	with nkb=100000 (100MB) and niter=10, the derivation takes close
	to 1 sec.


--- Curve25519-based Diffie-Hellman key exchange

public_key(sk) => pk
	return the public key associated to a curve25519 secret key
	sk is the secret key as a 32-byte string
	pk is the associated public key as a 32-byte string

	To generate a curve25519 key pair (sk, pk), do:
		sk = randombytes(32)
		pk = public_key(sk)
	
key_exchange(sk, pk) => k
	DH key exchange. Return a session key k used to encrypt 
	or decrypt a text.
	sk is the secret key of the party invoking the function 
	("our secret key"). 
	pk is the public key of the other party 
	("their public key").
	sk, pk and k are 32-byte strings

x25519(s, P1) => P2
	// raw scalar multiplication over curve25519
	// Note: this function should usually not be used directly.
	// For DH key exchange, the key_exchange() function below 
	// should be used instead.
	// --
	// s: a scalar as a 32-byte string
	// P1: a point as a 32-byte string
	// return the product s.P1 as a 32-byte string
	// the bit distribution in P2 is not uniform, so P2 should
	// not be directly used as a shared key. 
	// Again, use key_exchange() instead.


--- EdDSA signature (RFC 8032). 

The signature functions are based on the Ed25519 curve and Blake2b hash.

sign_public_key(sk) => pk
	return the public key associated to a secret key
	sk is the secret key as a 32-byte string
	pk is the associated public key as a 32-byte string

	Note: curve25519 key pairs cannot be used for EdDSA signature. 
	To generate a signature key pair (sk, pk), do:
		sk = randombytes(32)
		pk = sign_public_key(sk)

sign(sk, text) => sig
	sign a text with a secret key
	sk is the secret key as a 32-byte string
	text is the text to sign as a string
	Return the text signature as a 64-byte string.

check(sig, pk, text) => is_valid
	check a text signature with a public key
	sig is the signature to verify, as a 64-byte string
	pk is the public key as a 32-byte string
	text is the signed text
	Return a boolean indicating if the signature is valid or not.
	
	
--- SHA512 and NaCl original Ed25519 signature based on SHA512

sha512(m) => digest
	return the sha512 hash of message m as a 64-byte binary string

ed25519_public_key(sk)
	return the public key associated to a secret key
	sk is the secret key as a 32-byte string
	pk is the associated public key as a 32-byte string

	Note: curve25519 keypairs or keys generated by sign_public_key() 
	cannot be used for the ed25519_* signature functions.
	To generate a signature key pair (sk, pk), do:
		sk = randombytes(32)
		pk = ed25519_public_key(sk)

ed25519_sign(sk, text) => sig
	sign a text with a secret key
	sk is the secret key as a 32-byte string
	text is the text to sign as a string
	Return the text signature as a 64-byte string.

ed25519_check(sig, pk, text) => is_valid
	check a text signature with a public key
	sig is the signature to verify, as a 64-byte string
	pk is the public key as a 32-byte string
	text is the signed text
	Return a boolean indicating if the signature is valid or not
	
Note: contrary to the sign() and sign_open() NaCl functions, the 
signature is not prepended to the text ("detached signature")


```

## Building 

Adjust the Makefile according to your Lua installation (set the LUADIR variable). 

Targets:
```
	make          -- build luamonocypher.so
	make test     -- build luamonocypher.so if needed, 
	                 then run test_luamonocypher.lua
	make clean
```

An alternative Lua installation can be specified:
```
	make LUA=/path/to/lua LUAINC=/path/to/lua_include_dir test
```


## License

The original Monocypher source code is dual-licensed (2-clause BSD or CC-0) - see src/monocypher-LICENSE.md

The LuaMonocypher wrapper library is MIT-licensed.



