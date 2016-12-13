/**
* lightmac.h
*
* @author Sebastian Mertz
*
* Basic Implementation for LightMAC
*
* This code is hereby placed in the public domain.
*
*THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
*AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
*WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
*IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
*INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
*NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
*PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
*WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
*ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
*OF SUCH DAMAGE.
*/

#ifndef LIGHTMAC_H
#define LIGHTMAC_H

//define which Block Cipher is used
#define MBEDTLS_AES 0
#define CUSTOM 0

#if !MBEDTLS_AES && !CUSTOM
#define RIJNDAEL 1
#endif

#include <string.h> //memcpy, memset

#define N 16 //block size in bytes
#define T 16 //tag size in bytes
#define S 8 //counter size in bytes, values 1 to N/2 are allowed for S

#define FORCE_VAR_CTR 0 //force use of memcpy and memset instead of optimized versions

#if CUSTOM
//put own cipher defines here
#elif RIJNDAEL //defines for usage of Rijndael reference implementation
#include "rijndael-alg-fst.h"

#define ENCRYPT(rk,pt,ct) rijndaelEncrypt(rk,10,pt,ct)
#define SETUP(rk,k) rijndaelKeySetupEnc(rk, k, 128)

typedef unsigned long long u64;
typedef u32 rk_type[44];
typedef u8 byte_type;
typedef u64 word_type;
#elif MBEDTLS_AES //defines for usage of mbedTLS implementation of AES
#include "aes.h" //change to mbedtls path

#define ENCRYPT(rk,pt,ct) mbedtls_aes_encrypt(rk,pt,ct)
#define SETUP(rk,k) {\
		mbedtls_aes_init(rk);\
		mbedtls_aes_setkey_enc(rk,k,128); }

typedef mbedtls_aes_context rk_type[1];
typedef uint8_t byte_type;
typedef uint64_t word_type;
#endif

//defines for handling of different message/counter lengths
#if S==8
#define MAXBLOCKS 0xFFFFFFFFFFFFFFFF //max message length for 64-Bit counter
static const byte_type const pad[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#elif S==7
#define MAXBLOCKS 0xFFFFFFFFFFFFFF
#elif S==6
#define MAXBLOCKS 0xFFFFFFFFFFFF
#elif S==5
#define MAXBLOCKS 0xFFFFFFFFFF
#elif S==4
#define MAXBLOCKS 0xFFFFFFFF //max message length for 32-Bit counter
static const byte_type const pad[8] = {0x80, 0x00, 0x00, 0x00};
#elif S==3
#define MAXBLOCKS 0xFFFFFF
#elif S==2
#define MAXBLOCKS 0xFFFF //max message length for 16-Bit counter
#elif S==1
#define MAXBLOCKS 0xFF //max message length for 8-Bit counter
#endif

//key setup phase
void prepare(byte_type k1[N], rk_type ctx1, byte_type k2[N], rk_type ctx2);
//tag generation phase
int generateTag(byte_type* m, word_type size, byte_type t[T], rk_type ctx1, rk_type ctx2);

#endif
