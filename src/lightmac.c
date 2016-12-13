/**
* lightmac.c
*
* @author Sebastian Mertz
*
* Basic Implementation for LightMAC with adjustable counter
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

#include "lightmac.h"
#if (S!=1 && S!=4 && S!=8) || FORCE_VAR_CTR

//Set up block cipher context for two keys
void prepare(byte_type* k1, rk_type ctx1, byte_type *k2, rk_type ctx2)
{
    SETUP(ctx1, k1);
    SETUP(ctx2, k2);
}

//Process message and produce authentication tag
int generateTag(byte_type* m, word_type size, byte_type t[T], rk_type ctx1, rk_type ctx2)
{
    byte_type* pm = m;
    byte_type j, v[N], temp_t[N], temp_m[N], lastblocksize = (size)%(N-S);
    word_type i;
    word_type l = (size)/(N-S);

    //instead of ceiling operation, is probably faster when lastblocksize is known
    if(lastblocksize!=0)
    {
        l++;
    }

    //abort with error if message is too long to be processed
    if(((size*8)/(N-S)) > MAXBLOCKS)
    {
        return -1;
    }

    //initialize intermediate tag
    memset(v, 0, N);

    for (i=0; i<l-1; i++)
    {
        //concat message and counter
        memcpy(temp_m, &i, S);
        memcpy(temp_m+S, pm, N-S);

        //process block and xor to intermediate tag
        ENCRYPT(ctx1, temp_m, temp_t);
        for(j=0; j<N; j++) v[j] ^= temp_t[j];
        pm+=(N-S);
    }

    //process last block
    if(!lastblocksize)
    {
        memcpy(temp_m, pm, N-S);
        temp_m[N-S] = 0x80;
        memset(temp_m+((N-S)+1), 0, S-1);
    }
    else
    {
        memcpy(temp_m, pm, lastblocksize);
        temp_m[lastblocksize] = 0x80;
        memset(temp_m+(lastblocksize+1), 0, N-lastblocksize-1);
    }
    for (i=0; i<N; i++) v[i] ^= temp_m[i];

    //create final authentication tag
    ENCRYPT(ctx2, v, temp_t);
    memcpy(t, temp_t, T);
    return 0;
}
#endif
