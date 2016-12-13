/**
* lightmac8.c
*
* @author Sebastian Mertz
*
* Basic Implementation for LightMAC with 8 Bit counter
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
#if S==1 && !FORCE_VAR_CTR

//Set up block cipher context for two keys
void prepare(byte_type k1[N], rk_type ctx1, byte_type k2[N], rk_type ctx2)
{
    SETUP(ctx1, k1);
    SETUP(ctx2, k2);
}

//Process message and produce authentication tag
int generateTag(byte_type* m, word_type size, byte_type t[T], rk_type ctx1, rk_type ctx2)
{
    byte_type i, lastblocksize = (size)%(N-S), v[N], work[N];
    byte_type l = (size)/(N-S), ctr;
    byte_type *pm = m;

    //instead of ceiling operation, is probably faster when lastblocksize is known
    if(lastblocksize!=0)
    {
        l++;
    }

    //abort with error if message is too long to be processed
    if(l > MAXBLOCKS)
    {
        return -1;
    }

    //initialize intermediate tag
    for(i=0; i<N; i++) v[i] = 0;

    for (ctr=0; ctr<l-1; ctr++)
    {
        //concat message and counter
        work[0] = ctr;
        for(i=1; i<N; i++) work[i] = pm[i-1];

        //process block and xor to intermediate tag
        ENCRYPT(ctx1, work, work);
        for(i=0; i<N; i++) v[i] ^= work[i];
        pm+=15;
    }

    //process last block
    if(!lastblocksize)
    {
        for(i=0; i<N-1; i++) work[i] = pm[i];
        work[15] = 0x80;
    }
    else
    {
        for(i=0; i<lastblocksize; i++) work[i] = pm[i];
        work[lastblocksize] = 0x80;
        for(i=lastblocksize+1; i<N; i++) work[i] = 0;
    }
    for (i=0; i<N; i++) v[i] ^= work[i];

    //create final authentication tag
    ENCRYPT(ctx2, v, t);
    return 0;
}
#endif
