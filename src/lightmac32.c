/**
* lightmac32.c
*
* @author Sebastian Mertz
*
* Basic Implementation for LightMAC with 32 Bit counter
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
#if S==4 && !FORCE_VAR_CTR

//Set up block cipher context for two keys
void prepare(byte_type k1[N], rk_type ctx1, byte_type k2[N], rk_type ctx2)
{
    SETUP(ctx1, k1);
    SETUP(ctx2, k2);
}

//Process message and produce authentication tag
int generateTag(byte_type* m, word_type size, byte_type t[T], rk_type ctx1, rk_type ctx2)
{
    byte_type i,j=0, lastblocksize = (size)%(N-S);
    word_type l = (size)/(N-S), ctr;
    word_type *pm = (word_type*)m, v[N/4], work[N/4];

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
    v[0]=0;
    v[1]=0;
    v[2]=0;
    v[3]=0;

    for (ctr=0; ctr<l-1; ctr++)
    {
        //concat message and counter
        work[0] = ctr;
        work[1] = pm[0];
        work[2] = pm[1];
        work[3] = pm[2];

        //process block and xor to intermediate tag
        ENCRYPT(ctx1, (byte_type*)work, (byte_type*)work);
        for(i=0; i<N/4; i++) v[i] ^= work[i];
        pm+=3;
    }

    //process last block depending on remaining bytes
    if(lastblocksize == 0)
    {
        work[0] = pm[0];
        work[1] = pm[1];
        work[2] = pm[2];
        work[3] = ((word_type*)pad)[0];
    }
    else if(lastblocksize < 4)
    {
        work[0] = 0 | ((word_type)0x80)<<((lastblocksize)*8);
        for(i = 0; j<lastblocksize; i++, j++)
        {
            work[0] |= ((pm[0]>>(i*8))&0xff)<<(i*8);
        }
        work[1] = 0;
        work[2] = 0;
        work[3] = 0;
    }
    else if(lastblocksize < 8)
    {
        work[0] = pm[0];
        work[1] = 0 | ((word_type)0x80)<<((lastblocksize)*8);
        for(i = 0; j<lastblocksize-4; i++, j++)
        {
            work[1] |= ((pm[1]>>(i*8))&0xff)<<(i*8);
        }
        work[2] = 0;
        work[3] = 0;
    }
    else if(lastblocksize < 12)
    {
        work[0] = pm[0];
        work[1] = pm[1];
        work[2] = 0 | ((word_type)0x80)<<((lastblocksize)*8);
        for(i = 0; j<lastblocksize-8; i++, j++)
        {
            work[2] |= ((pm[2]>>(i*8))&0xff)<<(i*8);
        }
        work[3] = 0;
    }
    else
    {
        return -2; //something went wrong
    }
    for (i=0; i<N/4; i++) v[i] ^= work[i];

    //create final authentication tag
    ENCRYPT(ctx2, (byte_type*)v, t);
    return 0;
}
#endif
