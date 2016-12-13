/**
* lightmac.c
*
* @author Sebastian Mertz
*
* Usage and Test of LightMAC Implementation
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

#include <stdio.h>
#include "lightmac.h"

//function for printing hex values to console
void printValues(byte_type* v, word_type size)
{
    word_type i;
    printf("'");
    for(i = 0; i<size; i++)
    {
        printf("%x",v[i]);
    }
    printf("'\r\n");
}

//example main, using MAC independend of specified block cipher (can be declared in lightmac.h)
int main()
{
    byte_type* k1 = (byte_type*)"abcdefghijklmnop";
    byte_type* k2 = (byte_type*)"ponmlkjihgfedcba";
    byte_type* m = (byte_type*)"ponmlkjihgfedcbaponmlkjihgfedcbaponmlkjihgfedcbaponmlkjihgfedcba";
    byte_type t[16];
    rk_type ctx1[1], ctx2[1];
    prepare(k1, *ctx1, k2, *ctx2);
    generateTag(m, 63, t, *ctx1, *ctx2);
    printValues(t,16);
    return 0;
}
