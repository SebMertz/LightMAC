# LightMAC
An Implementation of the Message Authentication Code LightMAC

The implementation was created as part of my Bachelor Thesis. The original paper of the authors describing LightMAC can be found at https://eprint.iacr.org/2016/190.

I was not able to proof that my implementation is working correct because there are no test vectors available and I had no time to proof its correct outputs with high reliabillity. So if anyone has knews on this I wolud like to hear them. Nonetheless it should be good enough for demonstrating the algorithm. I take no guarantee on the proper functionality of this code but feel free to use it. Copyright declarations are given in the source files (they are all placed in the public domain).

I use an Rijndael (AES) implementation, that is in the public domain (as given in the source files). But the LightMAC implementation can be used with any block cipher. It needs to be included in the lightmac.h header file and the necessary variables and function mappings have to be defined. There are two examples given, one for the Rijndael implementation mentioned above and one for AES as implemented in the mbedTLS cryptographic library (see here for source code: https://tls.mbed.org/aes-source-code).

