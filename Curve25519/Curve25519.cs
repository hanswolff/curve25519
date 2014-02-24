using System;
using System.Security.Cryptography;
using limb = System.Int64;

/* C# port by CodesInChaos
 * ported from https://github.com/agl/curve25519-donna
 * The original c code is BSD licensed (original license reproduced below)
 * I put my contributions from porting in the public domain
 * /

/* Copyright 2008, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * curve25519-donna: Curve25519 elliptic curve, public key function
 *
 * http://code.google.com/p/curve25519-donna/
 *
 * Adam Langley <agl@imperialviolet.org>
 *
 * Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
 *
 * More information about curve25519 can be found here
 *   http://cr.yp.to/ecdh.html
 *
 * djb's sample implementation of curve25519 is written in a special assembly
 * language called qhasm and uses the floating point registers.
 *
 * This is, almost, a clean room reimplementation from the curve25519 paper. It
 * uses many of the tricks described therein. Only the crecip function is taken
 * from the sample implementation.
 */

namespace Elliptic
{
    unsafe class Curve25519Donna
    {

        /* Field element representation:
         *
         * Field elements are written as an array of signed, 64-bit limbs, least
         * significant first. The value of the field element is:
         *   x[0] + 2^26·x[1] + x^51·x[2] + 2^102·x[3] + ...
         *
         * i.e. the limbs are 26, 25, 26, 25, ... bits wide.
         */

        /* Sum two numbers: output += in */

        private static void fsum(limb* output, limb* input)
        {
            for (int i = 0; i < 10; i += 2)
            {
                output[0 + i] = (output[0 + i] + input[0 + i]);
                output[1 + i] = (output[1 + i] + input[1 + i]);
            }
        }

        /* Find the difference of two numbers: output = in - output
         * (note the order of the arguments!)
         */

        private static void fdifference(limb* output, limb* input)
        {
            for (int i = 0; i < 10; ++i)
            {
                output[i] = (input[i] - output[i]);
            }
        }

        /* Multiply a number by a scalar: output = in * scalar */

        private static void fscalar_product(limb* output, limb* input, limb scalar)
        {
            for (int i = 0; i < 10; ++i)
            {
                output[i] = input[i] * scalar;
            }
        }

        /* Multiply two numbers: output = in2 * in
         *
         * output must be distinct to both inputs. The inputs are reduced coefficient
         * form, the output is not.
         */

        private static void fproduct(limb* output, limb* in2, limb* input)
        {
            output[0] = ((limb)((int)in2[0])) * ((int)input[0]);
            output[1] = ((limb)((int)in2[0])) * ((int)input[1]) +
                        ((limb)((int)in2[1])) * ((int)input[0]);
            output[2] = 2 * ((limb)((int)in2[1])) * ((int)input[1]) +
                        ((limb)((int)in2[0])) * ((int)input[2]) +
                        ((limb)((int)in2[2])) * ((int)input[0]);
            output[3] = ((limb)((int)in2[1])) * ((int)input[2]) +
                        ((limb)((int)in2[2])) * ((int)input[1]) +
                        ((limb)((int)in2[0])) * ((int)input[3]) +
                        ((limb)((int)in2[3])) * ((int)input[0]);
            output[4] = ((limb)((int)in2[2])) * ((int)input[2]) +
                        2 * (((limb)((int)in2[1])) * ((int)input[3]) +
                           ((limb)((int)in2[3])) * ((int)input[1])) +
                        ((limb)((int)in2[0])) * ((int)input[4]) +
                        ((limb)((int)in2[4])) * ((int)input[0]);
            output[5] = ((limb)((int)in2[2])) * ((int)input[3]) +
                        ((limb)((int)in2[3])) * ((int)input[2]) +
                        ((limb)((int)in2[1])) * ((int)input[4]) +
                        ((limb)((int)in2[4])) * ((int)input[1]) +
                        ((limb)((int)in2[0])) * ((int)input[5]) +
                        ((limb)((int)in2[5])) * ((int)input[0]);
            output[6] = 2 * (((limb)((int)in2[3])) * ((int)input[3]) +
                           ((limb)((int)in2[1])) * ((int)input[5]) +
                           ((limb)((int)in2[5])) * ((int)input[1])) +
                        ((limb)((int)in2[2])) * ((int)input[4]) +
                        ((limb)((int)in2[4])) * ((int)input[2]) +
                        ((limb)((int)in2[0])) * ((int)input[6]) +
                        ((limb)((int)in2[6])) * ((int)input[0]);
            output[7] = ((limb)((int)in2[3])) * ((int)input[4]) +
                        ((limb)((int)in2[4])) * ((int)input[3]) +
                        ((limb)((int)in2[2])) * ((int)input[5]) +
                        ((limb)((int)in2[5])) * ((int)input[2]) +
                        ((limb)((int)in2[1])) * ((int)input[6]) +
                        ((limb)((int)in2[6])) * ((int)input[1]) +
                        ((limb)((int)in2[0])) * ((int)input[7]) +
                        ((limb)((int)in2[7])) * ((int)input[0]);
            output[8] = ((limb)((int)in2[4])) * ((int)input[4]) +
                        2 * (((limb)((int)in2[3])) * ((int)input[5]) +
                           ((limb)((int)in2[5])) * ((int)input[3]) +
                           ((limb)((int)in2[1])) * ((int)input[7]) +
                           ((limb)((int)in2[7])) * ((int)input[1])) +
                        ((limb)((int)in2[2])) * ((int)input[6]) +
                        ((limb)((int)in2[6])) * ((int)input[2]) +
                        ((limb)((int)in2[0])) * ((int)input[8]) +
                        ((limb)((int)in2[8])) * ((int)input[0]);
            output[9] = ((limb)((int)in2[4])) * ((int)input[5]) +
                        ((limb)((int)in2[5])) * ((int)input[4]) +
                        ((limb)((int)in2[3])) * ((int)input[6]) +
                        ((limb)((int)in2[6])) * ((int)input[3]) +
                        ((limb)((int)in2[2])) * ((int)input[7]) +
                        ((limb)((int)in2[7])) * ((int)input[2]) +
                        ((limb)((int)in2[1])) * ((int)input[8]) +
                        ((limb)((int)in2[8])) * ((int)input[1]) +
                        ((limb)((int)in2[0])) * ((int)input[9]) +
                        ((limb)((int)in2[9])) * ((int)input[0]);
            output[10] = 2 * (((limb)((int)in2[5])) * ((int)input[5]) +
                            ((limb)((int)in2[3])) * ((int)input[7]) +
                            ((limb)((int)in2[7])) * ((int)input[3]) +
                            ((limb)((int)in2[1])) * ((int)input[9]) +
                            ((limb)((int)in2[9])) * ((int)input[1])) +
                         ((limb)((int)in2[4])) * ((int)input[6]) +
                         ((limb)((int)in2[6])) * ((int)input[4]) +
                         ((limb)((int)in2[2])) * ((int)input[8]) +
                         ((limb)((int)in2[8])) * ((int)input[2]);
            output[11] = ((limb)((int)in2[5])) * ((int)input[6]) +
                         ((limb)((int)in2[6])) * ((int)input[5]) +
                         ((limb)((int)in2[4])) * ((int)input[7]) +
                         ((limb)((int)in2[7])) * ((int)input[4]) +
                         ((limb)((int)in2[3])) * ((int)input[8]) +
                         ((limb)((int)in2[8])) * ((int)input[3]) +
                         ((limb)((int)in2[2])) * ((int)input[9]) +
                         ((limb)((int)in2[9])) * ((int)input[2]);
            output[12] = ((limb)((int)in2[6])) * ((int)input[6]) +
                         2 * (((limb)((int)in2[5])) * ((int)input[7]) +
                            ((limb)((int)in2[7])) * ((int)input[5]) +
                            ((limb)((int)in2[3])) * ((int)input[9]) +
                            ((limb)((int)in2[9])) * ((int)input[3])) +
                         ((limb)((int)in2[4])) * ((int)input[8]) +
                         ((limb)((int)in2[8])) * ((int)input[4]);
            output[13] = ((limb)((int)in2[6])) * ((int)input[7]) +
                         ((limb)((int)in2[7])) * ((int)input[6]) +
                         ((limb)((int)in2[5])) * ((int)input[8]) +
                         ((limb)((int)in2[8])) * ((int)input[5]) +
                         ((limb)((int)in2[4])) * ((int)input[9]) +
                         ((limb)((int)in2[9])) * ((int)input[4]);
            output[14] = 2 * (((limb)((int)in2[7])) * ((int)input[7]) +
                            ((limb)((int)in2[5])) * ((int)input[9]) +
                            ((limb)((int)in2[9])) * ((int)input[5])) +
                         ((limb)((int)in2[6])) * ((int)input[8]) +
                         ((limb)((int)in2[8])) * ((int)input[6]);
            output[15] = ((limb)((int)in2[7])) * ((int)input[8]) +
                         ((limb)((int)in2[8])) * ((int)input[7]) +
                         ((limb)((int)in2[6])) * ((int)input[9]) +
                         ((limb)((int)in2[9])) * ((int)input[6]);
            output[16] = ((limb)((int)in2[8])) * ((int)input[8]) +
                         2 * (((limb)((int)in2[7])) * ((int)input[9]) +
                            ((limb)((int)in2[9])) * ((int)input[7]));
            output[17] = ((limb)((int)in2[8])) * ((int)input[9]) +
                         ((limb)((int)in2[9])) * ((int)input[8]);
            output[18] = 2 * ((limb)((int)in2[9])) * ((int)input[9]);
        }

        /* Reduce a long form to a short form by taking the input mod 2^255 - 19. */

        private static void freduce_degree(limb* output)
        {
            /* Each of these shifts and adds ends up multiplying the value by 19. */
            output[8] += output[18] << 4;
            output[8] += output[18] << 1;
            output[8] += output[18];
            output[7] += output[17] << 4;
            output[7] += output[17] << 1;
            output[7] += output[17];
            output[6] += output[16] << 4;
            output[6] += output[16] << 1;
            output[6] += output[16];
            output[5] += output[15] << 4;
            output[5] += output[15] << 1;
            output[5] += output[15];
            output[4] += output[14] << 4;
            output[4] += output[14] << 1;
            output[4] += output[14];
            output[3] += output[13] << 4;
            output[3] += output[13] << 1;
            output[3] += output[13];
            output[2] += output[12] << 4;
            output[2] += output[12] << 1;
            output[2] += output[12];
            output[1] += output[11] << 4;
            output[1] += output[11] << 1;
            output[1] += output[11];
            output[0] += output[10] << 4;
            output[0] += output[10] << 1;
            output[0] += output[10];
        }


        /* return v / 2^26, using only shifts and adds. */

        private static limb div_by_2_26(limb v)
        {
            /* High word of v; no shift needed*/
            UInt32 highword = (UInt32)(((UInt64)v) >> 32);
            /* Set to all 1s if v was negative; else set to 0s. */
            Int32 sign = ((Int32)highword) >> 31;
            /* Set to 0x3ffffff if v was negative; else set to 0. */
            Int32 roundoff = (Int32)(((UInt32)sign) >> 6);
            /* Should return v / (1<<26) */
            return (v + roundoff) >> 26;
        }

        /* return v / (2^25), using only shifts and adds. */

        private static limb div_by_2_25(limb v)
        {
            /* High word of v; no shift needed*/
            UInt32 highword = (UInt32)(((UInt64)v) >> 32);
            /* Set to all 1s if v was negative; else set to 0s. */
            Int32 sign = ((Int32)highword) >> 31;
            /* Set to 0x1ffffff if v was negative; else set to 0. */
            Int32 roundoff = (Int32)(((UInt32)sign) >> 7);
            /* Should return v / (1<<25) */
            return (v + roundoff) >> 25;
        }

        private static int div_s32_by_2_25(int v)
        {
            int roundoff = (Int32)(((UInt32)(v >> 31)) >> 7);
            return (v + roundoff) >> 25;
        }

        /* Reduce all coefficients of the short form input so that |x| < 2^26.
         *
         * On entry: |output[i]| < 2^62
         */
        private static void freduce_coefficients(limb* output)
        {
            output[10] = 0;

            for (int i = 0; i < 10; i += 2)
            {
                limb over = div_by_2_26(output[i]);
                output[i] -= over << 26;
                output[i + 1] += over;

                over = div_by_2_25(output[i + 1]);
                output[i + 1] -= over << 25;
                output[i + 2] += over;
            }
            /* Now |output[10]| < 2 ^ 38 and all other coefficients are reduced. */
            output[0] += output[10] << 4;
            output[0] += output[10] << 1;
            output[0] += output[10];

            output[10] = 0;

            /* Now output[1..9] are reduced, and |output[0]| < 2^26 + 19 * 2^38
             * So |over| will be no more than 77825  */
            {
                limb over = div_by_2_26(output[0]);
                output[0] -= over << 26;
                output[1] += over;
            }

            /* Now output[0,2..9] are reduced, and |output[1]| < 2^25 + 77825
             * So |over| will be no more than 1. */
            {
                /* output[1] fits in 32 bits, so we can use div_int_by_2_25 here. */
                int over32 = div_s32_by_2_25((int)output[1]);
                output[1] -= over32 << 25;
                output[2] += over32;
            }

            /* Finally, output[0,1,3..9] are reduced, and output[2] is "nearly reduced":
             * we have |output[2]| <= 2^26.  This is good enough for all of our math,
             * but it will require an extra freduce_coefficients before fcontract. */
        }

        /* A helpful wrapper around fproduct: output = in * in2.
         *
         * output must be distinct to both inputs. The output is reduced degree and
         * reduced coefficient.
         */
        private static void fmul(limb* output, limb* input, limb* in2)
        {
            Long19 t = new Long19();
            fproduct(t.Items, input, in2);
            freduce_degree(t.Items);
            freduce_coefficients(t.Items);
            memcpy10(output, t.Items);
        }

        private static void fsquare_inner(limb* output, limb* input)
        {
            output[0] = ((limb)((int)input[0])) * ((int)input[0]);
            output[1] = 2 * ((limb)((int)input[0])) * ((int)input[1]);
            output[2] = 2 * (((limb)((int)input[1])) * ((int)input[1]) +
                           ((limb)((int)input[0])) * ((int)input[2]));
            output[3] = 2 * (((limb)((int)input[1])) * ((int)input[2]) +
                           ((limb)((int)input[0])) * ((int)input[3]));
            output[4] = ((limb)((int)input[2])) * ((int)input[2]) +
                        4 * ((limb)((int)input[1])) * ((int)input[3]) +
                        2 * ((limb)((int)input[0])) * ((int)input[4]);
            output[5] = 2 * (((limb)((int)input[2])) * ((int)input[3]) +
                           ((limb)((int)input[1])) * ((int)input[4]) +
                           ((limb)((int)input[0])) * ((int)input[5]));
            output[6] = 2 * (((limb)((int)input[3])) * ((int)input[3]) +
                           ((limb)((int)input[2])) * ((int)input[4]) +
                           ((limb)((int)input[0])) * ((int)input[6]) +
                           2 * ((limb)((int)input[1])) * ((int)input[5]));
            output[7] = 2 * (((limb)((int)input[3])) * ((int)input[4]) +
                           ((limb)((int)input[2])) * ((int)input[5]) +
                           ((limb)((int)input[1])) * ((int)input[6]) +
                           ((limb)((int)input[0])) * ((int)input[7]));
            output[8] = ((limb)((int)input[4])) * ((int)input[4]) +
                        2 * (((limb)((int)input[2])) * ((int)input[6]) +
                           ((limb)((int)input[0])) * ((int)input[8]) +
                           2 * (((limb)((int)input[1])) * ((int)input[7]) +
                              ((limb)((int)input[3])) * ((int)input[5])));
            output[9] = 2 * (((limb)((int)input[4])) * ((int)input[5]) +
                           ((limb)((int)input[3])) * ((int)input[6]) +
                           ((limb)((int)input[2])) * ((int)input[7]) +
                           ((limb)((int)input[1])) * ((int)input[8]) +
                           ((limb)((int)input[0])) * ((int)input[9]));
            output[10] = 2 * (((limb)((int)input[5])) * ((int)input[5]) +
                            ((limb)((int)input[4])) * ((int)input[6]) +
                            ((limb)((int)input[2])) * ((int)input[8]) +
                            2 * (((limb)((int)input[3])) * ((int)input[7]) +
                               ((limb)((int)input[1])) * ((int)input[9])));
            output[11] = 2 * (((limb)((int)input[5])) * ((int)input[6]) +
                            ((limb)((int)input[4])) * ((int)input[7]) +
                            ((limb)((int)input[3])) * ((int)input[8]) +
                            ((limb)((int)input[2])) * ((int)input[9]));
            output[12] = ((limb)((int)input[6])) * ((int)input[6]) +
                         2 * (((limb)((int)input[4])) * ((int)input[8]) +
                            2 * (((limb)((int)input[5])) * ((int)input[7]) +
                               ((limb)((int)input[3])) * ((int)input[9])));
            output[13] = 2 * (((limb)((int)input[6])) * ((int)input[7]) +
                            ((limb)((int)input[5])) * ((int)input[8]) +
                            ((limb)((int)input[4])) * ((int)input[9]));
            output[14] = 2 * (((limb)((int)input[7])) * ((int)input[7]) +
                            ((limb)((int)input[6])) * ((int)input[8]) +
                            2 * ((limb)((int)input[5])) * ((int)input[9]));
            output[15] = 2 * (((limb)((int)input[7])) * ((int)input[8]) +
                            ((limb)((int)input[6])) * ((int)input[9]));
            output[16] = ((limb)((int)input[8])) * ((int)input[8]) +
                         4 * ((limb)((int)input[7])) * ((int)input[9]);
            output[17] = 2 * ((limb)((int)input[8])) * ((int)input[9]);
            output[18] = 2 * ((limb)((int)input[9])) * ((int)input[9]);
        }

        internal struct Long19
        {
            public fixed limb Items[19];
        }

        private static void fsquare(limb* output, limb* input)
        {
            var t = new Long19();
            fsquare_inner(t.Items, input);
            freduce_degree(t.Items);
            freduce_coefficients(t.Items);
            memcpy10(output, t.Items);
        }

        private static int ReadLittleEndianInt32(byte* p)
        {
            return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
        }

        /* Take a little-endian, 32-byte number and expand it into polynomial form */

        private static void fexpand(limb* output, byte* input)
        {
            output[0] = (ReadLittleEndianInt32(input + 0) >> 0) & 0x3ffffff;
            output[1] = (ReadLittleEndianInt32(input + 3) >> 2) & 0x1ffffff;
            output[2] = (ReadLittleEndianInt32(input + 6) >> 3) & 0x3ffffff;
            output[3] = (ReadLittleEndianInt32(input + 9) >> 5) & 0x1ffffff;
            output[4] = (ReadLittleEndianInt32(input + 12) >> 6) & 0x3ffffff;
            output[5] = (ReadLittleEndianInt32(input + 16) >> 0) & 0x1ffffff;
            output[6] = (ReadLittleEndianInt32(input + 19) >> 1) & 0x3ffffff;
            output[7] = (ReadLittleEndianInt32(input + 22) >> 3) & 0x1ffffff;
            output[8] = (ReadLittleEndianInt32(input + 25) >> 4) & 0x3ffffff;
            output[9] = (ReadLittleEndianInt32(input + 28) >> 6) & 0x1ffffff;
        }

        /* Take a fully reduced polynomial form number and contract it into a
         * little-endian, 32-byte array
         */
        static void fcontract(byte* output, limb* input)
        {
            int i;
            int j;
            int mask;
            int carry;

            for (j = 0; j < 2; ++j)
            {
                for (i = 0; i < 9; ++i)
                {
                    if ((i & 1) == 1)
                    {
                        /* This calculation is a time-invariant way to make input[i] positive
                           by borrowing from the next-larger limb.
                        */
                        mask = (int)(input[i]) >> 31;
                        carry = -(((int)(input[i]) & mask) >> 25);
                        input[i] = (int)(input[i]) + (carry << 25);
                        input[i + 1] = (int)(input[i + 1]) - carry;
                    }
                    else
                    {
                        mask = (int)(input[i]) >> 31;
                        carry = -(((int)(input[i]) & mask) >> 26);
                        input[i] = (int)(input[i]) + (carry << 26);
                        input[i + 1] = (int)(input[i + 1]) - carry;
                    }
                }
                mask = (int)(input[9]) >> 31;
                carry = -(((int)(input[9]) & mask) >> 25);
                input[9] = (int)(input[9]) + (carry << 25);
                input[0] = (int)(input[0]) - (carry * 19);
            }

            /* The first borrow-propagation pass above ended with every limb
               except (possibly) input[0] non-negative.

               Since each input limb except input[0] is decreased by at most 1
               by a borrow-propagation pass, the second borrow-propagation pass
               could only have wrapped around to decrease input[0] again if the
               first pass left input[0] negative *and* input[1] through input[9]
               were all zero.  In that case, input[1] is now 2^25 - 1, and this
               last borrow-propagation step will leave input[1] non-negative.
            */
            mask = (int)(input[0]) >> 31;
            carry = -(((int)(input[0]) & mask) >> 26);
            input[0] = (int)(input[0]) + (carry << 26);
            input[1] = (int)(input[1]) - carry;

            /* Both passes through the above loop, plus the last 0-to-1 step, are
               necessary: if input[9] is -1 and input[0] through input[8] are 0,
               negative values will remain in the array until the end.
             */

            input[1] <<= 2;
            input[2] <<= 3;
            input[3] <<= 5;
            input[4] <<= 6;
            input[6] <<= 1;
            input[7] <<= 3;
            input[8] <<= 4;
            input[9] <<= 6;
            /*
        #define F(i, s) \
          output[s+0] |=  input[i] & 0xff; \
          output[s+1]  = (input[i] >> 8) & 0xff; \
          output[s+2]  = (input[i] >> 16) & 0xff; \
          output[s+3]  = (input[i] >> 24) & 0xff;
          output[0] = 0;
          output[16] = 0;
          F(0,0);
          F(1,3);
          F(2,6);
          F(3,9);
          F(4,12);
          F(5,16);
          F(6,19);
          F(7,22);
          F(8,25);
          F(9,28);
        #undef F*/
            output[0] = (byte)input[0];

            output[1] = (byte)(input[0] >> 8);
            output[2] = (byte)(input[0] >> 16);
            output[3] = (byte)(input[0] >> 24 | input[1]);

            output[4] = (byte)(input[1] >> 8);
            output[5] = (byte)(input[1] >> 16);
            output[6] = (byte)(input[1] >> 24 | input[2]);

            output[7] = (byte)(input[2] >> 8);
            output[8] = (byte)(input[2] >> 16);
            output[9] = (byte)(input[2] >> 24 | input[3]);

            output[10] = (byte)(input[3] >> 8);
            output[11] = (byte)(input[3] >> 16);
            output[12] = (byte)(input[3] >> 24 | input[4]);

            output[13] = (byte)(input[4] >> 8);
            output[14] = (byte)(input[4] >> 16);
            output[15] = (byte)(input[4] >> 24);

            output[16] = (byte)input[5];

            output[17] = (byte)(input[5] >> 8);
            output[18] = (byte)(input[5] >> 16);
            output[19] = (byte)(input[5] >> 24 | input[6]);

            output[20] = (byte)(input[6] >> 8);
            output[21] = (byte)(input[6] >> 16);
            output[22] = (byte)(input[6] >> 24 | input[7]);

            output[23] = (byte)(input[7] >> 8);
            output[24] = (byte)(input[7] >> 16);
            output[25] = (byte)(input[7] >> 24 | input[8]);

            output[26] = (byte)(input[8] >> 8);
            output[27] = (byte)(input[8] >> 16);
            output[28] = (byte)(input[8] >> 24 | input[9]);

            output[29] = (byte)(input[9] >> 8);
            output[30] = (byte)(input[9] >> 16);
            output[31] = (byte)(input[9] >> 24);
        }

        /* Input: Q, Q', Q-Q'
         * Output: 2Q, Q+Q'
         *
         *   x2 z3: long form
         *   x3 z3: long form
         *   x z: short form, destroyed
         *   xprime zprime: short form, destroyed
         *   qmqp: short form, preserved
         */

        static void fmonty(limb* x2, limb* z2, /* output 2Q */
            limb* x3, limb* z3, /* output Q + Q' */
            limb* x, limb* z, /* input Q */
            limb* xprime, limb* zprime, /* input Q' */
            limb* qmqp /* input Q - Q' */)
        {
            var origx = new Long19();
            var origxprime = new Long19();
            var zzz = new Long19();
            var xx = new Long19();
            var zz = new Long19();
            var xxprime = new Long19();
            var zzprime = new Long19();
            var zzzprime = new Long19();
            var xxxprime = new Long19();

            memcpy10(origx.Items, x);
            fsum(x, z);
            fdifference(z, origx.Items); // does x - z

            memcpy10(origxprime.Items, xprime);
            fsum(xprime, zprime);
            fdifference(zprime, origxprime.Items);
            fproduct(xxprime.Items, xprime, z);
            fproduct(zzprime.Items, x, zprime);
            freduce_degree(xxprime.Items);
            freduce_coefficients(xxprime.Items);
            freduce_degree(zzprime.Items);
            freduce_coefficients(zzprime.Items);
            memcpy10(origxprime.Items, xxprime.Items);
            fsum(xxprime.Items, zzprime.Items);
            fdifference(zzprime.Items, origxprime.Items);
            fsquare(xxxprime.Items, xxprime.Items);
            fsquare(zzzprime.Items, zzprime.Items);
            fproduct(zzprime.Items, zzzprime.Items, qmqp);
            freduce_degree(zzprime.Items);
            freduce_coefficients(zzprime.Items);
            memcpy10(x3, xxxprime.Items);
            memcpy10(z3, zzprime.Items);

            fsquare(xx.Items, x);
            fsquare(zz.Items, z);
            fproduct(x2, xx.Items, zz.Items);
            freduce_degree(x2);
            freduce_coefficients(x2);
            fdifference(zz.Items, xx.Items); // does zz = xx - zz
            fscalar_product(zzz.Items, zz.Items, 121665);
            /* No need to call freduce_degree here:
               fscalar_product doesn't increase the degree of its input. */
            freduce_coefficients(zzz.Items);
            fsum(zzz.Items, xx.Items);
            fproduct(z2, zz.Items, zzz.Items);
            freduce_degree(z2);
            freduce_coefficients(z2);
        }

        private static void memcpy10(limb* destination, limb* source)
        {
            //ToDo: optimize
            for (int i = 0; i < 10; i++)
            {
                destination[i] = source[i];
            }
        }

        /* Conditionally swap two reduced-form limb arrays if 'iswap' is 1, but leave
         * them unchanged if 'iswap' is 0.  Runs in data-invariant time to avoid
         * side-channel attacks.
         *
         * NOTE that this function requires that 'iswap' be 1 or 0; other values give
         * wrong results.  Also, the two limb arrays must be in reduced-coefficient,
         * reduced-degree form: the values in a[10..19] or b[10..19] aren't swapped,
         * and all all values in a[0..9],b[0..9] must have magnitude less than
         * INT32_MAX.
         */

        private static void swap_conditional(limb* a, limb* b, limb iswap)
        {
            int swap = (int)-iswap;

            for (int i = 0; i < 10; ++i)
            {
                int x = swap & (((int)a[i]) ^ ((int)b[i]));
                a[i] = ((int)a[i]) ^ x;
                b[i] = ((int)b[i]) ^ x;
            }
        }

        /* Calculates nQ where Q is the x-coordinate of a point on the curve
         *
         *   resultx/resultz: the x coordinate of the resulting curve point (short form)
         *   n: a little endian, 32-byte number
         *   q: a point of the curve (short form)
         */

        private static void cmult(limb* resultx, limb* resultz, byte* n, limb* q)
        {
            Long19 a = new Long19();
            Long19 b = new Long19();
            Long19 c = new Long19();
            Long19 d = new Long19();
            b.Items[0] = 1;
            c.Items[0] = 1;
            limb* nqpqx = a.Items,
                nqpqz = b.Items,
                nqx = c.Items,
                nqz = d.Items,
                t;
            Long19 e = new Long19();
            Long19 f = new Long19();
            Long19 g = new Long19();
            Long19 h = new Long19();
            f.Items[0] = 1;
            h.Items[0] = 1;
            limb* nqpqx2 = e.Items,
                nqpqz2 = f.Items,
                nqx2 = g.Items,
                nqz2 = h.Items;

            memcpy10(nqpqx, q);

            for (int i = 0; i < 32; ++i)
            {
                byte @byte = n[31 - i];
                for (int j = 0; j < 8; ++j)
                {
                    limb bit = @byte >> 7;

                    swap_conditional(nqx, nqpqx, bit);
                    swap_conditional(nqz, nqpqz, bit);
                    fmonty(nqx2, nqz2,
                        nqpqx2, nqpqz2,
                        nqx, nqz,
                        nqpqx, nqpqz,
                        q);
                    swap_conditional(nqx2, nqpqx2, bit);
                    swap_conditional(nqz2, nqpqz2, bit);

                    t = nqx;
                    nqx = nqx2;
                    nqx2 = t;
                    t = nqz;
                    nqz = nqz2;
                    nqz2 = t;
                    t = nqpqx;
                    nqpqx = nqpqx2;
                    nqpqx2 = t;
                    t = nqpqz;
                    nqpqz = nqpqz2;
                    nqpqz2 = t;

                    @byte <<= 1;
                }
            }

            memcpy10(resultx, nqx);
            memcpy10(resultz, nqz);
        }

        // -----------------------------------------------------------------------------
        // Shamelessly copied from djb's code
        // -----------------------------------------------------------------------------
        private static void crecip(limb* output, limb* z)
        {
            Long19 z2 = new Long19();
            Long19 z9 = new Long19();
            Long19 z11 = new Long19();
            Long19 z2_5_0 = new Long19();
            Long19 z2_10_0 = new Long19();
            Long19 z2_20_0 = new Long19();
            Long19 z2_50_0 = new Long19();
            Long19 z2_100_0 = new Long19();
            Long19 t0 = new Long19();
            Long19 t1 = new Long19();
            int i;

            /* 2 */
            fsquare(z2.Items, z);
            /* 4 */
            fsquare(t1.Items, z2.Items);
            /* 8 */
            fsquare(t0.Items, t1.Items);
            /* 9 */
            fmul(z9.Items, t0.Items, z);
            /* 11 */
            fmul(z11.Items, z9.Items, z2.Items);
            /* 22 */
            fsquare(t0.Items, z11.Items);
            /* 2^5 - 2^0 = 31 */
            fmul(z2_5_0.Items, t0.Items, z9.Items);

            /* 2^6 - 2^1 */
            fsquare(t0.Items, z2_5_0.Items);
            /* 2^7 - 2^2 */
            fsquare(t1.Items, t0.Items);
            /* 2^8 - 2^3 */
            fsquare(t0.Items, t1.Items);
            /* 2^9 - 2^4 */
            fsquare(t1.Items, t0.Items);
            /* 2^10 - 2^5 */
            fsquare(t0.Items, t1.Items);
            /* 2^10 - 2^0 */
            fmul(z2_10_0.Items, t0.Items, z2_5_0.Items);

            /* 2^11 - 2^1 */
            fsquare(t0.Items, z2_10_0.Items);
            /* 2^12 - 2^2 */
            fsquare(t1.Items, t0.Items);
            /* 2^20 - 2^10 */
            for (i = 2; i < 10; i += 2)
            {
                fsquare(t0.Items, t1.Items);
                fsquare(t1.Items, t0.Items);
            }
            /* 2^20 - 2^0 */
            fmul(z2_20_0.Items, t1.Items, z2_10_0.Items);

            /* 2^21 - 2^1 */
            fsquare(t0.Items, z2_20_0.Items);
            /* 2^22 - 2^2 */
            fsquare(t1.Items, t0.Items);
            /* 2^40 - 2^20 */
            for (i = 2; i < 20; i += 2)
            {
                fsquare(t0.Items, t1.Items);
                fsquare(t1.Items, t0.Items);
            }
            /* 2^40 - 2^0 */
            fmul(t0.Items, t1.Items, z2_20_0.Items);

            /* 2^41 - 2^1 */
            fsquare(t1.Items, t0.Items);
            /* 2^42 - 2^2 */
            fsquare(t0.Items, t1.Items);
            /* 2^50 - 2^10 */
            for (i = 2; i < 10; i += 2)
            {
                fsquare(t1.Items, t0.Items);
                fsquare(t0.Items, t1.Items);
            }
            /* 2^50 - 2^0 */
            fmul(z2_50_0.Items, t0.Items, z2_10_0.Items);

            /* 2^51 - 2^1 */
            fsquare(t0.Items, z2_50_0.Items);
            /* 2^52 - 2^2 */
            fsquare(t1.Items, t0.Items);
            /* 2^100 - 2^50 */
            for (i = 2; i < 50; i += 2)
            {
                fsquare(t0.Items, t1.Items);
                fsquare(t1.Items, t0.Items);
            }
            /* 2^100 - 2^0 */
            fmul(z2_100_0.Items, t1.Items, z2_50_0.Items);

            /* 2^101 - 2^1 */
            fsquare(t1.Items, z2_100_0.Items);
            /* 2^102 - 2^2 */
            fsquare(t0.Items, t1.Items);
            /* 2^200 - 2^100 */
            for (i = 2; i < 100; i += 2)
            {
                fsquare(t1.Items, t0.Items);
                fsquare(t0.Items, t1.Items);
            }
            /* 2^200 - 2^0 */
            fmul(t1.Items, t0.Items, z2_100_0.Items);

            /* 2^201 - 2^1 */
            fsquare(t0.Items, t1.Items);
            /* 2^202 - 2^2 */
            fsquare(t1.Items, t0.Items);
            /* 2^250 - 2^50 */
            for (i = 2; i < 50; i += 2)
            {
                fsquare(t0.Items, t1.Items);
                fsquare(t1.Items, t0.Items);
            }
            /* 2^250 - 2^0 */
            fmul(t0.Items, t1.Items, z2_50_0.Items);

            /* 2^251 - 2^1 */
            fsquare(t1.Items, t0.Items);
            /* 2^252 - 2^2 */
            fsquare(t0.Items, t1.Items);
            /* 2^253 - 2^3 */
            fsquare(t1.Items, t0.Items);
            /* 2^254 - 2^4 */
            fsquare(t0.Items, t1.Items);
            /* 2^255 - 2^5 */
            fsquare(t1.Items, t0.Items);
            /* 2^255 - 21 */
            fmul(output, t1.Items, z11.Items);
        }

        internal struct Byte32
        {
            public fixed byte Items[32];
        }

        internal static void curve25519_donna(byte* mypublic, byte* secret, byte* basepoint)
        {
            Long19 bp = new Long19();
            Long19 x = new Long19();
            Long19 z = new Long19();
            Long19 zmone = new Long19();
            Byte32 e = new Byte32();
            int i;

            for (i = 0; i < 32; ++i)
                e.Items[i] = secret[i];
            e.Items[0] &= 248;
            e.Items[31] &= 127;
            e.Items[31] |= 64;

            fexpand(bp.Items, basepoint);
            cmult(x.Items, z.Items, e.Items, bp.Items);
            crecip(zmone.Items, z.Items);
            fmul(z.Items, x.Items, zmone.Items);
            freduce_coefficients(z.Items);
            fcontract(mypublic, z.Items);
        }
    }

    public unsafe class Curve25519
    {
        /// <summary>
        /// Private key clamping (inline, for performance)
        /// </summary>
        /// <param name="key">[out] 32 random bytes</param>
        public static void ClampPrivateKeyInline(byte[] key)
        {
            if (key == null) throw new ArgumentNullException("key");
            if (key.Length != 32) throw new ArgumentException(String.Format("key must be 32 bytes long (but was {0} bytes long)", key.Length));

            key[31] &= 0x7F;
            key[31] |= 0x40;
            key[0] &= 0xF8;
        }

        /// <summary>
        /// Private key clamping
        /// </summary>
        /// <param name="rawKey">[out] 32 random bytes</param>
        public static byte[] ClampPrivateKey(byte[] rawKey)
        {
            if (rawKey == null) throw new ArgumentNullException("rawKey");
            if (rawKey.Length != 32) throw new ArgumentException(String.Format("rawKey must be 32 bytes long (but was {0} bytes long)", rawKey.Length), "rawKey");

            var res = new byte[32];
            Array.Copy(rawKey, res, 32);

            res[31] &= 0x7F;
            res[31] |= 0x40;
            res[0] &= 0xF8;

            return res;
        }

        private static readonly byte[] BasePoint = { 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9 };
        /// <summary>
        /// Generates the public key out of the clamped private key
        /// </summary>
        /// <param name="privateKey">private key (must use ClampPrivateKey first!)</param>
        public static byte[] GetPublicKey(byte[] privateKey)
        {
            var publicKey = new byte[32];

            fixed (byte* mypublic = publicKey)
            fixed (byte* mysecret = privateKey)
            fixed (byte* basepoint = BasePoint)
            {
                Curve25519Donna.curve25519_donna(mypublic, mysecret, basepoint);
            }
            return publicKey;
        }

        /// <summary>
        /// Creates a random private key
        /// </summary>
        /// <returns>32 random bytes that are clamped to a suitable private key</returns>
        public static byte[] CreateRandomPrivateKey()
        {
            var privateKey = new byte[32];
            RNGCryptoServiceProvider.Create().GetBytes(privateKey);
            ClampPrivateKeyInline(privateKey);

            return privateKey;
        }

        /// <summary>
        /// Key agreement
        /// </summary>
        /// <param name="privateKey">[in] your private key for key agreement</param>
        /// <param name="peerPublicKey">[in] peer's public key</param>
        /// <returns>shared secret (needs hashing before use)</returns>
        public static byte[] GetSharedSecret(byte[] privateKey, byte[] peerPublicKey)
        {
            var sharedSecret = new byte[32];

            fixed (byte* sharedkey = sharedSecret)
            fixed (byte* mysecret = privateKey)
            fixed (byte* theirpublic = peerPublicKey)
            {
                Curve25519Donna.curve25519_donna(sharedkey, mysecret, theirpublic);
            }
            return sharedSecret;
        }
    }
}