/*
Copyright (c) 2009, guidtech.net
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the guidtech.net nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY guidtech.net ''AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL guidtech.net BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

//mostly derived from the pages below, and also some work with IDA pro
//http://www.intel.com/Assets/PDF/manual/253666.pdf
//http://www.intel.com/products/processor/manuals/index.htm

#define AAA				0x37	//ASCII adjust AL after addition.
#define AAD				0xD5	//[D5 0A]( Invalid Valid ASCII adjust AX before division. )[D5 ib]( Invalid Valid Adjust AX before division to number base imm8. )
#define AAM				0xD4	//[D4 0A]( Invalid Valid ASCII adjust AX after multiply. )[D4 ib]( Invalid Valid Adjust AX after multiply to number base imm8. )
#define AAS				0x3F	//ASCII adjust AL after subtraction.

#define ADD_AL			0x04	//takes imm8
#define ADD_AX			0x05	//takes imm16
#define ADD_EAX			0x05	//takes imm32

#define ADC_AL			0x14	//takes imm8
#define ADC_AX			0x15	//takes imm16
#define ADC_EAX			0x15	//takes imm32

#define AND_AL			0x24	//takes imm8
#define AND_AX			0x25	//takes imm16
#define AND_EAX			0x25	//takes imm32

#define BIT_OPERATION	0x0F	//first opcode of the "Bit scan" group of funtions
#define BIT_T			0xA3	//Store selected bit in CF flag. !! REQUIRES "BIT_OPERATION" FIRST OP !!
#define BITSCAN_SF		0xBC	//(Bit scan forward on r/m16. - Bit scan forward on r/m32. ) !! REQUIRES "BIT_OPERATION" FIRST OP !!
#define BITSCAN_SR		0xBD	//(Bit scan reverse on r/m16. - Bit scan reverse on r/m32. ) !! REQUIRES "BIT_OPERATION" FIRST OP !!
#define BITSCAN_SWAP	0xC8	//Reverses the byte order of a 32-bit register !! REQUIRES "BIT_OPERATION" FIRST OP !!

#define BOUND			0x62	//takes ( r16/r32, m16&16/m32&32 )

#define MOV_AL_OFFSET	0xA0
#define MOV_EAX_OFFSET	0xA1
#define MOV_OFFSET_AL	0xA2
#define MOV_OFFSET_EAX	0xA3
#define MOV_EAX_VALUE	0xB8

#define CALL_INTERNAL	0xE8
#define CALL_EXTERNAL	0xFF

#define XOR				0x31
#define NOP				0x90
#define INT3			0xCC
#define RETN			0xC3
#define PUSHA			0x60
#define POPA			0x61