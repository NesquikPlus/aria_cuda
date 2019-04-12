/*
This version assigns one thread per 16 bytes of text.(one text block)
Stores the plaintext/ciphertext in registers.
Stores the encryption keys in shared memory.
Stores the S-boxes in shared memory.
The blocksize is 512.
*/

#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>

#include <cuda_runtime_api.h>
#include <device_launch_parameters.h>


typedef unsigned char uint8;

//Key generation constants
uint8 C1[] = { 0x51,0x7c,0xc1,0xb7,0x27,0x22,0x0a,0x94,0xfe,0x13,0xab,0xe8,0xfa,0x9a,0x6e,0xe0 };
uint8 C2[] = { 0x6d,0xb1,0x4a,0xcc,0x9e,0x21,0xc8,0x20,0xff,0x28,0xb1,0xd5,0xef,0x5d,0xe2,0xb0 };
uint8 C3[] = { 0xdb,0x92,0x37,0x1d,0x21,0x26,0xe9,0x70,0x03,0x24,0x97,0x75,0x04,0xe8,0xc9,0x0e };

//Encryption round keys
uint8 ek[272] = { 0 }; //272 bytes(17 round keys each 16 bytes)
					   //Decyription round keys
uint8 dk[272] = { 0 }; //272 bytes(17 round keys each 16 bytes)

					   //S-boxes
static const uint8 SB1[256] =
{
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static const uint8 SB2[256] =
{
	0xE2, 0x4E, 0x54, 0xFC, 0x94, 0xC2, 0x4A, 0xCC, 0x62, 0x0D, 0x6A, 0x46, 0x3C, 0x4D, 0x8B, 0xD1,
	0x5E, 0xFA, 0x64, 0xCB, 0xB4, 0x97, 0xBE, 0x2B, 0xBC, 0x77, 0x2E, 0x03, 0xD3, 0x19, 0x59, 0xC1,
	0x1D, 0x06, 0x41, 0x6B, 0x55, 0xF0, 0x99, 0x69, 0xEA, 0x9C, 0x18, 0xAE, 0x63, 0xDF, 0xE7, 0xBB,
	0x00, 0x73, 0x66, 0xFB, 0x96, 0x4C, 0x85, 0xE4, 0x3A, 0x09, 0x45, 0xAA, 0x0F, 0xEE, 0x10, 0xEB,
	0x2D, 0x7F, 0xF4, 0x29, 0xAC, 0xCF, 0xAD, 0x91, 0x8D, 0x78, 0xC8, 0x95, 0xF9, 0x2F, 0xCE, 0xCD,
	0x08, 0x7A, 0x88, 0x38, 0x5C, 0x83, 0x2A, 0x28, 0x47, 0xDB, 0xB8, 0xC7, 0x93, 0xA4, 0x12, 0x53,
	0xFF, 0x87, 0x0E, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8E, 0x37, 0x74, 0x32, 0xCA, 0xE9, 0xB1,
	0xB7, 0xAB, 0x0C, 0xD7, 0xC4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xD9, 0xB6, 0xB9, 0x11, 0x40,
	0xEC, 0x20, 0x8C, 0xBD, 0xA0, 0xC9, 0x84, 0x04, 0x49, 0x23, 0xF1, 0x4F, 0x50, 0x1F, 0x13, 0xDC,
	0xD8, 0xC0, 0x9E, 0x57, 0xE3, 0xC3, 0x7B, 0x65, 0x3B, 0x02, 0x8F, 0x3E, 0xE8, 0x25, 0x92, 0xE5,
	0x15, 0xDD, 0xFD, 0x17, 0xA9, 0xBF, 0xD4, 0x9A, 0x7E, 0xC5, 0x39, 0x67, 0xFE, 0x76, 0x9D, 0x43,
	0xA7, 0xE1, 0xD0, 0xF5, 0x68, 0xF2, 0x1B, 0x34, 0x70, 0x05, 0xA3, 0x8A, 0xD5, 0x79, 0x86, 0xA8,
	0x30, 0xC6, 0x51, 0x4B, 0x1E, 0xA6, 0x27, 0xF6, 0x35, 0xD2, 0x6E, 0x24, 0x16, 0x82, 0x5F, 0xDA,
	0xE6, 0x75, 0xA2, 0xEF, 0x2C, 0xB2, 0x1C, 0x9F, 0x5D, 0x6F, 0x80, 0x0A, 0x72, 0x44, 0x9B, 0x6C,
	0x90, 0x0B, 0x5B, 0x33, 0x7D, 0x5A, 0x52, 0xF3, 0x61, 0xA1, 0xF7, 0xB0, 0xD6, 0x3F, 0x7C, 0x6D,
	0xED, 0x14, 0xE0, 0xA5, 0x3D, 0x22, 0xB3, 0xF8, 0x89, 0xDE, 0x71, 0x1A, 0xAF, 0xBA, 0xB5, 0x81
};

static const uint8 SB3[256] =
{
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

static const uint8 SB4[256] =
{
	0x30, 0x68, 0x99, 0x1B, 0x87, 0xB9, 0x21, 0x78, 0x50, 0x39, 0xDB, 0xE1, 0x72, 0x09, 0x62, 0x3C,
	0x3E, 0x7E, 0x5E, 0x8E, 0xF1, 0xA0, 0xCC, 0xA3, 0x2A, 0x1D, 0xFB, 0xB6, 0xD6, 0x20, 0xC4, 0x8D,
	0x81, 0x65, 0xF5, 0x89, 0xCB, 0x9D, 0x77, 0xC6, 0x57, 0x43, 0x56, 0x17, 0xD4, 0x40, 0x1A, 0x4D,
	0xC0, 0x63, 0x6C, 0xE3, 0xB7, 0xC8, 0x64, 0x6A, 0x53, 0xAA, 0x38, 0x98, 0x0C, 0xF4, 0x9B, 0xED,
	0x7F, 0x22, 0x76, 0xAF, 0xDD, 0x3A, 0x0B, 0x58, 0x67, 0x88, 0x06, 0xC3, 0x35, 0x0D, 0x01, 0x8B,
	0x8C, 0xC2, 0xE6, 0x5F, 0x02, 0x24, 0x75, 0x93, 0x66, 0x1E, 0xE5, 0xE2, 0x54, 0xD8, 0x10, 0xCE,
	0x7A, 0xE8, 0x08, 0x2C, 0x12, 0x97, 0x32, 0xAB, 0xB4, 0x27, 0x0A, 0x23, 0xDF, 0xEF, 0xCA, 0xD9,
	0xB8, 0xFA, 0xDC, 0x31, 0x6B, 0xD1, 0xAD, 0x19, 0x49, 0xBD, 0x51, 0x96, 0xEE, 0xE4, 0xA8, 0x41,
	0xDA, 0xFF, 0xCD, 0x55, 0x86, 0x36, 0xBE, 0x61, 0x52, 0xF8, 0xBB, 0x0E, 0x82, 0x48, 0x69, 0x9A,
	0xE0, 0x47, 0x9E, 0x5C, 0x04, 0x4B, 0x34, 0x15, 0x79, 0x26, 0xA7, 0xDE, 0x29, 0xAE, 0x92, 0xD7,
	0x84, 0xE9, 0xD2, 0xBA, 0x5D, 0xF3, 0xC5, 0xB0, 0xBF, 0xA4, 0x3B, 0x71, 0x44, 0x46, 0x2B, 0xFC,
	0xEB, 0x6F, 0xD5, 0xF6, 0x14, 0xFE, 0x7C, 0x70, 0x5A, 0x7D, 0xFD, 0x2F, 0x18, 0x83, 0x16, 0xA5,
	0x91, 0x1F, 0x05, 0x95, 0x74, 0xA9, 0xC1, 0x5B, 0x4A, 0x85, 0x6D, 0x13, 0x07, 0x4F, 0x4E, 0x45,
	0xB2, 0x0F, 0xC9, 0x1C, 0xA6, 0xBC, 0xEC, 0x73, 0x90, 0x7B, 0xCF, 0x59, 0x8F, 0xA1, 0xF9, 0x2D,
	0xF2, 0xB1, 0x00, 0x94, 0x37, 0x9F, 0xD0, 0x2E, 0x9C, 0x6E, 0x28, 0x3F, 0x80, 0xF0, 0x3D, 0xD3,
	0x25, 0x8A, 0xB5, 0xE7, 0x42, 0xB3, 0xC7, 0xEA, 0xF7, 0x4C, 0x11, 0x33, 0x03, 0xA2, 0xAC, 0x60
};



uint8 hex2dec(char ch)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	else
		return ch - 'a' + 10;
}

uint8 leftRotate(uint8 n, uint8 d)
{
	return (n << d) | (n >> (8 - d));
}

uint8 rightRotate(uint8 n, uint8 d)
{
	return (n >> d) | (n << (8 - d));
}

uint8* RightShiftBytes(uint8* arr, int arrSize, int amount)//shift the bytes, place them in a new array
{
	uint8* tmp = (uint8*) malloc(amount);
	uint8* newArr = (uint8*)malloc(16 * sizeof(uint8));

	for (int i = 0; i < amount; i++) {
		tmp[i] = arr[arrSize - amount + i];
	}

	for (int i = arrSize - 1; i >= amount; i--) {
		newArr[i] = arr[i - amount];
	}

	for (int i = 0; i < amount; i++) {
		newArr[i] = tmp[i];
	}
	free(tmp);
	return newArr;
}

uint8* LeftShiftBytes(uint8* arr, int arrSize, int amount)//shift the bytes, place them in a new array
{
	uint8* tmp = (uint8*)malloc(amount);
	uint8* newArr = (uint8*)malloc(16 * sizeof(uint8));

	for (int i = 0; i < amount; i++) {
		tmp[i] = arr[i];
	}

	for (int i = 0; i < arrSize - amount; i++) {
		newArr[i] = arr[i + amount];
	}

	for (int i = 0; i < amount; i++) {
		newArr[arrSize - amount + i] = tmp[i];
	}

	free(tmp);
	return newArr;
}

uint8* ShiftArrR(uint8* originalArr, int amount)
{
	int arrSize = 16;
	int byteShiftAmount = amount / 8;
	uint8* arr = RightShiftBytes(originalArr, arrSize, byteShiftAmount);
	amount = amount - byteShiftAmount * 8;

	uint8 carryTmp, carry;
	carry = arr[arrSize - 1] & (0xff >> (8 - amount));//bits that are shifted to byte on right

	for (int i = 0; i < arrSize; i++)
	{
		carryTmp = arr[i] & (0xff >> (8 - amount));//calculate carry for byte on right
		arr[i] >>= amount;//right shift the current byte.
		arr[i] |= rightRotate(carry, amount);//place the bits from coming from byte on left
		carry = carryTmp;
	}

	return arr;
}

uint8* ShiftArrL(uint8* originalArr, int amount)
{
	int arrSize = 16;
	int byteShiftAmount = amount / 8;
	uint8* arr = LeftShiftBytes(originalArr, arrSize, byteShiftAmount);
	amount = amount - byteShiftAmount * 8;

	uint8 carryTmp, carry;
	carry = arr[0] & (0xff << (8 - amount));//bits that are shifted to byte on left

	for (int i = arrSize - 1; i >= 0; i--)
	{
		carryTmp = arr[i] & (0xff << (8 - amount));//calculate carry for byte on left
		arr[i] <<= amount;//left shift the current byte.
		arr[i] |= leftRotate(carry, amount);//place the bits from coming from byte on right
		carry = carryTmp;
	}

	return arr;
}

void XOR_16(uint8* x, uint8* y, uint8* z)
{
	for (int i = 0; i < 16; i++) {
		z[i] = x[i] ^ y[i];
	}
}

void XOR_16wFree(uint8* x, uint8* y, uint8* z)
{
	for (int i = 0; i < 16; i++) {
		z[i] = x[i] ^ y[i];
	}
	free(y);
}

//Substition Layer 1
void SL1(uint8* in, uint8* out)
{
	out[0] = SB1[in[0]];
	out[1] = SB2[in[1]];
	out[2] = SB3[in[2]];
	out[3] = SB4[in[3]];
	out[4] = SB1[in[4]];
	out[5] = SB2[in[5]];
	out[6] = SB3[in[6]];
	out[7] = SB4[in[7]];
	out[8] = SB1[in[8]];
	out[9] = SB2[in[9]];
	out[10] = SB3[in[10]];
	out[11] = SB4[in[11]];
	out[12] = SB1[in[12]];
	out[13] = SB2[in[13]];
	out[14] = SB3[in[14]];
	out[15] = SB4[in[15]];
}

//Substition Layer 2(Inverse of SL1)
void SL2(uint8* in, uint8* out)
{
	out[0] = SB3[in[0]];
	out[1] = SB4[in[1]];
	out[2] = SB1[in[2]];
	out[3] = SB2[in[3]];
	out[4] = SB3[in[4]];
	out[5] = SB4[in[5]];
	out[6] = SB1[in[6]];
	out[7] = SB2[in[7]];
	out[8] = SB3[in[8]];
	out[9] = SB4[in[9]];
	out[10] = SB1[in[10]];
	out[11] = SB2[in[11]];
	out[12] = SB3[in[12]];
	out[13] = SB4[in[13]];
	out[14] = SB1[in[14]];
	out[15] = SB2[in[15]];
}

//Diffusion layer
void A(uint8* in, uint8* out)
{
	out[0] = in[3] ^ in[4] ^ in[6] ^ in[8] ^ in[9] ^ in[13] ^ in[14];
	out[1] = in[2] ^ in[5] ^ in[7] ^ in[8] ^ in[9] ^ in[12] ^ in[15];
	out[2] = in[1] ^ in[4] ^ in[6] ^ in[10] ^ in[11] ^ in[12] ^ in[15];
	out[3] = in[0] ^ in[5] ^ in[7] ^ in[10] ^ in[11] ^ in[13] ^ in[14];
	out[4] = in[0] ^ in[2] ^ in[5] ^ in[8] ^ in[11] ^ in[14] ^ in[15];
	out[5] = in[1] ^ in[3] ^ in[4] ^ in[9] ^ in[10] ^ in[14] ^ in[15];
	out[6] = in[0] ^ in[2] ^ in[7] ^ in[9] ^ in[10] ^ in[12] ^ in[13];
	out[7] = in[1] ^ in[3] ^ in[6] ^ in[8] ^ in[11] ^ in[12] ^ in[13];
	out[8] = in[0] ^ in[1] ^ in[4] ^ in[7] ^ in[10] ^ in[13] ^ in[15];
	out[9] = in[0] ^ in[1] ^ in[5] ^ in[6] ^ in[11] ^ in[12] ^ in[14];
	out[10] = in[2] ^ in[3] ^ in[5] ^ in[6] ^ in[8] ^ in[13] ^ in[15];
	out[11] = in[2] ^ in[3] ^ in[4] ^ in[7] ^ in[9] ^ in[12] ^ in[14];
	out[12] = in[1] ^ in[2] ^ in[6] ^ in[7] ^ in[9] ^ in[11] ^ in[12];
	out[13] = in[0] ^ in[3] ^ in[6] ^ in[7] ^ in[8] ^ in[10] ^ in[13];
	out[14] = in[0] ^ in[3] ^ in[4] ^ in[5] ^ in[9] ^ in[11] ^ in[14];
	out[15] = in[1] ^ in[2] ^ in[4] ^ in[5] ^ in[8] ^ in[10] ^ in[15];
}

/*Round Functions(F0,FE) takes 16 bytes of plaintext
and generates an intermediate val of 16bytes
*/

//Odd Round Function
void F0(uint8* D, uint8* RK, uint8* out)
{
	//res1, res2 are auxillary arrays for storing the results of XOR_16 and SL1
	uint8 res1[16];
	uint8 res2[16];
	XOR_16(D, RK, res1);
	SL1(res1, res2);
	A(res2, out);
}

//Even Round Function
void FE(uint8* D, uint8* RK, uint8* out)
{
	//res1, res2 are auxillary arrays for storing the results of XOR_16 and SL1
	uint8 res1[16];
	uint8 res2[16];
	XOR_16(D, RK, res1);
	SL2(res1, res2);
	A(res2, out);
}

void GenerateRoundKeys(uint8* W0, uint8* W1, uint8* W2, uint8* W3)
{
	//Producing encryption round keys
	//Producing encryption round keys can be parallelized.
	//However since we do this once for all blocks, it is faster to compute in CPU.
	//ShiftArr functions return array from heap, must free.
	XOR_16wFree(W0, ShiftArrR(W1, 19), &ek[0]);
	XOR_16wFree(W1, ShiftArrR(W2, 19), &ek[16]);
	XOR_16wFree(W2, ShiftArrR(W3, 19), &ek[32]);
	XOR_16wFree(W3, ShiftArrR(W0, 19), &ek[48]);
	XOR_16wFree(W0, ShiftArrR(W1, 31), &ek[64]);
	XOR_16wFree(W1, ShiftArrR(W2, 31), &ek[80]);
	XOR_16wFree(W2, ShiftArrR(W3, 31), &ek[96]);
	XOR_16wFree(W3, ShiftArrR(W0, 31), &ek[112]);
	XOR_16wFree(W0, ShiftArrL(W1, 61), &ek[128]);
	XOR_16wFree(W1, ShiftArrL(W2, 61), &ek[144]);
	XOR_16wFree(W2, ShiftArrL(W3, 61), &ek[160]);
	XOR_16wFree(W3, ShiftArrL(W0, 61), &ek[176]);
	XOR_16wFree(W0, ShiftArrL(W1, 31), &ek[192]);
	XOR_16wFree(W1, ShiftArrL(W2, 31), &ek[208]);
	XOR_16wFree(W2, ShiftArrL(W3, 31), &ek[224]);
	XOR_16wFree(W3, ShiftArrL(W0, 31), &ek[240]);
	XOR_16wFree(W0, ShiftArrL(W1, 19), &ek[256]);
}


void GenerateDecRoundKeys(uint8 numOfRounds)
{
	int N = numOfRounds - 1;
	int k = 1;

	for (int i = 0; i < 16; i++)
	{
		dk[i] = ek[16 * N + i];
	}


	for (int i = N - 1; i >= 1; i--)
	{
		A(&ek[i * 16], &dk[k * 16]);
		k++;
	}

	for (int i = 0; i < 16; i++)
	{
		dk[k * 16 + i] = ek[i];
	}
}

//Odd Round Function
__device__ void F0_d(uint8* D, const uint8* RK, uint8* SB1, uint8* SB2, uint8* SB3, uint8* SB4)
{
	uint8 aux[16];//auxilary array for keeping the results of Diffusion layer

  	//XOR with the round key
	#pragma unroll
	for (int i = 0; i < 16; i++) {
		D[i] = D[i] ^ RK[i];
	}
	//Substition Layer(SL1)
	D[0] = SB1[D[0]];
	D[1] = SB2[D[1]];
	D[2] = SB3[D[2]];
	D[3] = SB4[D[3]];
	D[4] = SB1[D[4]];
	D[5] = SB2[D[5]];
	D[6] = SB3[D[6]];
	D[7] = SB4[D[7]];
	D[8] = SB1[D[8]];
	D[9] = SB2[D[9]];
	D[10] = SB3[D[10]];
	D[11] = SB4[D[11]];
	D[12] = SB1[D[12]];
	D[13] = SB2[D[13]];
	D[14] = SB3[D[14]];
	D[15] = SB4[D[15]];
	//Diffusion layer
	aux[0] = D[3] ^ D[4] ^ D[6] ^ D[8] ^ D[9] ^ D[13] ^ D[14];
	aux[1] = D[2] ^ D[5] ^ D[7] ^ D[8] ^ D[9] ^ D[12] ^ D[15];
	aux[2] = D[1] ^ D[4] ^ D[6] ^ D[10] ^ D[11] ^ D[12] ^ D[15];
	aux[3] = D[0] ^ D[5] ^ D[7] ^ D[10] ^ D[11] ^ D[13] ^ D[14];
	aux[4] = D[0] ^ D[2] ^ D[5] ^ D[8] ^ D[11] ^ D[14] ^ D[15];
	aux[5] = D[1] ^ D[3] ^ D[4] ^ D[9] ^ D[10] ^ D[14] ^ D[15];
	aux[6] = D[0] ^ D[2] ^ D[7] ^ D[9] ^ D[10] ^ D[12] ^ D[13];
	aux[7] = D[1] ^ D[3] ^ D[6] ^ D[8] ^ D[11] ^ D[12] ^ D[13];
	aux[8] = D[0] ^ D[1] ^ D[4] ^ D[7] ^ D[10] ^ D[13] ^ D[15];
	aux[9] = D[0] ^ D[1] ^ D[5] ^ D[6] ^ D[11] ^ D[12] ^ D[14];
	aux[10] = D[2] ^ D[3] ^ D[5] ^ D[6] ^ D[8] ^ D[13] ^ D[15];
	aux[11] = D[2] ^ D[3] ^ D[4] ^ D[7] ^ D[9] ^ D[12] ^ D[14];
	aux[12] = D[1] ^ D[2] ^ D[6] ^ D[7] ^ D[9] ^ D[11] ^ D[12];
	aux[13] = D[0] ^ D[3] ^ D[6] ^ D[7] ^ D[8] ^ D[10] ^ D[13];
	aux[14] = D[0] ^ D[3] ^ D[4] ^ D[5] ^ D[9] ^ D[11] ^ D[14];
	aux[15] = D[1] ^ D[2] ^ D[4] ^ D[5] ^ D[8] ^ D[10] ^ D[15];

	//put the result into plaintext registers
	#pragma unroll
	for (int i = 0; i < 16; i++) {
		D[i] = aux[i];
	}
}

//Even Round Function
__device__ void FE_d(uint8* D, const uint8* RK, uint8* SB1, uint8* SB2, uint8* SB3, uint8* SB4)
{
	uint8 aux[16];//auxilary array for keeping the results of Diffusion layer

  	//XOR with the round key
	#pragma unroll
	for (int i = 0; i < 16; i++) {
		D[i] = D[i] ^ RK[i];
	}
	//Substition Layer(SL2)
	D[0] = SB3[D[0]];
	D[1] = SB4[D[1]];
	D[2] = SB1[D[2]];
	D[3] = SB2[D[3]];
	D[4] = SB3[D[4]];
	D[5] = SB4[D[5]];
	D[6] = SB1[D[6]];
	D[7] = SB2[D[7]];
	D[8] = SB3[D[8]];
	D[9] = SB4[D[9]];
	D[10] = SB1[D[10]];
	D[11] = SB2[D[11]];
	D[12] = SB3[D[12]];
	D[13] = SB4[D[13]];
	D[14] = SB1[D[14]];
	D[15] = SB2[D[15]];
	//Diffusion layer
	aux[0] = D[3] ^ D[4] ^ D[6] ^ D[8] ^ D[9] ^ D[13] ^ D[14];
	aux[1] = D[2] ^ D[5] ^ D[7] ^ D[8] ^ D[9] ^ D[12] ^ D[15];
	aux[2] = D[1] ^ D[4] ^ D[6] ^ D[10] ^ D[11] ^ D[12] ^ D[15];
	aux[3] = D[0] ^ D[5] ^ D[7] ^ D[10] ^ D[11] ^ D[13] ^ D[14];
	aux[4] = D[0] ^ D[2] ^ D[5] ^ D[8] ^ D[11] ^ D[14] ^ D[15];
	aux[5] = D[1] ^ D[3] ^ D[4] ^ D[9] ^ D[10] ^ D[14] ^ D[15];
	aux[6] = D[0] ^ D[2] ^ D[7] ^ D[9] ^ D[10] ^ D[12] ^ D[13];
	aux[7] = D[1] ^ D[3] ^ D[6] ^ D[8] ^ D[11] ^ D[12] ^ D[13];
	aux[8] = D[0] ^ D[1] ^ D[4] ^ D[7] ^ D[10] ^ D[13] ^ D[15];
	aux[9] = D[0] ^ D[1] ^ D[5] ^ D[6] ^ D[11] ^ D[12] ^ D[14];
	aux[10] = D[2] ^ D[3] ^ D[5] ^ D[6] ^ D[8] ^ D[13] ^ D[15];
	aux[11] = D[2] ^ D[3] ^ D[4] ^ D[7] ^ D[9] ^ D[12] ^ D[14];
	aux[12] = D[1] ^ D[2] ^ D[6] ^ D[7] ^ D[9] ^ D[11] ^ D[12];
	aux[13] = D[0] ^ D[3] ^ D[6] ^ D[7] ^ D[8] ^ D[10] ^ D[13];
	aux[14] = D[0] ^ D[3] ^ D[4] ^ D[5] ^ D[9] ^ D[11] ^ D[14];
	aux[15] = D[1] ^ D[2] ^ D[4] ^ D[5] ^ D[8] ^ D[10] ^ D[15];

	//put the result into plaintext registers
	#pragma unroll
	for (int i = 0; i < 16; i++) {
		D[i] = aux[i];
	}
}



template <unsigned int keySize>
__global__ void Decrypt(uint8* cipherText, unsigned long textSize, uint8* dk, uint8* SB_gmem, uint8* IV)
{
	unsigned int tid = threadIdx.x;
	unsigned int idx = blockIdx.x * blockDim.x + threadIdx.x;

	uint8 cipherTextR_1[16];//registers keeping the cipherText.
	uint8 cipherTextR_2[16];//registers keeping the cipherText.

	__shared__ uint8 keySmem[272];//each round key is 16 bytes, there are 17 round keys 272 bytes
	__shared__ uint8 SB1[256];
	__shared__ uint8 SB2[256];
	__shared__ uint8 SB3[256];
	__shared__ uint8 SB4[256];

	//Load decryption round keys to shared memory.
	keySmem[tid] = dk[tid];
	//rest of the bytes(272 bytes) are loaded by first 16 threads.
	if (tid < 16) {
		keySmem[256 + tid] = dk[256 + tid];
	}

	//Load SB tables to shared memory.(1024 bytes loaded by 256 threads)
	SB1[tid] = SB_gmem[tid];
	SB2[tid] = SB_gmem[tid + 256];
	SB3[tid] = SB_gmem[tid + 512];
	SB4[tid] = SB_gmem[tid + 768];

	//Load the plaintext to registers
	//Each thread is responsible for 16 bytes.

	if(idx == 0)//first thread is different than other threads.Uses IV.
	{
		for (int i = 0; i < 16; i++)
		{
			cipherTextR_1[i] = IV[i];
		}
	}
	else
	{
		for (int i = 0; i < 16; i++)
		{
			cipherTextR_1[i] = cipherText[16 * idx -16 + i];//non-coalasced access, slow
		}
	}

	for (int i = 0; i < 16; i++)
	{
		cipherTextR_2[i] = cipherText[16 * idx + i];//non-coalasced access, slow
	}

	__syncthreads();

	if (keySize == 16)//128-bit keys
	{
		F0_d(cipherTextR_2, &keySmem[0], SB1, SB2, SB3, SB4);//ek1...   
		FE_d(cipherTextR_2, &keySmem[16], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[32], SB1, SB2, SB3, SB4);
		FE_d(cipherTextR_2, &keySmem[48], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[64], SB1, SB2, SB3, SB4);
		FE_d(cipherTextR_2, &keySmem[80], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[96], SB1, SB2, SB3, SB4);
		FE_d(cipherTextR_2, &keySmem[112], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[128], SB1, SB2, SB3, SB4);
		FE_d(cipherTextR_2, &keySmem[144], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[160], SB1, SB2, SB3, SB4);//...ek11

		#pragma unroll
		for (int i = 0; i < 16; i++) {
			cipherTextR_2[i] = cipherTextR_2[i] ^ keySmem[176 + i];//ek12
		}

		cipherTextR_2[0] = SB3[cipherTextR_2[0]];
		cipherTextR_2[1] = SB4[cipherTextR_2[1]];
		cipherTextR_2[2] = SB1[cipherTextR_2[2]];
		cipherTextR_2[3] = SB2[cipherTextR_2[3]];
		cipherTextR_2[4] = SB3[cipherTextR_2[4]];
		cipherTextR_2[5] = SB4[cipherTextR_2[5]];
		cipherTextR_2[6] = SB1[cipherTextR_2[6]];
		cipherTextR_2[7] = SB2[cipherTextR_2[7]];
		cipherTextR_2[8] = SB3[cipherTextR_2[8]];
		cipherTextR_2[9] = SB4[cipherTextR_2[9]];
		cipherTextR_2[10] = SB1[cipherTextR_2[10]];
		cipherTextR_2[11] = SB2[cipherTextR_2[11]];
		cipherTextR_2[12] = SB3[cipherTextR_2[12]];
		cipherTextR_2[13] = SB4[cipherTextR_2[13]];
		cipherTextR_2[14] = SB1[cipherTextR_2[14]];
		cipherTextR_2[15] = SB2[cipherTextR_2[15]];

		#pragma unroll
		for (int i = 0; i < 16; i++) {
			cipherTextR_2[i] = cipherTextR_2[i] ^ keySmem[192 + i];//ek13
		}

		//XOR with the previous block.
		#pragma unroll
		for (int i = 0; i < 16; i++) {
			cipherTextR_2[i] = cipherTextR_2[i] ^ cipherTextR_1[i];
		}

		//Write back to global memory
		for (int i = 0; i < 16; i++)
		{
			cipherText[16 * idx + i] = cipherTextR_2[i];
		}
	}
	else if (keySize == 24)//192-bit keys
	{
		F0_d(cipherTextR_2, &keySmem[0], SB1, SB2, SB3, SB4);//ek1...   
		FE_d(cipherTextR_2, &keySmem[16], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[32], SB1, SB2, SB3, SB4);
		FE_d(cipherTextR_2, &keySmem[48], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[64], SB1, SB2, SB3, SB4);
		FE_d(cipherTextR_2, &keySmem[80], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[96], SB1, SB2, SB3, SB4);
		FE_d(cipherTextR_2, &keySmem[112], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[128], SB1, SB2, SB3, SB4);
		FE_d(cipherTextR_2, &keySmem[144], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[160], SB1, SB2, SB3, SB4);
		FE_d(cipherTextR_2, &keySmem[176], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[192], SB1, SB2, SB3, SB4);//ek13

		#pragma unroll
		for (int i = 0; i < 16; i++) {
			cipherTextR_2[i] = cipherTextR_2[i] ^ keySmem[208 + i];//ek14
		}

		cipherTextR_2[0] = SB3[cipherTextR_2[0]];
		cipherTextR_2[1] = SB4[cipherTextR_2[1]];
		cipherTextR_2[2] = SB1[cipherTextR_2[2]];
		cipherTextR_2[3] = SB2[cipherTextR_2[3]];
		cipherTextR_2[4] = SB3[cipherTextR_2[4]];
		cipherTextR_2[5] = SB4[cipherTextR_2[5]];
		cipherTextR_2[6] = SB1[cipherTextR_2[6]];
		cipherTextR_2[7] = SB2[cipherTextR_2[7]];
		cipherTextR_2[8] = SB3[cipherTextR_2[8]];
		cipherTextR_2[9] = SB4[cipherTextR_2[9]];
		cipherTextR_2[10] = SB1[cipherTextR_2[10]];
		cipherTextR_2[11] = SB2[cipherTextR_2[11]];
		cipherTextR_2[12] = SB3[cipherTextR_2[12]];
		cipherTextR_2[13] = SB4[cipherTextR_2[13]];
		cipherTextR_2[14] = SB1[cipherTextR_2[14]];
		cipherTextR_2[15] = SB2[cipherTextR_2[15]];

		#pragma unroll
		for (int i = 0; i < 16; i++) {
			cipherTextR_2[i] = cipherTextR_2[i] ^ keySmem[224 + i];//ek15
		}

		//XOR with the previous block.
		#pragma unroll
		for (int i = 0; i < 16; i++) {
			cipherTextR_2[i] = cipherTextR_2[i] ^ cipherTextR_1[i];
		}

		//Write back to global memory
		for (int i = 0; i < 16; i++)
		{
			cipherText[16 * idx + i] = cipherTextR_2[i];
		}

	}
	else//256-bit keys
	{
		F0_d(cipherTextR_2, &keySmem[0], SB1, SB2, SB3, SB4);//ek1...    
		FE_d(cipherTextR_2, &keySmem[16], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[32], SB1, SB2, SB3, SB4);
		FE_d(cipherTextR_2, &keySmem[48], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[64], SB1, SB2, SB3, SB4);
		FE_d(cipherTextR_2, &keySmem[80], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[96], SB1, SB2, SB3, SB4);
		FE_d(cipherTextR_2, &keySmem[112], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[128], SB1, SB2, SB3, SB4);
		FE_d(cipherTextR_2, &keySmem[144], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[160], SB1, SB2, SB3, SB4);
		FE_d(cipherTextR_2, &keySmem[176], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[192], SB1, SB2, SB3, SB4);
		FE_d(cipherTextR_2, &keySmem[208], SB1, SB2, SB3, SB4);
		F0_d(cipherTextR_2, &keySmem[224], SB1, SB2, SB3, SB4);//ek15

		#pragma unroll
		for (int i = 0; i < 16; i++) {
			cipherTextR_2[i] = cipherTextR_2[i] ^ keySmem[240 + i];//ek16
		}

		cipherTextR_2[0] = SB3[cipherTextR_2[0]];
		cipherTextR_2[1] = SB4[cipherTextR_2[1]];
		cipherTextR_2[2] = SB1[cipherTextR_2[2]];
		cipherTextR_2[3] = SB2[cipherTextR_2[3]];
		cipherTextR_2[4] = SB3[cipherTextR_2[4]];
		cipherTextR_2[5] = SB4[cipherTextR_2[5]];
		cipherTextR_2[6] = SB1[cipherTextR_2[6]];
		cipherTextR_2[7] = SB2[cipherTextR_2[7]];
		cipherTextR_2[8] = SB3[cipherTextR_2[8]];
		cipherTextR_2[9] = SB4[cipherTextR_2[9]];
		cipherTextR_2[10] = SB1[cipherTextR_2[10]];
		cipherTextR_2[11] = SB2[cipherTextR_2[11]];
		cipherTextR_2[12] = SB3[cipherTextR_2[12]];
		cipherTextR_2[13] = SB4[cipherTextR_2[13]];
		cipherTextR_2[14] = SB1[cipherTextR_2[14]];
		cipherTextR_2[15] = SB2[cipherTextR_2[15]];

		#pragma unroll
		for (int i = 0; i < 16; i++) {
			cipherTextR_2[i] = cipherTextR_2[i] ^ keySmem[256 + i];//ek17
		}

		//XOR with the previous block.
		#pragma unroll
		for (int i = 0; i < 16; i++) {
			cipherTextR_2[i] = cipherTextR_2[i] ^ cipherTextR_1[i];
		}

		//Write back to global memory
		for (int i = 0; i < 16; i++)
		{
			cipherText[16 * idx + i] = cipherTextR_2[i];
		}
	}

}


int main(void)
{
	/////////INPUT PART BEGIN//////////////////////

	//Device pointers:
	uint8* deviceArr, *dk_d, *SB_dev, *IV_d;

	FILE *file;
	uint8* inputText;//ciphertext input
	unsigned long int fileLen, textSize;
	uint8 numOfRounds;
    const uint8 keySize = 32;
    uint8 key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

	uint8 IV[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	file = fopen("../input.txt", "r");
	if (file)
	{
		char buf[2];

		fseek(file, 0, SEEK_END);
		fileLen = ftell(file);
		fseek(file, 0, SEEK_SET);
		textSize = fileLen / 2;
		inputText = (uint8*)malloc(textSize);

		for (int i = 0; i < textSize; i++)
		{
			buf[0] = fgetc(file);
			buf[1] = fgetc(file);
			uint8 hexVal = (uint8)strtol(buf, NULL, 16);
			inputText[i] = hexVal;
		}
	}
	else
	{
		printf("File not found.\n");
		return -1;
	}
	/////////INPUT PART END//////////////////////

	if (keySize == 16)
		numOfRounds = 13;
	else if (keySize == 24)
		numOfRounds = 15;
	else
		numOfRounds = 17;


	uint8 KL[16];//KL = leftmost 16 bytes of key 
	uint8 KR[16];//KR = rightmost 16 bytes of key

	/*
	Most significant byte is stored in 0th index.
	KL = leftmost 16 bytes of key
	KR = rightmost 16 bytes of key
	*/

	for (int i = 0; i < 16; i++)
	{
		KL[i] = key[i];
	}

	for (int i = 0; i < 16; i++)
	{
		KR[i] = key[i + 16];
	}

	uint8* CK1, *CK2, *CK3;
	if (keySize == 16) {
		CK1 = C1;
		CK2 = C2;
		CK3 = C3;
	}
	else if (keySize == 24) {
		CK1 = C2;
		CK2 = C3;
		CK3 = C1;
	}
	else {
		CK1 = C3;
		CK2 = C1;
		CK3 = C2;
	}

	//Calculate round key generators W0,W1,W2,W3
	uint8* W0 = KL;
	uint8 W1[16];
	uint8 W2[16];
	uint8 W3[16];
	uint8 Fres[16];//auxilary array

	/*
	W0, W1, W2, W3 are calculated only once and used for all blocks.
	Since the key data W0 and CK1 are small enough this key generators are calculated in CPU.
	W1 needed for calc of W2, W2 needed for calc of W3.
	F0 and FE are also used in the encryption process.
	*/

	F0(W0, CK1, Fres);
	XOR_16(Fres, KR, W1);

	FE(W1, CK2, Fres);
	XOR_16(Fres, W0, W2);

	F0(W2, CK3, Fres);
	XOR_16(Fres, W1, W3);

	GenerateRoundKeys(W0, W1, W2, W3);

	/*
	Because each thread will process 16 bytes we need textSize/16 threads in total.
	Then thread number per block is: ceil(textSize/(16*blockSize)) bytes.
	To decide blockSize we must consider the main occupancy limiter, in this case number of registers per SM.
	Based on NVIDIA's programming guide Number of 32-bit registers per multiprocessor for compute capability >= 5.0 is 64K.
	In this code 16 registers used for plaintext, 16 registers auxilary, +1 by itself, each thread uses 33 registers.
	Then blocksize must be smaller than 64k/33. And larger than 272 since first 272 threads loads the shared memory.
	512, 1024 are available blockSizes.
	256 can also be tried but number of threads loading the shared memory must be decreased.
	Keeping the round keys in registers results in low number of warps per SM therefore poor performance.
	*/

	int blockSize = 256;
	int numOfBlocks = ceil((float)(textSize) / (16 * blockSize));


	//Decryption round keys are derived from the encryption round keys which is generated by GenerateRoundKeys.
	GenerateDecRoundKeys(numOfRounds);

	uint8* resPlainText = (uint8*)malloc(textSize);
	cudaMalloc((void**)& deviceArr, textSize);
	cudaMalloc((void**)& dk_d, 272);
	cudaMalloc((void**)& IV_d, 16);
	cudaMalloc((void**)& SB_dev, 1024);


	//START TIMER.
	using namespace std::chrono;
	high_resolution_clock::time_point start = high_resolution_clock::now();

	cudaMemcpy(deviceArr, inputText, textSize, cudaMemcpyHostToDevice);
	cudaMemcpy(dk_d, dk, 272, cudaMemcpyHostToDevice);
	cudaMemcpy(IV_d, IV, 16, cudaMemcpyHostToDevice);
	//Move Substition layer tables to global memory.(will be moved to shared memory in the kernel.)
	cudaMemcpy(SB_dev, SB1, 256, cudaMemcpyHostToDevice);
	cudaMemcpy(SB_dev + 256, SB2, 256, cudaMemcpyHostToDevice);
	cudaMemcpy(SB_dev + 512, SB3, 256, cudaMemcpyHostToDevice);
	cudaMemcpy(SB_dev + 768, SB4, 256, cudaMemcpyHostToDevice);
	Decrypt<keySize> << <numOfBlocks, blockSize >> >  (deviceArr, textSize, dk_d, SB_dev ,IV_d);
	cudaMemcpy(resPlainText, deviceArr, textSize, cudaMemcpyDeviceToHost);

	//END TIMER; PRINT ELAPSED TIME.
	high_resolution_clock::time_point end = high_resolution_clock::now();
	duration<double> timeElapsed = duration_cast<duration<double>>(end - start);
	std::cout << "Time elapsed: " << timeElapsed.count() << std::endl;		


	//Print/write to file
	FILE *f = fopen("output.txt", "w");
	for (int i = 0; i < textSize; i++) {
		fprintf(f, "%02x", resPlainText[i]);
	}
	fclose(f);

	//free
	cudaFree(deviceArr);
	cudaFree(dk_d);
	free(resPlainText);



	return 0;
}