/* 
 *		    GNU GENERAL PUBLIC LICENSE
 *		       Version 2, June 1991
 *
 * Copyright (C) 2016 Yash Singh
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *
 *  For questions regarding this license you can email me at warrioryash@protonmail.com
 */

// Header files needed by NGINX structs
extern "C" {
  #include <ngx_config.h>
  #include <ngx_core.h>
  #include <ngx_event.h>
  #include <ngx_event_connect.h>
  #include <ngx_event_pipe.h>
  #include <ngx_http.h>   
}
// Include C++ header files
// #include <iostream>

#include <algorithm>
#include <iostream>
#include <string>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>

#include "keygen.h"


#define CRYPTOX_ERROR              1
#define CRYPTOX_ERROR_SUCCESS      0

#define True                       0
#define False                      1

#define nil                        NULL

#ifndef MAX_PATH
#define MAX_PATH 256
#endif


char* __cdecl _strrev(char* pStr)
{
size_t iLen,iHalf;
char a,b;
 iLen=strlen(pStr), iHalf=iLen/2;
for(size_t i=0; i<iHalf; i++)
 {
     a=pStr[i], b=pStr[iLen-i-1];
     pStr[i]=b, pStr[iLen-i-1]=a;
 }
return pStr;
}

#define ALL_MAX_PATH MAX_PATH + MAX_PATH + MAX_PATH + MAX_PATH
#define FREE_ALL free(temporary_a); free(temporary_b); free(temporary_c); free(temporary_d)
#define VALIDA_STR_A(STR, VALOR) if (!(strlen(STR) >= VALOR)) { FREE_ALL; return result; }
#define VALIDA_STR_B(STR, VALOR) if (!(strlen(STR) == VALOR)) { FREE_ALL; return result; }

#define FORMAT_NUMBER(STROUT) for (a = 0; STROUT[a] != '\0'; a++) {                        \
   if (a == 4)  { temporary_a[a] = '\0'; for (b = 0; STROUT[a] != '\0'; b++, a++)          \
   STROUT[b] = STROUT[a]; STROUT[b] = '\0'; } temporary_a[a] = STROUT[a]; }                \
   _strrev(STROUT); if (STROUT[0] == '0') STROUT[0] = '1'                                  \

#define GENERATE(A, B, C, D, E, F) if (global_key % 2 == 0) {                              \
   if (a % 2 == 0) temporary_d[a] = A; else { if (b % 2 == 0) temporary_d[a] = B;          \
   else temporary_d[a] = C; } } else { if (d % 2 == 0) temporary_d[a] = D;                 \
   else { if (c % 2 == 0) temporary_d[a] = E; else temporary_d[a] = F; } }                 \

extern "C" int str_encrypt (char * string)
{
   char * temporary_a, * temporary_b, * temporary_c, * temporary_d;
   int a = 0, b = 0, c = 0, d = 0;
   int key_temp, global_key, rand_key;
   int result = CRYPTOX_ERROR;

   if ((temporary_a = (char *)malloc(ALL_MAX_PATH)) == NULL) return result;
   if ((temporary_b = (char *)malloc(ALL_MAX_PATH)) == NULL) return result;
   if ((temporary_c = (char *)malloc(ALL_MAX_PATH)) == NULL) return result;
   if ((temporary_d = (char *)malloc(ALL_MAX_PATH)) == NULL) return result;

   memset(temporary_a, 0x00, ALL_MAX_PATH);
   memset(temporary_b, 0x00, ALL_MAX_PATH);
   memset(temporary_c, 0x00, ALL_MAX_PATH);
   memset(temporary_d, 0x00, ALL_MAX_PATH);

   // Gera chave randomica...
   srand((unsigned int)time(NULL));
   key_temp = (int)rand() * 5;
   sprintf(temporary_a, "%d", key_temp);

   VALIDA_STR_A(temporary_a, 8) for (a = 0; a != 8; a++) temporary_b[a] = temporary_a[a];
   VALIDA_STR_B(temporary_b, 8) memset(temporary_a, 0x00, ALL_MAX_PATH);
   FORMAT_NUMBER(temporary_b);

   memset(temporary_a, 0x00, ALL_MAX_PATH);

   key_temp = (int)rand() * key_temp;
   sprintf(temporary_a, "%d", key_temp);

   VALIDA_STR_A(temporary_a, 8) for (a = 0; a != 8; a++) temporary_c[a] = temporary_a[a];
   VALIDA_STR_B(temporary_c, 8) memset(temporary_a, 0x00, ALL_MAX_PATH);
   FORMAT_NUMBER(temporary_c);

   sprintf(temporary_d, "%s%s", temporary_b, temporary_c);
   VALIDA_STR_B(temporary_d, 8)
   
   global_key = (int)strtol(temporary_d, (char **)0, 10);
   rand_key = global_key;

   // Encoda string...
   memset(temporary_a, 0x00, ALL_MAX_PATH);
   memset(temporary_b, 0x00, ALL_MAX_PATH);

   for (a = 0; string[a]; a++)
   {
      if (string[a] > rand_key)
      {
         b = string[a] - rand_key;
         rand_key = rand_key + b;

         sprintf(temporary_a, "D%d", b);
         strcat(temporary_b, temporary_a);
      }

      if (string[a] < rand_key)
      {
         b = rand_key - string[a];
         rand_key = rand_key - b;

         sprintf(temporary_a, "M%d", b);
         strcat(temporary_b, temporary_a);
      }

      if (string[a] == string[a+1])
      {
         sprintf(temporary_a, "R%d", b);
         strcat(temporary_b, temporary_a);
      }
   }

   // Monta string...
   memset(temporary_a, 0x00, ALL_MAX_PATH);
   memset(temporary_c, 0x00, ALL_MAX_PATH);
   sprintf(temporary_a, "%d", global_key);

   for (a = 0; temporary_a[a] != '\0'; a++)
   {
      if (a == 4)
      {
         temporary_c[a] = '\0';
         for (b = 0; temporary_a[a] != '\0'; b++, a++)
         {
            temporary_a[b] = temporary_a[a];
         }
         temporary_a[b] = '\0';
      }
      temporary_c[a] = temporary_a[a];
   }

   VALIDA_STR_B(temporary_a, 4)
   VALIDA_STR_B(temporary_c, 4)

   sprintf(temporary_d, "%s%s%s", temporary_a, temporary_b, temporary_c);

   // Ofusca string...
   for (a = 0; temporary_d[a] != '\0' ; a++)
   {
      b = (int)temporary_d[a];
      c = global_key / 3;
      d = b + c;

      switch (temporary_d[a])
      {
      case 'D': GENERATE('A', 'D', 'a', 'n', '}', ';') break;
      case 'M': GENERATE('E', 'H', 'o', 'p', '@', '.') break;
      case 'R': GENERATE('I', 'R', 'z', 'f', '&', ',') break;
      case '0': GENERATE('B', 'K', 'j', 'k', '#', ':') break;
      case '1': GENERATE('F', 'S', 'q', 't', ')', '^') break;
      case '2': GENERATE('L', 'M', 'e', 'y', '-', '_') break;
      case '3': GENERATE('O', 'U', 'r', 'b', '*', '?') break;
      case '4': GENERATE('Q', 'T', 'i', 's', '%', '/') break;
      case '5': GENERATE('J', 'Y', 'm', 'l', '$', '>') break;
      case '6': GENERATE('C', 'N', 'u', 'v', '(', '[') break;
      case '7': GENERATE('W', 'V', 'c', 'd', '+', '!') break;
      case '8': GENERATE('G', 'P', 'w', 'x', '{', '~') break;
      case '9': GENERATE('X', 'Z', 'g', 'h', '=', '<') break;
      }
   }

   strcpy(string, temporary_d);

   free(temporary_a);
   free(temporary_b);
   free(temporary_c);
   free(temporary_d);
   return CRYPTOX_ERROR_SUCCESS;
}

/***********************************
 * Keygenerator for CSAW Challenge *
 * Jeffrey Crowell                 *
 * used in solution and server     *
 ***********************************/


typedef unsigned char uchar;
typedef unsigned int uint;
typedef struct keys keys;

using namespace std;

//simple pair of uints for returning from encrypt
struct keys
{
    uint v0;
    uint v1;
};

//TEA off of the wikipedia page :-)
keys encrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
    }                                              /* end cycle */
    keys s = {v0, v1};
    return s;
}


int Gen(const char* user, char* license, char* license_iv)
{
    uint v[2];
    uint k[4];
    string input(user);
    if(input.length() < 16) //less than 16 chars makes the keys not work
    {
        // cout << "input must be at least 16 characters" << endl;
        // cout << "you provided only " << input.length() << " characters" << endl;
        return -1;
    }
    v[0] = (input[0] << 24) | (input[1] << 16) | (input[2] << 8) | (input[3]); //fill up the plaintext
    v[1] = (input[4] << 24) | (input[5] << 16) | (input[6] << 8) | (input[7]);
    string inrev(input.rbegin(), input.rend());                                //reverse input
    k[0] = (inrev[0] << 24) | (inrev[1] << 16) | (inrev[2] << 8) | (inrev[3]); //fill up the keys
    k[1] = (inrev[4] << 24) | (inrev[5] << 16) | (inrev[6] << 8) | (inrev[7]);
    k[2] = (inrev[8] << 24) | (inrev[9] << 16) | (inrev[10] << 8) | (inrev[11]);
    k[3] = (inrev[12] << 24) | (inrev[13] << 16) | (inrev[14] << 8) | (inrev[15]);
    keys s = encrypt(v, k); //encrypt the input under the reverse input
    uint license_iv_int = time(0);
#if 0
    // uint temp1 = s.v1 ^ 0x12345678; //this part is just to make it so that it isn't straight TEA as from the vm binary
#else
    uint temp1 = s.v1 ^ license_iv_int; //this part is just to make it so that it isn't straight TEA as from the vm binary
#endif
    uchar ch1 = ((s.v0 & 0xFFFFFFFF) >> 24);
    uchar ch2 = ((s.v0 & 0x00FF0000) >> 16);
    uchar ch3 = ((s.v0 & 0x0000FF00) >> 8);
    uchar ch4 = ((s.v0 & 0x000000FF));
    uint temp2 = (ch3 << 24) | (ch1 << 16) | (ch2 << 8) | (ch4);
    // cout << temp1 << " " << temp2 << endl;  //print out the keys, for use in the solver and the server
    std::string username = input;
    std::string tok1 = std::to_string(temp1);
    std::string tok2 = std::to_string(temp2);
    username += ":";
    username += tok1;
    username += ":";
    username += tok2;
    // char user[256] = {0};
    std::string license_iv_str = std::to_string(license_iv_int);
    memmove(license, username.c_str(), username.length());
    memmove(license_iv, license_iv_str.c_str(), license_iv_str.length());
    return str_encrypt(license);
    // cout << user << endl;  //print out the keys, for use in the solver and the server
}

bool IsAlphaStr(const char* str) {
   int i = strlen(str);
   for (int j = 0; j < i; j++) {
       int c = str[j];
       if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
         continue;
       }
       return false;
   }
   return true;
}

int LicenseGen(const char* user, char* license, char* license_iv) {
   Gen(user, license, license_iv);
   while (!IsAlphaStr(license)) {
      memset(license , 0, strlen(license));
      memset(license_iv , 0, strlen(license_iv));
      Gen(user, license, license_iv);
   }
   return 0;
}




