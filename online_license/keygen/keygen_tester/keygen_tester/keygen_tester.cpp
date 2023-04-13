#include "keygen_tester.h"
#include <iostream>
#include <sstream>
#include <vector>

#include "keygenme/keygenme.h"
//#include "CryptoX/decrypt.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define CRYPTOX_ERROR              1
#define CRYPTOX_ERROR_SUCCESS      0

#define True                       0
#define False                      1

#define nil                        NULL

#ifndef MAX_PATH
#define MAX_PATH 256
#endif

#define COMPARE(A,B,C,D,E,F) string[a] == A || string[a] == B                \
   || string[a] == C || string[a] == D || string[a] == E || string[a] == F   \

int str_decrypt(char * string)
{
   char ca, *cb, *cd, * temporary_a, * temporary_b, * temporary_c;
   int a, b, c, d, e, global_key = 0, key = 0, length = MAX_PATH, result = False;

   if ((temporary_a = (char *)malloc(strlen(string))) == NULL) return result;
   if ((temporary_b = (char *)malloc(length)) == NULL) return result;
   if ((temporary_c = (char *)malloc(length)) == NULL) return result;

   // Faz reverso da ofuscação...
   for (a = 0; string[a] != '\0' ; a++)
   {
      if      (COMPARE('A', 'D', 'a', 'n', '}', ';')) string[a] = 'D';
      else if (COMPARE('E', 'H', 'o', 'p', '@', '.')) string[a] = 'M';
      else if (COMPARE('I', 'R', 'z', 'f', '&', ',')) string[a] = 'R';
      else if (COMPARE('B', 'K', 'j', 'k', '#', ':')) string[a] = '0';
      else if (COMPARE('F', 'S', 'q', 't', ')', '^')) string[a] = '1';
      else if (COMPARE('L', 'M', 'e', 'y', '-', '_')) string[a] = '2';
      else if (COMPARE('O', 'U', 'r', 'b', '*', '?')) string[a] = '3';
      else if (COMPARE('Q', 'T', 'i', 's', '%', '/')) string[a] = '4';
      else if (COMPARE('J', 'Y', 'm', 'l', '$', '>')) string[a] = '5';
      else if (COMPARE('C', 'N', 'u', 'v', '(', '[')) string[a] = '6';
      else if (COMPARE('W', 'V', 'c', 'd', '+', '!')) string[a] = '7';
      else if (COMPARE('G', 'P', 'w', 'x', '{', '~')) string[a] = '8';
      else if (COMPARE('X', 'Z', 'g', 'h', '=', '<')) string[a] = '9';
   }

   // Parseia string...
   for (a = 0; string[a] != '\0' ; a++)
   {
      if (a == 4)
      {
         temporary_a[a] = '\0';
         break;
      }
      temporary_a[a] = string[a];
   }
   temporary_a[a] = '\0';

   for (a = strlen(string) - 4, b = 0; string[a] != '\0' ; a++, b++)
   {
      temporary_b[b] = string[a];
   }
   temporary_b[b] = '\0';

   memset(temporary_c, 0x00, length);
   snprintf(temporary_c, length - 1, "%s%s", temporary_b, temporary_a);
   global_key = (int)strtol(temporary_c, (char **)0, 10);

   for (a = 4, b = 0; a < (int)(strlen(string) - 4); a++, b++)
   {
      string[b] = string[a];
   }
   string[b] = '\0';

   // Decoda string...
   for (a = 0, b = 0, d = 0, e = 0, c = strlen(string); a <= c; ++a)
   {
      if (isalpha(string[a])) ca = string[a];

      else if (isdigit(string[a]))
      {
         cb = string + a;
         cd = NULL;
         key = strtol(cb, &cd, 10);

         if (ca == 'M')
         {
            e = global_key - key;
            global_key = e;
            temporary_a[d] = e;
            d++;
         }
         else if (ca == 'D')
         {
            e = global_key + key;
            global_key = e;
            temporary_a[d] = e;
            d++;
         }
         else if (ca == 'R')
         {
            temporary_a[d] = e;
            d++;
         }
         a += cd - cb - 1;
      }
   }

   strcpy(string, temporary_a);

   result = True;
   free(temporary_a);
   free(temporary_b);
   free(temporary_c);
   return result;
}

std::vector<std::string> split(std::string s, std::string delimiter) {
    size_t pos_start = 0, pos_end, delim_len = delimiter.length();
    std::string token;
    std::vector<std::string> res;
    while ((pos_end = s.find (delimiter, pos_start)) != std::string::npos) {
        token = s.substr (pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_len;
        res.push_back (token);
    }
    res.push_back (s.substr (pos_start));
    return res;
}

int KeyGenTester(const char* key, const char* iv) {
#if 0
    char user[256] = "LgOKEmGKXMGrBDFDXoWDFrEqXDFTENLDFDFDFDFDFDFDFDFDFoWDFoODWoFoJDQoLoLoFDXoWDLDLoCDQDQoLoLRLDLmGKX";
    str_decrypt(user);
    NSString* cdkey = [NSString stringWithUTF8String:user];
    NSArray* cdkeys = [cdkey componentsSeparatedByString:@":"];
    check_user(((NSString*)cdkeys[0]).UTF8String, ((NSString*)cdkeys[1]).UTF8String, ((NSString*)cdkeys[2]).UTF8String);
    check_user("dengtao123456789", "3418726421", "3571597557");
#endif
    bool is_activated = false;
    char user_key[4096] = {0};
    size_t key_len = (size_t)strlen(key);
    if (key_len > 4096 || key_len == 0) {
        return is_activated;
    }
    strncpy(user_key, key, key_len);
    str_decrypt(user_key);

    std::string str = user_key;
    std::string delimiter = ":";
    std::vector<std::string> cdkeys = split (str, delimiter);
    if (cdkeys.size() == 3) {
        if (is_activated == false) {
            if(check_user(cdkeys[0].c_str(), cdkeys[1].c_str(), cdkeys[2].c_str(), iv)) {
                is_activated = true;
            }
        }
    }
    return is_activated;
}
