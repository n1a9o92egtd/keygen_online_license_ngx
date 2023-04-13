
#pragma comment(lib, "Shlwapi.lib")

/* Definições */
#define CRYPTOX_ERROR              1
#define CRYPTOX_ERROR_SUCCESS      0

#define True                       0
#define False                      1

#define nil                        NULL

#ifndef MAX_PATH
#define MAX_PATH 256
#endif

/* Windows headers */
// #include <Windows.h>
// #include <Shlwapi.h>
#include <stdio.h>
#include <string.h>

void dbg(const char * format, ...);
