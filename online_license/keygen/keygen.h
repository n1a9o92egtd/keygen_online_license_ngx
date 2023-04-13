#ifndef KEYGEN_H_
#define KEYGEN_H_

#ifdef __cplusplus
extern "C"
#endif

int LicenseGen(const char* user, char* license, char* license_iv);

#endif