#ifndef __KEYGENME__
#define __KEYGENME__

#ifdef __cplusplus
extern "C" {
#endif

bool check_user(const char* pusername, const char* tok1, const char* tok2, const char* iv);

#ifdef __cplusplus
};
#endif

#endif
