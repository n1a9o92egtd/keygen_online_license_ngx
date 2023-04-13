#include <iostream>
#include <stdlib.h>
#include <string.h>
#include "cpu.h"
#include "keygenme.h"
using namespace std;
typedef unsigned int uint;
typedef unsigned char uchar;
void printusage(char*);
void printconstraints(char*);
bool check(uint, uint, uint, uint, uint);

bool KeyValidImpl(const char* pusername, uint tok1, uint tok2, uint iv) {
    int namelen = strlen(pusername);
    if(namelen < 16) {
//        printconstraints(argv[1]);
//        exit(1);
        return false;
    }
//    int tok1 = strtoul(argv[2], NULL, 0);
//    int tok2 = strtoul(argv[3], NULL, 0);
    std::string username(pusername);
    std::string fullkey = std::string(username.rbegin(), username.rend());
    cpu* libdrm = new cpu("000048202129009E00094a002129003700094a002129007900094a00212900b900005020000040208c1800088C17000C8C1600108c0b00148c0f00008c0e000401094020000ea1000298a02001c89820000e914202579020027288260234882601f17820000fa1000296a02001e89820000f9142024b9020027288260234882601d1702020100020214a000115500010", username, fullkey);
    libdrm->Execute();
    uint t6 = libdrm->GetT6();
    uint t7 = libdrm->GetT7();
    delete libdrm;
    if(check(t6, t7, tok1, tok2, iv)) {
//        std::cout << "*<:-)" << std::endl;
        return true;
    }
    else {
//        std::cout << ":-(" << std::endl;
        return false;
    }
//    return 0;
}

bool check_user(const char* pusername, const char* tok1, const char* tok2, const char* iv) {
    return KeyValidImpl(pusername, (uint)atoi(tok1), (uint)atoi(tok2), (uint)atoi(iv));
}
//int main(int argc, char** argv)
//{
//	if(argc < 4)
//	{
//		printusage(argv[0]);
//		exit(1);
//	}
//	int namelen = strlen(argv[1]);
//	if(namelen < 16)
//	{
//		printconstraints(argv[1]);
//		exit(1);
//	}
//	int tok1 = strtoul(argv[2], NULL, 0);
//	int tok2 = strtoul(argv[3], NULL, 0);
//	std::string username(argv[1]);
//	std::string fullkey = std::string(username.rbegin(), username.rend());
//	cpu* libdrm = new cpu("000048202129009E00094a002129003700094a002129007900094a00212900b900005020000040208c1800088C17000C8C1600108c0b00148c0f00008c0e000401094020000ea1000298a02001c89820000e914202579020027288260234882601f17820000fa1000296a02001e89820000f9142024b9020027288260234882601d1702020100020214a000115500010", username, fullkey);
//	libdrm->Execute();
//	uint t6 = libdrm->GetT6();
//	uint t7 = libdrm->GetT7();
//	delete libdrm;
//	if(check(t6, t7, tok1, tok2))
//	{
//		std::cout << "*<:-)" << std::endl;
//	}
//	else
//	{
//		std::cout << ":-(" << std::endl;
//	}
//	return 0;
//}

bool check(uint t6, uint t7, uint tok1, uint tok2, uint iv) {
	// uint temp1 = tok1 ^ 0x12345678;
    uint temp1 = tok1 ^ iv;
	uchar ch1 = ((tok2 & 0xFF000000) >> 24);
	uchar ch2 = ((tok2 & 0x00FF0000) >> 16);
	uchar ch3 = ((tok2 & 0x0000FF00) >> 8);
	uchar ch4 = (tok2 & 0x000000FF);
	uint temp2 = ch2 << 24;
	temp2 |= (ch3 << 16);
	temp2 |= (ch1 << 8);
	temp2 |= (ch4);
	if(t6 == temp1 && t7 == temp2)
	{
		return true;
	}
	return false;
}

//void printusage(char* progname)
//{
//	std::cout << "usage: " << progname << " <username> <token 1> <token 2>" << std::endl;
//}
//
//void printconstraints(char* username)
//{
//	std::cout << "error: " << username << " is not a valid username" << std::endl;
//}
//
