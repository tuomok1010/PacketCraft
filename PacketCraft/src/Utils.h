#ifndef PC_UTILS_H
#define PC_UTILS_H

#include "PCTypes.h"

#ifdef DEBUG_BUILD
#define LOG_ERROR(errorCode, msg) PacketCraft::PrintError((errorCode), (__PRETTY_FUNCTION__), (msg))
#else
    #define LOG_ERROR(errorCode, msg)
#endif

#define BIT_CHECK(value, nthBit) PacketCraft::CheckBit((value), (nthBit))

namespace PacketCraft
{
    // String utils
    // returns the number of characters in str, excluding the null terminating character
    int GetStrLen(const char* str);

    void CopyStr(char* dest, size_t destSize, const char* src);

    // copies characters from src to dst until a delimiter character in src is found, if no delimiter is found it copies the entire string
    void CopyStrUntil(char* dst, size_t destSize, const char* src, const char delimiter);

    void ConcatStr(char* dst, size_t destSize, const char* str1, const char* str2);

    bool32 CompareStr(const char* str1, const char* str2);

    // If pattern string is found in str, returns the index. If it is not found returns -1
    int FindInStr(const char* str, const char* pattern);
    ////////////////


    // Debug utils
    void PrintError(const int errorCode, const char* func, const char* msg);

    // Other
    bool32 CheckBit(const int val, const int nthBit);

}

#endif