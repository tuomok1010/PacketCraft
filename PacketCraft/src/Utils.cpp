#include "Utils.h"

#include <iostream>

// General utils
int PacketCraft::GetStrLen(const char* str)
{
    int counter{};
    while(str[counter++] != '\0')
        continue;
    return counter -1;
}

void PacketCraft::CopyStr(char* dest, size_t destSize, const char* src)
{
    for(size_t i = 0; i < destSize; ++i)
    {
        dest[i] = src[i];
        if(src[i] == '\0')
            break;
    }
}

void PacketCraft::CopyStrUntil(char* dst, size_t destSize, const char* src, const char delimiter)
{
    for(size_t i = 0; i < destSize; ++i)
    {
        dst[i] = src[i];
        if(src[i] == '\0' || src[i] == delimiter)
        {
            dst[i + 1] = '\0';
            break;
        }
    }
}

void PacketCraft::ConcatStr(char* dst, size_t destSize, const char* str1, const char* str2)
{
    unsigned int str1EndIndex{0};

    // copy string 1
    for(size_t i = 0; i < destSize; ++i)
    {
        dst[i] = str1[i];
        if(str1[i] == '\0')
        {
            str1EndIndex = i;
            break;
        }
    }

    // copy string 2
    for(size_t i = str1EndIndex, j = 0; i < destSize; ++i, ++j)
    {
        dst[i] = str2[j];
        if(str2[j] == '\0')
            break;
    }
}

bool32 PacketCraft::CompareStr(const char* str1, const char* str2)
{
    while((*str1 == *str2))
    {
        if(*str1 == '\0')
            return TRUE;

        ++str1;
        ++str2;
    }

    return FALSE;
}

int PacketCraft::FindInStr(const char* str, const char* pattern)
{
    int foundIndex{0};
    while(*str != '\0')
    {
        const char* c1 = str;
        const char* c2 = pattern;

        while(*c1 == *c2)
        {
            ++c1;
            ++c2;

            if(*c2 == '\0')
            {
                return foundIndex;
            }
        }
        ++str;
        ++foundIndex;
    }
    return -1;
}

// Debug utils
void PacketCraft::PrintError(const int errorCode, const char* func, const char* msg)
{
    switch(errorCode)
    {
        case APPLICATION_ERROR:
        {
            std::cerr << "APPLICATION ERROR in function: " << func << ". Error message: " << msg << std::endl;
        } break;
        case APPLICATION_WARNING:
        {
            std::cerr << "APPLICATION WARNING in function: " << func << ". Error message: " << msg << std::endl;
        } break;
        default:
        {
            std::cerr << "UNKNOWN ERROR in function: " << func << ". Error message: " << msg << std::endl;
        }
    }
}

bool32 PacketCraft::CheckBit(const int val, const int nthBit)
{
    return ((val) & (1 << (nthBit - 1))) != 0 ? TRUE : FALSE;
}