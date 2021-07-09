#ifndef CKSCSTRINGCONVERT_H
#define CKSCSTRINGCONVERT_H

#include "ksc_comdef.h"
#include "ksc_error.h"
#include <fstream>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>

class CKscStringConvert
{
public:
    static CKscStringConvert *get_instance();
    CKscStringConvert();
    virtual ~CKscStringConvert();

public:
    bool is_exist(const std::string& s, const char* str2);

    /*
     * @brief str1包含str2返回 true 否则返回flase
     *
     */
    bool contains(const std::string& str1, const char* str2);

    bool is_start_with(const std::string &str1, const std::string &startstr);

    void trimmed(std::string& s);

    void get_str_number(const std::string& str, std::string& strnum);
    /*
     * @brief
     * 返回str1中第一个str2后整数的值
     * 没有找到返回0
     */
    int get_str_int(std::string& str1, const char *str2);

    void del_str_for_it(std::string &str, const char* it);

    std::string del_char(const std::string& s, char letter);

    void del_sub_str(std::string &str,const std::string &sub);

    //void del_strSpace(string &str);

    void rep_sub_str(std::string &str,const std::string &sub,const std::string &repstr);

    std::string replace_char(const std::string& s, char preletter, char letter);

    void replace_str(std::string& str, const char *prestr, const std::string& posstr);
};

#endif // CKSCSTRINGCONVERT_H
