#include "KscStringConvert.h"

CKscStringConvert::CKscStringConvert()
{

}

CKscStringConvert::~CKscStringConvert()
{

}
CKscStringConvert *CKscStringConvert::get_instance()
{
    static CKscStringConvert * m_pInstance = nullptr;
    if (!m_pInstance)
    {
        m_pInstance = new CKscStringConvert();
    }
    return m_pInstance;
}

bool CKscStringConvert::is_exist(const std::string &s, const char *str2)
{
    if(str2 == nullptr)
    {
        return false;
    }

    size_t size = s.find("#");
    std::string temp;

    if(size == std::string::npos)
    {
        temp = s;
    }
    else
    {
        temp = s.substr(0, size);
    }

    size = temp.find(str2);
    if(size == std::string::npos)
    {
        return false;
    }

    return true;
}

bool CKscStringConvert::contains(const std::string &str1, const char *str2)
{
    if(str2 == nullptr)
    {
        return false;
    }

    size_t cur = str1.find(str2);
    if(cur != std::string::npos)
    {
        return true;
    }

    return false;
}

bool CKscStringConvert::is_start_with(const std::string &str1, const std::string &startstr)
{
    int pos = str1.find(startstr);
    if(pos != std::string::npos)
    {
        return true;
    }

    return false;
}

void CKscStringConvert::trimmed(std::string &s)
{
    int iSize = 0;
    int i = 0;
    int iCur = 0;

    for(i = 0; i < s.size(); i++)
    {
        if(s[i] == ' ')
        {
            iSize++;
            continue;
        }
        break;
    }

    for(i = iSize; i < s.size(); i++, iCur++)
    {
        s[iCur] = s[i];
    }

    s.resize(s.size() - iSize); //剔除掉最后的部分
}

void CKscStringConvert::get_str_number(const std::string &str,  std::string& strnum)
{
    int iSize = 0;
    for(int i = 0; i < str.size(); i++)
    {
        if(str[i] >= '0' && str[i] <= '9')
        {
            iSize = i;
            break;
        }
    }

    for(int i = iSize; i < str.size(); i++)
    {
        if(str[i] >= '0' && str[i] <= '9')
        {
            strnum += str[iSize];
        }
    }
}

int CKscStringConvert::get_str_int(std::string &str1, const char *str2)
{
    if(str2 == nullptr)
    {
        return 0;
    }

    size_t start = 0;
    size_t size = 0;
    std::string temp;
    start = str1.find(str2);
    if(start == std::string::npos)
    {
        return 0;
    }

    start = start + strlen(str2);
    while(start < str1.size())
    {
        if(str1[start] >= '0' && str1[start] <= '9')
        {
            size++;
            start++;
            continue;
        }

        break;
    }

    temp = str1.substr(start - size, size);
    return  atoi(temp.c_str());
}

void CKscStringConvert::del_str_for_it(std::string &str, const char *it)
{
    if(it == nullptr)
    {
        return ;
    }

    int len = strlen(it);
    if(len == 0)
    {
        return ;
    }

    while(1)
    {
        size_t start = str.find(it);
        if(start == std::string::npos)
        {
        break ;
    }

        for(size_t i = start + len ; i < str.size(); i++, start++)
        {
            str[start] = str[i];
        }

        str.resize(str.size() - len);
    }
}

std::string CKscStringConvert::replace_char(const std::string& s, char preletter, char letter)
{
    std::string str;
    for(int i = 0 ; i < s.size(); i++)
    {
        if(preletter == s[i])
        {
            str.push_back(letter);
        }
        else
        {
            str.push_back(s[i]);
        }
    }

    return str;
}

void CKscStringConvert::replace_str(std::string &str, const char *prestr, const std::string& posstr)
{
    if(prestr == nullptr)
    {
        return;
    }

    int len = strlen(prestr);
    if(len == 0)
    {
        return;
    }

    int lenpos = posstr.size();

    while(1)
    {
        size_t start = str.find(prestr);
        if(start == std::string::npos)
        {
            break;
        }

        for(size_t i = start + len ; i < str.size(); i++, start++){
            for(size_t j = 0 ; j< lenpos; j++)
            {
                str[start] = posstr[j];
                start++;
            }
        }

        str.resize(str.size() - len);
    }
}

std::string CKscStringConvert::del_char(const std::string &s, char letter)
{
    std::string str;
    for(int i = 0 ; i < s.size(); i++)
    {
        if(letter != s[i])
        {
            str.push_back(s[i]);
        }
    }

    return str;
}

void CKscStringConvert::rep_sub_str(std::string &str,const std::string &sub, const std::string &repstr)
{
    int pos = 0, flag = 0;
    int subsize = sub.length();
    while(flag == 0)
    {
        pos = str.find(sub);
        if(pos != std::string::npos)
        {
            str.replace(pos, subsize,repstr);
        }
        else
        {
            flag = 1;
        }
    }
}

void CKscStringConvert::del_sub_str(std::string &str, const std::string &sub)
{
    int pos = 0, flag = 0;
    int subsize = sub.length();
    while(flag == 0)
    {
        pos = str.find(sub);
        if(pos != std::string::npos)
        {
            str.erase(pos, subsize);
        }
        else
        {
            flag = 1;
        }
    }
}

