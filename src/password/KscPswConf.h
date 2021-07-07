#ifndef CKSCPSWCONF_H
#define CKSCPSWCONF_H

#include "ksc_comdef.h"
#include <stdio.h>
#include <string.h>

class CKscPswConf
{
public:
    CKscPswConf();
    virtual ~CKscPswConf();

    int get_psw_mode(int & strmode);
    int set_psw_mode(int strmode);

private:

};

#endif // CKSCPSWCONF_H
