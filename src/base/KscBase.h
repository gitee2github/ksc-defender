#ifndef KSC_BASE_H
#define KSC_BASE_H

#include "ksc_comdef.h"
#include "ksc_error.h"

#define emit_try_help() \
  do \
    { \
      fprintf (stderr, _("Try '%s --help' for more information.\n"), \
               program_name); \
    } \
  while (0)

class CKscBase
{

public:
    virtual int handle_options(int argc, char **argv) = 0;
};

#endif // end KSC_BASE_H
