#ifndef __ERRORS_H__
#define __ERRORS_H__

enum error_codes
{
    ERROR_NONE,

    ERROR_PAIRING_NOT_INITIALIZED,
    ERROR_PAIRING_IS_SYMMETRIC,

    ERROR_QKEY_NOT_INITIALIZED,
    ERROR_MSKEY_NOT_INITIALIZED,

    ERROR_DSTLEN_INVALID,

    ERROR_NULL_POINTER,

    ERROR_PARAMS_MISMATCH,

    ERROR_CTXT_NOT_INITIALIZED,
    ERROR_TOKEN_NOT_INITIALIZED,
};

#endif /* __ERRORS_H__ */