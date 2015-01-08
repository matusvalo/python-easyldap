from ctypes import *
from . import lib_ldap

ldap_err2string = lib_ldap.ldap_err2string
ldap_err2string.restype = c_char_p
ldap_err2string.argtypes = [c_int]


class LdapError(Exception):

    def __init__(self, errno=None):
        self.errno = errno

    def __str__(self):
        if self.errno is not None:
            a = ldap_err2string(c_int(self.errno))
            return '{} (Error Code {})'.format(a.decode('utf8'), self.errno)
        else:
            return ''

    @classmethod
    def create_error(cls, errno):
        if errno in LDAP_ATTR_ERROR:
            return LdapAttrError(errno)
        elif errno in LDAP_NAME_ERROR:
            return LdapNameError(errno)
        elif errno in LDAP_SECURITY_ERROR:
            return LdapSecurityError(errno)
        elif errno in LDAP_SERVICE_ERROR:
            return LdapServiceError(errno)
        elif errno in LDAP_UPDATE_ERROR:
            return LdapUpdateError(errno)
        elif errno in LDAP_E_ERROR:
            return LdapEError(errno)
        else:
            return LdapError(errno)


class LdapAttrError(LdapError):
    pass


class LdapNameError(LdapError):
    pass


class LdapSecurityError(LdapError):
    pass


class LdapServiceError(LdapError):
    pass


class LdapUpdateError(LdapError):
    pass


class LdapEError(LdapError):
    pass


class URLError(Exception):
    def __init__(self, errno=None):
        self.errno = errno

    #TODO: __str__()

######################
#### Return Codes ####
######################

LDAP_SUCCESS = 0x00

LDAP_OPERATIONS_ERROR = 0x01
LDAP_PROTOCOL_ERROR	 = 0x02
LDAP_TIMELIMIT_EXCEEDED = 0x03
LDAP_SIZELIMIT_EXCEEDED = 0x04
LDAP_COMPARE_FALSE = 0x05
LDAP_COMPARE_TRUE = 0x06
LDAP_AUTH_METHOD_NOT_SUPPORTED = 0x07
LDAP_STRONG_AUTH_NOT_SUPPORTED = LDAP_AUTH_METHOD_NOT_SUPPORTED
LDAP_STRONG_AUTH_REQUIRED = 0x08
LDAP_STRONGER_AUTH_REQUIRED	= LDAP_STRONG_AUTH_REQUIRED
LDAP_PARTIAL_RESULTS = 0x09	                                 # LDAPv2+ (not LDAPv3)

LDAP_REFERRAL = 0x0a                                         # LDAPv3
LDAP_ADMINLIMIT_EXCEEDED = 0x0b                              # LDAPv3
LDAP_UNAVAILABLE_CRITICAL_EXTENSION = 0x0c                   # LDAPv3
LDAP_CONFIDENTIALITY_REQUIRED = 0x0d                         # LDAPv3
LDAP_SASL_BIND_IN_PROGRESS = 0x0e                            # LDAPv3

# LDAP Attributes Errors (0x10 - 0x15)

LDAP_NO_SUCH_ATTRIBUTE = 0x10
LDAP_UNDEFINED_TYPE = 0x11
LDAP_INAPPROPRIATE_MATCHING = 0x12
LDAP_CONSTRAINT_VIOLATION = 0x13
LDAP_TYPE_OR_VALUE_EXISTS = 0x14
LDAP_INVALID_SYNTAX = 0x15

LDAP_ATTR_ERROR = {
    LDAP_NO_SUCH_ATTRIBUTE,
    LDAP_UNDEFINED_TYPE,
    LDAP_INAPPROPRIATE_MATCHING,
    LDAP_CONSTRAINT_VIOLATION,
    LDAP_TYPE_OR_VALUE_EXISTS,
    LDAP_INVALID_SYNTAX
}

# LDAP Name Errors (0x20 - 0x24)

LDAP_NO_SUCH_OBJECT = 0x20
LDAP_ALIAS_PROBLEM = 0x21
LDAP_INVALID_DN_SYNTAX = 0x22
LDAP_IS_LEAF = 0x23                                          # not LDAPv3
LDAP_ALIAS_DEREF_PROBLEM = 0x24

LDAP_NAME_ERROR = {
    LDAP_NO_SUCH_OBJECT,
    LDAP_ALIAS_PROBLEM,
    LDAP_INVALID_DN_SYNTAX,
    LDAP_IS_LEAF,
    LDAP_ALIAS_DEREF_PROBLEM
}

# LDAP Security Errors	(0x2F - 0x32)

LDAP_X_PROXY_AUTHZ_FAILURE = 0x2F                            # LDAPv3 proxy authorization
LDAP_INAPPROPRIATE_AUTH	= 0x30
LDAP_INVALID_CREDENTIALS = 0x31
LDAP_INSUFFICIENT_ACCESS = 0x32

LDAP_SECURITY_ERROR = {
    LDAP_X_PROXY_AUTHZ_FAILURE,
    LDAP_INAPPROPRIATE_AUTH,
    LDAP_INVALID_CREDENTIALS,
    LDAP_INSUFFICIENT_ACCESS,
}


# LDAP Service Error    (0x33 - 0x36)

LDAP_BUSY = 0x33
LDAP_UNAVAILABLE = 0x34
LDAP_UNWILLING_TO_PERFORM = 0x35
LDAP_LOOP_DETECT = 0x36

LDAP_SERVICE_ERROR = {
    LDAP_BUSY,
    LDAP_UNAVAILABLE,
    LDAP_UNWILLING_TO_PERFORM,
    LDAP_LOOP_DETECT,
}

# LDAP Update Error	(0x40 - 0x47)

LDAP_NAMING_VIOLATION = 0x40
LDAP_OBJECT_CLASS_VIOLATION = 0x41
LDAP_NOT_ALLOWED_ON_NONLEAF = 0x42
LDAP_NOT_ALLOWED_ON_RDN	= 0x43
LDAP_ALREADY_EXISTS = 0x44
LDAP_NO_OBJECT_CLASS_MODS = 0x45
LDAP_RESULTS_TOO_LARGE = 0x46                   # CLDAP
LDAP_AFFECTS_MULTIPLE_DSAS = 0x47

LDAP_UPDATE_ERROR = {
    LDAP_NAMING_VIOLATION,
    LDAP_OBJECT_CLASS_VIOLATION,
    LDAP_NOT_ALLOWED_ON_NONLEAF,
    LDAP_NOT_ALLOWED_ON_RDN,
    LDAP_ALREADY_EXISTS,
    LDAP_NO_OBJECT_CLASS_MODS,
    LDAP_RESULTS_TOO_LARGE,
    LDAP_AFFECTS_MULTIPLE_DSAS,
}

LDAP_VLV_ERROR = 0x4C

LDAP_OTHER = 0x50

#### LCUP operation codes (113-117) - not implemented ####

LDAP_CUP_RESOURCES_EXHAUSTED = 0x71
LDAP_CUP_SECURITY_VIOLATION	= 0x72
LDAP_CUP_INVALID_DATA = 0x73
LDAP_CUP_UNSUPPORTED_SCHEME = 0x74
LDAP_CUP_RELOAD_REQUIRED = 0x75

#### Cancel operation codes (118-121) ####

LDAP_CANCELLED = 0x77
LDAP_NO_SUCH_OPERATION = 0x77
LDAP_TOO_LATE = 0x78
LDAP_CANNOT_CANCEL = 0x79

#### Assertion control (122) ####

LDAP_ASSERTION_FAILED = 0x7A

#### Proxied Authorization Denied (123) ####

LDAP_PROXIED_AUTHORIZATION_DENIED = 0x7B

#### Experimental result codes ####

# LDAP E Error	(0x1000 - 0x3FFF)
LDAP_E_ERROR = set(range(0x1000, 0x3FFF + 1))

#### LDAP Sync (4096) ####

LDAP_SYNC_REFRESH_REQUIRED = 0x1000

### URL Error codes ###
LDAP_URL_SUCCESS = 0x00             # Success
LDAP_URL_ERR_MEM = 0x01             # can't allocate memory space
LDAP_URL_ERR_PARAM = 0x02           # parameter is bad
LDAP_URL_ERR_BADSCHEME = 0x03	    # URL doesn't begin with "ldap[si]://"
LDAP_URL_ERR_BADENCLOSURE = 0x04	# URL is missing trailing ">"
LDAP_URL_ERR_BADURL = 0x05	        # URL is bad
LDAP_URL_ERR_BADHOST = 0x06	        # host port is bad
LDAP_URL_ERR_BADATTRS = 0x07        # bad (or missing) attributes
LDAP_URL_ERR_BADSCOPE = 0x08        # scope string is invalid (or missing)
LDAP_URL_ERR_BADFILTER = 0x09       # bad or missing filter
LDAP_URL_ERR_BADEXTS = 0x0a         # bad or missing extensions
