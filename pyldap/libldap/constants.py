from ctypes import *

LDAP_VERSION1 = c_int(1)
LDAP_VERSION2 = c_int(2)
LDAP_VERSION3 = c_int(3)

LDAP_VERSIONS = {
    1: LDAP_VERSION1,
    2: LDAP_VERSION2,
    3: LDAP_VERSION3,
}

SCOPES = {
    'LDAP_SCOPE_BASE': 0x0000,
    'LDAP_SCOPE_ONELEVEL': 0x0001,
    'LDAP_SCOPE_SUBTREE': 0x0002,
    'LDAP_SCOPE_SUBORDINATE': 0x0003,     # OpenLDAP extension
    'LDAP_SCOPE_DEFAULT': -1	          # OpenLDAP extension
}
SCOPES['LDAP_SCOPE_BASEOBJECT'] = SCOPES['LDAP_SCOPE_BASE']
SCOPES['LDAP_SCOPE_ONE'] = SCOPES['LDAP_SCOPE_ONELEVEL']
SCOPES['LDAP_SCOPE_SUB'] = SCOPES['LDAP_SCOPE_SUBTREE']
SCOPES['LDAP_SCOPE_CHILDREN'] = SCOPES['LDAP_SCOPE_SUBORDINATE']   # OpenLDAP extension
SCOPES['base'] = SCOPES['LDAP_SCOPE_BASE']
SCOPES['one'] = SCOPES['LDAP_SCOPE_ONELEVEL']
SCOPES['sub'] = SCOPES['LDAP_SCOPE_SUBTREE']

######################
#### Option Codes ####
######################

# LDAP_OPTions
# 0x0000 - 0x0fff reserved for api options
# 0x1000 - 0x3fff reserved for api extended options
# 0x4000 - 0x7fff reserved for private and experimental options
# /
#
LDAP_OPT_API_INFO = c_int(0x0000)
LDAP_OPT_DESC = c_int(0x0001)                          # historic
LDAP_OPT_DEREF = c_int(0x0002)
LDAP_OPT_SIZELIMIT = c_int(0x0003)
LDAP_OPT_TIMELIMIT = c_int(0x0004)
# 0x05 - 0x07 not defined
LDAP_OPT_REFERRALS = c_int(0x0008)
LDAP_OPT_RESTART = c_int(0x0009)
# 0x0a - 0x10 not defined
LDAP_OPT_PROTOCOL_VERSION = c_int(0x0011)
LDAP_OPT_SERVER_CONTROLS = c_int(0x0012)
LDAP_OPT_CLIENT_CONTROLS = c_int(0x0013)
# 0x14 not defined
LDAP_OPT_API_FEATURE_INFO = c_int(0x0015)
# 0x16 - 0x2f not defined
LDAP_OPT_HOST_NAME = c_int(0x0030)
LDAP_OPT_RESULT_CODE = c_int(0x0031)
LDAP_OPT_ERROR_NUMBER = LDAP_OPT_RESULT_CODE
LDAP_OPT_DIAGNOSTIC_MESSAGE = c_int(0x0032)
LDAP_OPT_ERROR_STRING = LDAP_OPT_DIAGNOSTIC_MESSAGE
LDAP_OPT_MATCHED_DN = c_int(0x0033)
# 0x0034 - 0x3fff not defined
# 0x0091 used by Microsoft for LDAP_OPT_AUTO_RECONNECT
LDAP_OPT_SSPI_FLAGS = c_int(0x0092)
# 0x0093 used by Microsoft for LDAP_OPT_SSL_INFO
# 0x0094 used by Microsoft for LDAP_OPT_REF_DEREF_CONN_PER_MSG
LDAP_OPT_SIGN = c_int(0x0095)
LDAP_OPT_ENCRYPT = c_int(0x0096)
LDAP_OPT_SASL_METHOD = c_int(0x0097)
#0x0098 used by Microsoft for LDAP_OPT_AREC_EXCLUSIVE
LDAP_OPT_SECURITY_CONTEXT = c_int(0x0099)
# 0x009A used by Microsoft for LDAP_OPT_ROOTDSE_CACHE
# 0x009B - 0x3fff not defined

# API Extensions
LDAP_OPT_API_EXTENSION_BASE = c_int(0x4000)                # API extensions
