from contextlib import contextmanager
from .tools import iterate_array
from .structures import *
from .constants import *
from . import lib_ldap
from .ldapexception import LDAP_SUCCESS, LdapError, URLError, LDAP_COMPARE_FALSE, LDAP_COMPARE_TRUE


def _ldap_compare_check(result, func, args):
    if result == LDAP_COMPARE_TRUE:
        return True
    elif result == LDAP_COMPARE_FALSE:
        return False
    else:
        raise URLError(result)


def _url_result_check(result, func, args):
    if result != 0:
        raise URLError(result)
    return result


def _ldap_result_check(result, func, args):
    if result != LDAP_SUCCESS:
        raise LdapError.create_error(result)
    return result


def _ldap_result_null_check(result, func, args):
    if result is None:
        raise LdapError()
    return result


def _ldap_result_negative_check(result, func, args):
    if result == -1:
        raise LdapError()
    return result


def _ldap_result_bool_map(result, func, args):
    if result > 0:
        return True
    else:
        return False


ldap_set_option = lib_ldap.ldap_set_option
ldap_set_option.restype = c_int
ldap_set_option.argtypes = [POINTER(LDAP), c_int, c_void_p]
ldap_set_option.errcheck = _ldap_result_check

ldap_get_option = lib_ldap.ldap_get_option
ldap_get_option.restype = c_int
ldap_get_option.argtypes = [POINTER(LDAP), c_int, c_void_p]
ldap_get_option.errcheck = _ldap_result_check

_ldap_initialize = lib_ldap.ldap_initialize
_ldap_initialize.argtypes = [POINTER(POINTER(LDAP)), c_char_p]
_ldap_initialize.restype = c_int
_ldap_initialize.errcheck = _ldap_result_check


def ldap_initialize(uri):
    ldap = POINTER(LDAP)()
    _ldap_initialize(byref(ldap), uri)
    return ldap


ldap_simple_bind_s = lib_ldap.ldap_simple_bind_s
ldap_simple_bind_s.restype = c_int
ldap_simple_bind_s.argtypes = [POINTER(LDAP), c_char_p, c_char_p]
ldap_simple_bind_s.errcheck = _ldap_result_check

ldap_unbind = lib_ldap.ldap_unbind
ldap_unbind.restype = c_int
ldap_unbind.argtypes = [POINTER(LDAP)]
ldap_unbind.errcheck = _ldap_result_check

ldap_unbind_s = ldap_unbind

_ldap_search_ext_s = lib_ldap.ldap_search_ext_s
_ldap_search_ext_s.restype = c_int
_ldap_search_ext_s.argtypes = [POINTER(LDAP),
                               c_char_p,
                               c_int,
                               c_char_p,
                               POINTER(POINTER(c_char_p)),
                               c_int,
                               POINTER(POINTER(LDAPControl)),
                               POINTER(POINTER(LDAPControl)),
                               POINTER(Timeval),
                               c_int,
                               POINTER(POINTER(LDAPMessage))]
_ldap_search_ext_s.errcheck = _ldap_result_check


def ldap_search_ext_s(ld, base, scope, filter, attrs, attrsonly, serverctrls, clientctrls, timeout, sizelimit):
    if attrs is not None:
        attrs_array = c_char_p * len(attrs)
    if scope not in SCOPES.values():
        raise ValueError
    result = POINTER(LDAPMessage)()
    try:
        _ldap_search_ext_s(ld,
                           base,
                           scope,
                           filter,
                           None if attrs is None else byref(attrs_array(attrs)),
                           attrsonly,
                           serverctrls,
                           clientctrls,
                           timeout,
                           sizelimit,
                           byref(result))
    except LdapError as e:
        # LDAPMsg should be freed also when search failes. See Notes in  LDAP_SEARCH(3).
        ldap_msgfree(result)
        raise
    return result

ldap_msgfree = lib_ldap.ldap_msgfree
ldap_msgfree.restype = int
ldap_msgfree.argtypes = [POINTER(LDAPMessage)]


_ldap_add_ext_s = lib_ldap.ldap_add_ext_s
_ldap_add_ext_s.restype = c_int
_ldap_add_ext_s.argtypes = [POINTER(LDAP),
                            c_char_p,
                            POINTER(POINTER(LDAPMod)),
                            POINTER(LDAPControl),
                            POINTER(LDAPControl)]
_ldap_add_ext_s.errcheck = _ldap_result_check


def ldap_add_ext_s(ld, dn, attrs, sctrls, cctrls):
    attrs_p = tuple(map(lambda m: pointer(m), attrs))
    mods_array = (POINTER(LDAPMod) * (len(attrs_p) + 1))(*(attrs_p + (None,)))
    return _ldap_add_ext_s(ld, dn, mods_array, sctrls, cctrls)


ldap_delete_ext_s = lib_ldap.ldap_delete_ext_s
ldap_delete_ext_s.restype = c_int
ldap_delete_ext_s.argtypes = [POINTER(LDAP),
                              c_char_p,
                              POINTER(POINTER(LDAPControl)),
                              POINTER(POINTER(LDAPControl))]
ldap_delete_ext_s.errcheck = _ldap_result_check

_ldap_modify_ext_s = lib_ldap.ldap_modify_ext_s
_ldap_modify_ext_s.restype = c_int
_ldap_modify_ext_s.argtypes = [POINTER(LDAP),
                               c_char_p,
                               POINTER(POINTER(LDAPMod)),
                               POINTER(POINTER(LDAPControl)),
                               POINTER(POINTER(LDAPControl))]
_ldap_modify_ext_s.errcheck = _ldap_result_check


def ldap_modify_ext_s(ld, dn, mods, sctrls, cctrls):
    mods_p = tuple(map(lambda m: pointer(m), mods))
    mods_array = (POINTER(LDAPMod) * (len(mods_p) + 1))(*(mods_p + (None,)))
    return _ldap_modify_ext_s(ld, dn, mods_array, sctrls, cctrls)


ldap_compare_ext_s = lib_ldap.ldap_compare_ext_s
ldap_compare_ext_s.restype = c_int
ldap_compare_ext_s.argtypes = [POINTER(LDAP),
                               c_char_p,
                               c_char_p,
                               POINTER(BerVal),
                               POINTER(POINTER(LDAPControl)),
                               POINTER(POINTER(LDAPControl))]
ldap_compare_ext_s.errcheck = _ldap_compare_check

_ldap_rename_s = lib_ldap.ldap_rename_s
_ldap_rename_s.restype = c_int
_ldap_rename_s.argtypes = [POINTER(LDAP),
                           c_char_p,
                           c_char_p,
                           c_char_p,
                           c_int,
                           POINTER(LDAPControl),
                           POINTER(LDAPControl)]
_ldap_rename_s.errcheck = _ldap_result_negative_check


def ldap_rename_s(ld, dn, newrdn, newparent, deleteoldrdn, sctrls, cctrls):
    if deleteoldrdn:
        _ldap_rename_s(ld, dn, newrdn, newparent, 1, sctrls, cctrls)
    else:
        _ldap_rename_s(ld, dn, newrdn, newparent, 0, sctrls, cctrls)


ldap_mods_free = lib_ldap.ldap_mods_free
ldap_mods_free.restype = None
ldap_mods_free.argtypes = [POINTER(POINTER(LDAPMod)), c_int]

ldap_count_entries = lib_ldap.ldap_count_entries
ldap_count_entries.restype = c_int
ldap_count_entries.argtypes = [POINTER(LDAP), POINTER(LDAPMessage)]
ldap_count_entries.errcheck = _ldap_result_negative_check


def _ldap_entry_handler(result, func, args):
    return _ldap_result_null_check(
        cast(result, POINTER(LDAPMessage)),
        func,
        args)


ldap_first_entry = lib_ldap.ldap_first_entry
ldap_first_entry.restype = c_int
ldap_first_entry.argtypes = [POINTER(LDAP), POINTER(LDAPMessage)]
ldap_first_entry.errcheck = _ldap_entry_handler

ldap_next_entry = lib_ldap.ldap_next_entry
ldap_next_entry.restype = c_int
ldap_next_entry.argtypes = [POINTER(LDAP), POINTER(LDAPMessage)]
ldap_next_entry.errcheck = _ldap_entry_handler


def _ldap_get_dn_handler(result, func, args):
    return _ldap_result_null_check(
        cast(result, c_char_p),
        func,
        args)


ldap_get_dn = lib_ldap.ldap_get_dn
ldap_get_dn.restype = c_int
ldap_get_dn.argtypes = [POINTER(LDAP), POINTER(LDAPMessage)]
ldap_get_dn.errcheck = _ldap_get_dn_handler

_ldap_str2dn = lib_ldap.ldap_str2dn
_ldap_str2dn.restype = c_int
_ldap_str2dn.argtypes = [c_char_p, POINTER(LDAPDN), c_uint]
_ldap_str2dn.errcheck = _ldap_result_check


def ldap_str2dn(str, flags):
    ldapdn = LDAPDN()
    _ldap_str2dn(bytes(str), byref(ldapdn), flags)
    return ldapdn


_ldap_dn2str = lib_ldap.ldap_dn2str
_ldap_dn2str.restype = c_int
_ldap_dn2str.argtypes = [LDAPDN, POINTER(c_char_p), c_uint]
_ldap_dn2str.errcheck = _ldap_result_check


def ldap_dn2str(ldap_dn, flags):
    # FIXME: Free retval??
    ret_val = c_char_p()
    _ldap_dn2str(ldap_dn, byref(ret_val), flags)
    ret_str = ret_val.value
    return ret_str


ldap_dnfree = lib_ldap.ldap_dnfree
ldap_dnfree.restype = None
ldap_dnfree.argtypes = [LDAPDN]

ldap_memfree = lib_ldap.ldap_memfree
ldap_memfree.restype = None
ldap_memfree.argtypes = [c_void_p]


def _ldap_get_values_handler(result, func, args):
    return _ldap_result_null_check(cast(result, POINTER(c_char_p)),
                                   func,
                                   args)

_ldap_get_values = lib_ldap.ldap_get_values
_ldap_get_values.restype = c_int
_ldap_get_values.argtypes = [POINTER(LDAP), POINTER(LDAPMessage), c_char_p]
_ldap_get_values.errcheck = _ldap_get_values_handler


@contextmanager
def ldap_get_values(ld, entry, attr):
    ret_values = _ldap_get_values(ld, entry, attr)

    try:
        yield iterate_array(ret_values)
    finally:
        ldap_value_free(ret_values)

ldap_value_free = lib_ldap.ldap_value_free
ldap_value_free.restype = None
ldap_value_free.argtypes = [POINTER(c_char_p)]


def _ldap_get_values_len_handler(result, func, args):
    return cast(result,
                _ldap_result_null_check(POINTER(POINTER(BerVal)),
                                        func,
                                        args
                )
    )


@contextmanager
def ldap_get_values_len(ld, entry, attr):
    ret_values = _ldap_get_values_len(ld, entry, attr)

    try:
        yield iterate_array(ret_values, lambda v: v[0].value)
    finally:
        ldap_value_free_len(ret_values)


_ldap_get_values_len = lib_ldap.ldap_get_values_len
_ldap_get_values_len.restype = c_int
_ldap_get_values_len.argstypes = [POINTER(LDAP), POINTER(LDAPMessage), c_char_p]
_ldap_get_values_len.errcheck = _ldap_get_values_len_handler

ldap_value_free_len = lib_ldap.ldap_value_free_len
ldap_value_free_len.restype = None
ldap_value_free_len.argtypes = [POINTER(POINTER(BerVal))]


def _ldap_attribute_handler(result, func, args):
    return _ldap_result_null_check(cast(result, c_char_p),
                                   func,
                                   args)


_ldap_first_attribute = lib_ldap.ldap_first_attribute
_ldap_first_attribute.restype = c_int
_ldap_first_attribute.argtypes = [POINTER(LDAP), POINTER(LDAPMessage), POINTER(POINTER(BerElement))]
_ldap_first_attribute.errcheck = _ldap_attribute_handler


def ldap_first_attribute(ld, entry):
    ber = POINTER(BerElement)()
    attr = _ldap_first_attribute(ld, entry, byref(ber))
    return attr, ber


ldap_next_attribute = lib_ldap.ldap_next_attribute
ldap_next_attribute.restype = c_int
ldap_next_attribute.argtypes = [POINTER(LDAP), POINTER(LDAPMessage), POINTER(BerElement)]
ldap_next_attribute.errcheck = _ldap_attribute_handler

ber_free = lib_ldap.ber_free
ber_free.restype = None
ber_free.argtypes = [POINTER(BerElement), c_int]

ldap_is_ldap_url = lib_ldap.ldap_is_ldap_url
ldap_is_ldap_url.restype = c_int
ldap_is_ldap_url.argtypes = [c_char_p]
ldap_is_ldap_url.errcheck = _ldap_result_bool_map

_ldap_url_parse = lib_ldap.ldap_url_parse
_ldap_url_parse.restype = c_int
_ldap_url_parse.argtypes = [c_char_p, POINTER(POINTER(LDAPURLDesc))]
_ldap_url_parse.errcheck = _url_result_check


def ldap_url_parse(url):
    lud = POINTER(LDAPURLDesc)()
    _ldap_url_parse(url, byref(lud))
    return lud.contents


ldap_free_urldesc = lib_ldap.ldap_free_urldesc
ldap_free_urldesc.restype = None
ldap_free_urldesc.argtypes = [POINTER(LDAPURLDesc)]

_ldap_tls_inplace = lib_ldap.ldap_tls_inplace
_ldap_tls_inplace.restype = c_int
_ldap_tls_inplace.argtypes = [POINTER(LDAP)]


def ldap_tls_inplace(ldap):
    return True if _ldap_tls_inplace(ldap) == 1 else False


ldap_start_tls_s = lib_ldap.ldap_start_tls_s
ldap_start_tls_s.restype = c_int
ldap_start_tls_s.argtypes = [POINTER(LDAP), POINTER(POINTER(LDAPControl)), POINTER(POINTER(LDAPControl))]
ldap_start_tls_s.errcheck = _ldap_result_check
