from .libldap.structures import LDAPMod

def is_iterable(obj):
    from collections import Iterable
    return not (isinstance(obj, str) or isinstance(obj, bytes)) and isinstance(obj, Iterable)


def is_ascii(s):
    if isinstance(s, bytes):
        return all(c < 128 for c in s)
    else:
        return all(ord(c) < 128 for c in s)


def ldap_encode(s):
    import base64
    if isinstance(s, str):
        if is_ascii(s):
            return s.encode('utf8')
        else:
            return base64.b64encode(s.encode('utf8'))
    elif isinstance(s, bytes):
        if is_ascii(s):
            return s
        else:
            return base64.b64encode(s)


def build_binary_ldapmod(battr_name, op, vals):
    if is_iterable(vals):
        mod = LDAPMod.create_binary(op | LDAPMod.LDAP_MOD_BVALUES,
                                    ldap_encode(battr_name),
                                    values=map(lambda a: ldap_encode(a), vals))
    else:
        mod = LDAPMod.create_binary(op | LDAPMod.LDAP_MOD_BVALUES,
                                    ldap_encode(battr_name),
                                    values=ldap_encode(vals))
    return mod

def build_ascii_ldapmod(attr_name, op, vals):
    if is_iterable(vals):
        mod = LDAPMod.create_string(op,
                                    ldap_encode(attr_name),
                                    values=map(lambda a: ldap_encode(a),vals))
    else:
        mod = LDAPMod.create_string(op,
                                    ldap_encode(attr_name),
                                    values=ldap_encode(vals))
    return mod
