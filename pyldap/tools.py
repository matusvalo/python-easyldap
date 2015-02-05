from .libldap.structures import LDAPMod

def is_iterable(obj):
    from collections import Iterable
    return not (isinstance(obj, str) or isinstance(obj, bytes)) and isinstance(obj, Iterable)


def is_ascii(s):
    if isinstance(s, bytes):
        return all(c < 128 for c in s)
    else:
        return all(ord(c) < 128 for c in s)


def ldap_decode(s):
    if s is None:
        return None
    if isinstance(s, str):
        return str(s)
    elif isinstance(s, bytes):
        return s.decode('utf8')
    else:
        try:
            return str(s)
        except:
            pass

        try:
            return bytes(s).decode('utf8')
        except:
            pass
        raise ValueError('Cannot decode to bytes')


def ldap_encode(s):
    if s is None:
        return None
    if isinstance(s, str):
        return s.encode('utf8')
    elif isinstance(s, bytes):
        return bytes(s)
    else:
        try:
            return bytes(s)
        except:
            pass

        try:
            return str(s).encode('utf8')
        except:
            pass
        raise ValueError('Cannot encode to bytes')

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
