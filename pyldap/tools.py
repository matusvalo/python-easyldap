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
