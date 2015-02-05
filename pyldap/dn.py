from collections import namedtuple
from functools import reduce
from .libldap.functions import *
from .tools import ldap_encode, is_iterable, ldap_decode


AvaTuple = namedtuple('AvaTuple', ['attr', 'val'])


class Ava(AvaTuple):
    LDAP_AVA_NULL = 0x0000
    LDAP_AVA_STRING = 0x0001
    LDAP_AVA_BINARY = 0x0002
    LDAP_AVA_NONPRINTABLE = 0x0004
    LDAP_AVA_FREE_ATTR = 0x0010
    LDAP_AVA_FREE_VALUE = 0x0020

    def __new__(cls, attr, val, flags):
        return AvaTuple.__new__(cls, attr, val)

    def __init__(self, attr, val, flags):
        super(Ava, self).__init__(attr, val)
        self._flags = flags

    def is_null(self):
        return self._flags & Ava.LDAP_AVA_NULL == Ava.LDAP_AVA_NULL

    def is_string(self):
        return self._flags & Ava.LDAP_AVA_STRING == Ava.LDAP_AVA_STRING

    def is_binary(self):
        return self._flags & Ava.LDAP_AVA_BINARY == Ava.LDAP_AVA_BINARY

    def is_non_printable(self):
        return self._flags & Ava.LDAP_AVA_NONPRINTABLE == Ava.LDAP_AVA_NONPRINTABLE

    def is_free_attr(self):
        return self._flags & Ava.LDAP_AVA_FREE_ATTR == Ava.LDAP_AVA_FREE_ATTR

    def is_free_value(self):
        return self._flags & Ava.LDAP_AVA_FREE_VALUE == Ava.LDAP_AVA_FREE_VALUE

    @classmethod
    def from_string(cls, ava_str):
        dn = Dn(ava_str)
        if len(dn) != 1:
            raise ValueError
        if len(dn[0]) != 1:
            raise ValueError
        return dn[0][0]

    def __bytes__(self):
        return self.attr + b'=' + self.val

    def __str__(self):
        return '{}={}'.format(ldap_decode(self.attr), ldap_decode(self.val))


class RDn(tuple):

    def __new__(cls, avas):
        ava_list = list()
        if isinstance(avas, LDAPRDN):
            ava_index = 0
            while True:
                if not bool(avas[ava_index]):
                    break
                #FIXME: Support binary format (use ByVal length)
                ava_list.append(Ava(avas[ava_index][0].la_attr.bv_val,
                                    avas[ava_index][0].la_value.bv_val,
                                    avas[ava_index][0].la_flags))
                ava_index += 1
        elif is_iterable(avas):
            for ava in avas:
                if not isinstance(ava, Ava):
                    raise ValueError
                ava_list.append(ava)
        else:
            raise ValueError
        return tuple.__new__(cls, ava_list)

    def __str__(self):
        avas = map(lambda ava: '{}={}'.format(ldap_decode(ava.attr), ldap_decode(ava.val)), self)
        return reduce(lambda x, y: '{}+{}'.format(x, y), avas)

    def __bytes__(self):
        return reduce(lambda x, y: x + b'+' + y, map(lambda ava: ava.attr + b'=' + ava.val, self))

    @classmethod
    def from_string(cls, rdn_str):
        dn = Dn(rdn_str)
        if len(dn) != 1:
            raise ValueError
        return dn[0]


class Dn(tuple):

    # DN formats
    LDAP_DN_FORMAT_LDAPV3 = 0x0010
    LDAP_DN_FORMAT_LDAPV2 = 0x0020
    LDAP_DN_FORMAT_DCE = 0x0030
    LDAP_DN_FORMAT_UFN = 0x0040	                # dn2str only
    LDAP_DN_FORMAT_AD_CANONICAL = 0x0050	    # dn2str only
    LDAP_DN_FORMAT_MASK = 0x00F0

    # DN flags
    LDAP_DN_PRETTY = 0x0100
    LDAP_DN_SKIP = 0x0200
    LDAP_DN_P_NOLEADTRAILSPACES = 0x1000
    LDAP_DN_P_NOSPACEAFTERRDN = 0x2000
    LDAP_DN_PEDANTIC = 0xF000

    def __new__(cls, other, flags=LDAP_DN_FORMAT_LDAPV3):
        if isinstance(other, str) or isinstance(other, bytes):
            dn = list()
            ldapdn = ldap_str2dn(ldap_encode(other), flags)
            rdn_index = 0
            try:
                while True:
                    if not bool(ldapdn[rdn_index]):
                        break
                    rdn = RDn(ldapdn[rdn_index])
                    dn.append(rdn)
                    rdn_index += 1
            finally:
                ldap_dnfree(ldapdn)
        elif is_iterable(other):
            dn = other
        else:
            raise ValueError

        return tuple.__new__(cls, dn)

    def __init__(self, other, flags=LDAP_DN_FORMAT_LDAPV3):
        if is_iterable(other):
            for rdn in other:
                if not isinstance(rdn, RDn):
                    raise ValueError
            in_str = reduce(lambda x, y: ldap_encode(bytes(x)) + b',' + ldap_encode(bytes(y)), other)
            self._dn_str = type(self)._convert_format(in_str, Dn.LDAP_DN_FORMAT_LDAPV3, flags)
        else:
            self._dn_str = ldap_encode(other)
        self._flags = flags
        super(Dn, self).__init__()

    def __str__(self):
        return ldap_decode(self._dn_str)

    def __bytes__(self):
        return bytes(self._dn_str)


    @property
    def flags(self):
        return int(self._flags)

    @property
    def rdn(self):
        return RDn(self[0])

    @property
    def base_dn(self):
        return Dn(self[1:], self._flags)

    def _format(self, out_format):
        return type(self)._convert_format(self._dn_str, self._flags, out_format)

    @classmethod
    def _convert_format(cls, dn_str, in_format, out_format):
        if in_format is not None and (
           in_format & Dn.LDAP_DN_FORMAT_LDAPV2 == Dn.LDAP_DN_FORMAT_LDAPV2 ^
           in_format & Dn.LDAP_DN_FORMAT_LDAPV3 == Dn.LDAP_DN_FORMAT_LDAPV3 ^
           in_format & Dn.LDAP_DN_FORMAT_DCE == Dn.LDAP_DN_FORMAT_DCE):
            raise ValueError

        if out_format is not None and (
           out_format & Dn.LDAP_DN_FORMAT_LDAPV3 == Dn.LDAP_DN_FORMAT_LDAPV3 ^
           out_format & Dn.LDAP_DN_FORMAT_LDAPV2 == Dn.LDAP_DN_FORMAT_LDAPV2 ^
           out_format & Dn.LDAP_DN_FORMAT_DCE == Dn.LDAP_DN_FORMAT_DCE ^
           out_format & Dn.LDAP_DN_FORMAT_UFN == Dn.LDAP_DN_FORMAT_UFN ^
           out_format & Dn.LDAP_DN_FORMAT_AD_CANONICAL == Dn.LDAP_DN_FORMAT_AD_CANONICAL):
            raise ValueError

        ldap_dn = ldap_str2dn(dn_str, in_format)
        try:
            ret_str = ldap_dn2str(ldap_dn, out_format)
        finally:
            ldap_dnfree(ldap_dn)
        return ret_str

    def format_ldapv2(self, flags=None):
        if flags is None:
            return ldap_decode(self._format(Dn.LDAP_DN_FORMAT_LDAPV2))
        else:
            return ldap_decode(self._format(Dn.LDAP_DN_FORMAT_LDAPV2 | flags))

    def format_ldapv3(self, flags=None):
        if flags is None:
            return ldap_decode(self._format(Dn.LDAP_DN_FORMAT_LDAPV3))
        else:
            return ldap_decode(self._format(Dn.LDAP_DN_FORMAT_LDAPV3 | flags))

    def format_dce(self, flags=None):
        if flags is None:
            return ldap_decode(self._format(Dn.LDAP_DN_FORMAT_DCE))
        else:
            return ldap_decode(self._format(Dn.LDAP_DN_FORMAT_DCE | flags))

    def format_ufn(self, flags=None):
        if flags is None:
            return ldap_decode(self._format(Dn.LDAP_DN_FORMAT_UFN))
        else:
            return ldap_decode(self._format(Dn.LDAP_DN_FORMAT_UFN | flags))

    def format_ad_canonical(self, flags=None):
        if flags is None:
            return ldap_decode(self._format(Dn.LDAP_DN_FORMAT_AD_CANONICAL))
        else:
            return ldap_decode(self._format(Dn.LDAP_DN_FORMAT_AD_CANONICAL | flags))
