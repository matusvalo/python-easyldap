from ctypes import *
from ..tools import is_iterable


class BerElement(Structure):
    _fields_ = []


class LDAP(Structure):
    _fields_ = []


class LDAPMessage(Structure):
    _fields_ = []


class Timeval(Structure):
    _fields_ = []


class BerVal(Structure):
    _fields_ = [('bv_len', c_ulong),
                ('bv_val', c_char_p)]

    @classmethod
    def from_string(cls, string):
        val = bytes(string)
        return cls(bv_val=c_char_p(val), bv_len=c_ulong(len(val)))


class LDAPAVA(Structure):
    _fields_ = [('la_attr', BerVal),
                ('la_value', BerVal),
                ('la_flags', c_uint)]



LDAPRDN = POINTER(POINTER(LDAPAVA))
LDAPDN = POINTER(LDAPRDN)


class LDAPMod(Structure):

    class ModVals(Union):

        _fields_ = [('modv_strvals', POINTER(c_char_p)),
                    ('modv_bvals', POINTER(POINTER(BerVal)))]

        @classmethod
        def create_string(cls, values):
            if is_iterable(values):
                values_list = list(map(lambda v: c_char_p(v), values))
                values_array = (c_char_p * (len(values_list) + 1))(*(values_list + [None]))
            else:
                values_array = (c_char_p * 2)(c_char_p(values), None)
            return cls(modv_strvals=cast(values_array, POINTER(c_char_p)))

        @classmethod
        def create_binary(cls, values):
            if is_iterable(values):
                berval_list = list(map(lambda x: pointer(BerVal.from_string(x)), values))
                values_array = (POINTER(BerVal) * (len(values) + 1))(*(berval_list + [None]))
            else:
                berval_value = pointer(BerVal.from_string(values))
                values_array = (POINTER(BerVal) * 2)(berval_value, None)
            return cls(modv_bvals=cast(values_array, POINTER(POINTER(BerVal))))

    # IMPORTANT: do not use code 0x1000 (or above),
    # it is used internally by the backends!
    # (see ldap/servers/slapd/slap.h)
    LDAP_MOD_OP = 0x0007
    LDAP_MOD_ADD = 0x0000
    LDAP_MOD_DELETE = 0x0001
    LDAP_MOD_REPLACE = 0x0002
    LDAP_MOD_INCREMENT = 0x0003         # OpenLDAP extension
    LDAP_MOD_BVALUES = 0x0080

    _fields_ = [('mod_op', c_int),             # OP Code
                ('mod_type', c_char_p),        # Attr. name
                ('mod_vals', ModVals)]         # Attr. values

    def __init__(self, mod_op, mod_type, mod_vals):
        if mod_op != LDAPMod.LDAP_MOD_OP and                  \
           mod_op != LDAPMod.LDAP_MOD_ADD and                 \
           mod_op != LDAPMod.LDAP_MOD_DELETE and              \
           mod_op != LDAPMod.LDAP_MOD_REPLACE and             \
           mod_op != LDAPMod.LDAP_MOD_INCREMENT and           \
           mod_op != LDAPMod.LDAP_MOD_BVALUES and             \
           mod_op != 0x0:
            raise ValueError
        super().__init__(c_int(mod_op), mod_type, mod_vals)

    @classmethod
    def create_binary(cls, mod_op, attr_name, values):
        return cls(mod_op=mod_op, mod_type=c_char_p(attr_name), mod_vals=cls.ModVals.create_binary(values))

    @classmethod
    def create_string(cls, mod_op, attr_name, values):
        return cls(mod_op=mod_op, mod_type=c_char_p(attr_name), mod_vals=cls.ModVals.create_string(values))

    @property
    def mod_values(self):
        return self.ModVals.modv_strvals

    @mod_values.setter
    def mod_values(self, val):
        self.ModVals.modv_strvals = val

    @property
    def mod_bvalues(self):
        return self.ModVals.modv_bvals

    @mod_bvalues.setter
    def mod_bvalues(self, val):
        self.ModVals.modv_bvals = val


class LDAPControl(Structure):
    _fields_ = [('ldctl_oid', c_char_p),        # numericoid of control
                ('ldctl_value', BerVal),        # encoded value of control
                ('ldctl_iscritical', c_char)]   # criticality


class LDAPURLDesc(Structure):

    @property
    def lud_scheme(self):
        return self._lud_scheme
    @property
    def lud_host(self):
        return self._lud_host
    @property
    def lud_port(self):
        return self._lud_port
    @property
    def lud_dn(self):
        return self._lud_dn
    @property
    def lud_attrs(self):
        if self._lud_attrs:
            i = 0
            while True:
                if not self._lud_attrs[i]:
                    break
                yield self._lud_attrs[i]
                i += 1
    @property
    def lud_scope(self):
        return self._lud_scope
    @property
    def lud_filter(self):
        return self._lud_filter
    @property
    def lud_exts(self):
        if self._lud_exts:
            i = 0
            while True:
                if not self._lud_exts[i]:
                    break
                yield self._lud_exts[i]
                i += 1
    @property
    def lud_crit_exts(self):
        return bool(self._lud_crit_exts)

LDAPURLDesc._fields_ = [('_lud_next', POINTER(LDAPURLDesc)),   # libLDAP internal attribute
                        ('_lud_scheme', c_char_p),             # URI scheme
                        ('_lud_host', c_char_p),               # LDAP host to contact
                        ('_lud_port', c_int),                  # port on host
                        ('_lud_dn', c_char_p),                 # base for search
                        ('_lud_attrs', POINTER(c_char_p)),     # list of attributes
                        ('_lud_scope', c_int),                 # a LDAP_SCOPE_... value
                        ('_lud_filter', c_char_p),             # LDAP search filter
                        ('_lud_exts', POINTER(c_char_p)),      # LDAP extensions
                        ('_lud_crit_exts', c_int)]             # true if any extension is critical
