from .libldap.functions import *
from .dn import Dn, RDn
from .tools import ldap_encode


class QueryResult(object):
    def __init__(self, ldap, query_result):
        self._ldap = ldap
        self._query_result = query_result

    def __len__(self):
        return ldap_count_entries(self._ldap, self._query_result)

    def __iter__(self):
        return self.entries()

    def __del__(self):
        ldap_msgfree(self._query_result)

    def entries(self, raw=False):
        entry = ldap_first_entry(self._ldap, self._query_result)
        if not entry:
            yield
        entry_dn = ldap_get_dn(self._ldap, entry)
        try:
            ret_entry = QueryResultEntry(entry_dn.value)
        finally:
            ldap_memfree(entry_dn)
        for attr in self._get_attrs(entry):
            try:
                if raw:
                    ret_entry[attr.value] = tuple(self._get_raw_values(entry, attr))
                else:
                    ret_entry[attr.value] = tuple(self._get_values(entry, attr))
            finally:
                ldap_memfree(attr)
        yield ret_entry

        while True:
            entry = ldap_next_entry(self._ldap, entry)
            if not entry:
                break
            entry_dn = ldap_get_dn(self._ldap, entry)
            try:
                ret_entry = QueryResultEntry(entry_dn.value)
            finally:
                ldap_memfree(entry_dn)
            for attr in self._get_attrs(entry):
                try:
                    if raw:
                        ret_entry[attr.value] = tuple(map(lambda v: v, self._get_raw_values(entry, attr)))
                    else:
                        ret_entry[attr.value] = tuple(map(lambda v: v, self._get_values(entry, attr)))
                finally:
                    ldap_memfree(attr)
            yield ret_entry

    def _get_raw_values(self, entry, attr):
        with ldap_get_values(self._ldap, entry, attr) as values_iterator:
            return tuple(values_iterator)

    def _get_values(self, entry, attr):
        with ldap_get_values_len(self._ldap, entry, attr) as values_iterator:
            return tuple(values_iterator)

    def _get_attrs(self, entry):
        attr, ber = ldap_first_attribute(self._ldap, entry)
        try:
            yield attr
            while True:
                attr = ldap_next_attribute(self._ldap, entry, ber)
                if not attr.value:
                    break
                yield attr
        finally:
            ber_free(ber, 0)


class BaseEntry(object):
    def __init__(self, dn):
        super().__init__()
        self._dn = ldap_encode(dn)

    @property
    def dn(self):
        return Dn(self._dn)

    @property
    def rdn(self):
        return self.dn.rdn

    @property
    def base_dn(self):
        return self.dn.base_dn


class QueryResultEntry(BaseEntry, dict):
    pass


class Entry(BaseEntry, dict):

    def __init__(self, ldap, dn):
        BaseEntry.__init__(self, dn)
        self._ldap = ldap
        self._init_data()

    def _init_data(self):
        result = ldap_search_ext_s(self._ldap, ldap_encode(self._dn), SCOPES['LDAP_SCOPE_BASE'],
                                   None, None, False, None, None, None, 0)
        query_result = QueryResult(self._ldap, result)

        if len(query_result) != 1:
            raise ValueError

        self._search_result_entry = tuple(query_result.entries())[0]

        self.update(self._search_result_entry)

    def rename(self, newrdn=None, newparent=None, delete_old_rdn=False):
        if newrdn is None:
            if newparent is None:
                raise ValueError
            rdn = self.dn.rdn
        elif isinstance(newrdn, RDn):
            rdn = newrdn
        elif isinstance(newrdn, bytes) or isinstance(newrdn, str):
            rdn = RDn.from_string(newrdn)
        else:
            raise ValueError

        if newparent is not None:
            if isinstance(newparent, Dn):
                parent = newparent
            elif isinstance(newparent, bytes) or isinstance(newparent, str):
                parent = Dn(newparent)
            else:
                raise ValueError

        if newparent is None:
            ldap_rename_s(self._ldap, bytes(self.dn),
                          bytes(rdn),
                          None,
                          delete_old_rdn, None, None)
            self._dn = bytes(Dn((rdn,) + self.dn.base_dn))
        else:
            if not isinstance(parent, Dn):
                raise ValueError
            ldap_rename_s(self._ldap, bytes(self.dn),
                          bytes(rdn),
                          bytes(parent),
                          delete_old_rdn, None, None)
            self._dn = bytes(Dn((rdn,) + parent))

    def commit(self):
        mods = list()
        for key, val in self.items():
            try:
                ldap_entry_val = tuple(self._search_result_entry[key])
                if ldap_entry_val != tuple(val):
                    if is_iterable(val):
                        mods.append(LDAPMod.create_string(LDAPMod.LDAP_MOD_REPLACE,
                                                          bytes(key),
                                                          values=map(lambda a: bytes(a), tuple(val))))
                    else:
                        mods.append(LDAPMod.create_string(LDAPMod.LDAP_MOD_REPLACE,
                                                          bytes(key),
                                                          values=bytes(val)))
            except KeyError:
                if is_iterable(val):
                    mods.append(LDAPMod.create_string(LDAPMod.LDAP_MOD_ADD,
                                                      bytes(key),
                                                      values=map(lambda a: bytes(a), tuple(val))))
                else:
                    mods.append(LDAPMod.create_string(LDAPMod.LDAP_MOD_ADD,
                                                      bytes(key),
                                                      values=bytes(val)))
        for key, val in self._search_result_entry.items():
            if key not in self.keys():
                if is_iterable(val):
                    mods.append(LDAPMod.create_string(LDAPMod.LDAP_MOD_DELETE,
                                                      bytes(key),
                                                      values=map(lambda a: bytes(a), tuple(val))))
                else:
                    mods.append(LDAPMod.create_string(LDAPMod.LDAP_MOD_DELETE,
                                                      bytes(key),
                                                      values=bytes(val)))
        try:
            ldap_modify_ext_s(self._ldap, self._dn, mods, None, None)
        except Exception:
            self.clear()
            self.update(self._search_result_entry)

        self._init_data()

