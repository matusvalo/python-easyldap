from .libldap.functions import *
from .libldap.constants import *
from .libldap.structures import *
from .tools import is_iterable, ldap_encode
from .queryresult import QueryResult, Entry

__all__ = ['LdapConnection']


class LdapConnection(object):
    def __init__(self, uri):
        if not ldap_is_ldap_url(ldap_encode(uri)):
            raise ValueError('Wrong URI format.')
        self._ldap = ldap_initialize(ldap_encode(uri))

    @property
    def protocol_version(self):
        version = c_int()
        ldap_get_option(self._ldap, LDAP_OPT_PROTOCOL_VERSION, byref(version))
        return version.value

    @protocol_version.setter
    def protocol_version(self, version):
        if version not in LDAP_VERSIONS.keys():
            raise ValueError
        ldap_set_option(self._ldap, LDAP_OPT_PROTOCOL_VERSION, byref(LDAP_VERSIONS[version]))

    def simple_bind(self, rootdn, passwd):
        ldap_simple_bind_s(self._ldap, ldap_encode(rootdn), ldap_encode(passwd))

    def unbind(self):
        ldap_unbind(self._ldap)

    def search(self, base, scope, filter, attrs=None, attrsonly=False, timeout=None, sizelimit=0):
        result = ldap_search_ext_s(self._ldap,
                                   ldap_encode(base),
                                   SCOPES[scope],
                                   ldap_encode(filter),
                                   attrs,
                                   bool(attrsonly),
                                   None,
                                   None,
                                   None,
                                   0)

        return QueryResult(self._ldap, result)

    def get_entry(self, dn):
        return Entry(self._ldap, dn)

    def add(self, dn, attrs=None, battrs=None):
        """
        :param dn:
        :param attrs:
         {<attr_name>: <attr_val>,
          <attr_name>: [<attr_val1>, <attr_val2>, ...],
          ...
         }
        :param battrs:
         {<battr_name>: <battr_val>,
          <battr_name>: [<battr_val1>, <battr_val2>, ...],
          ...
         }
        """
        mods = list()
        if attrs is None and battrs is None:
            raise ValueError
        if attrs is not None:
            for attr_name in attrs:
                if is_iterable(attrs[attr_name]):
                    mod = LDAPMod.create_string(0,
                                                ldap_encode(attr_name),
                                                values=map(lambda a: ldap_encode(a), attrs[attr_name]))
                else:
                    mod = LDAPMod.create_string(0,
                                                ldap_encode(attr_name),
                                                values=ldap_encode(attrs[attr_name]))
                mods.append(mod)

        if battrs is not None:
            for battr_name in battrs:
                mod = LDAPMod.create_binary(LDAPMod.LDAP_MOD_BVALUES,
                                            ldap_encode(battr_name),
                                            values=ldap_encode(battrs[battr_name]))
                mods.append(mod)

        ldap_add_ext_s(self._ldap, ldap_encode(dn), mods, None, None)

    def delete(self, entry):
        if isinstance(entry, Entry):
            ldap_delete_ext_s(self._ldap, bytes(entry.dn), None, None)
        else:
            ldap_delete_ext_s(self._ldap, ldap_encode(entry), None, None)

    def modify(self, dn, attrs=None):
        """
        :param dn:
        :param attrs:
         {<attr_name>: (<mod_op>, <attr_val>),
          <attr_name>: (<mod_op>, [<attr_val1>, <attr_val2>, ...]),
          ...
         }
        """
        # TODO: battrs?
        mods = list()
        if attrs is None:
            raise ValueError
        if attrs is not None:
            for attr_name in attrs:
                if len(attrs[attr_name]) != 2:
                    raise ValueError
                if attrs[attr_name][0] not in (LDAPMod.LDAP_MOD_ADD, LDAPMod.LDAP_MOD_DELETE, LDAPMod.LDAP_MOD_REPLACE):
                    raise ValueError
                if is_iterable(attrs[attr_name][1]):
                    mod = LDAPMod.create_string(attrs[attr_name][0],
                                                attr_name,
                                                values=map(lambda a: ldap_encode(a), attrs[attr_name][1]))
                else:
                    mod = LDAPMod.create_string(attrs[attr_name][0],
                                                attr_name,
                                                values=ldap_encode(attrs[attr_name][1]))
                mods.append(mod)
        ldap_modify_ext_s(self._ldap, ldap_encode(dn), mods, None, None)

    def compare(self, dn, attr, value):
        if dn is None:
            raise ValueError
        if attr is None:
            raise ValueError
        return ldap_compare_ext_s(self._ldap,
                                  ldap_encode(dn),
                                  ldap_encode(attr),
                                  BerVal.from_string(ldap_encode(value)),
                                  None, None)

    @property
    def ldap(self):
        return self._ldap

