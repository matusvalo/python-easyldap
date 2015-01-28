from .libldap.functions import ldap_url_parse, ldap_is_ldap_url, ldap_free_urldesc
from .tools import ldap_encode
from .libldap.constants import SCOPES


class Url(object):
    __slots__ = 'scheme', 'host', 'port', 'dn', 'attrs', 'scope', 'filter', 'extensions', 'has_crit_extension'

    SCOPE_BASE = SCOPES['LDAP_SCOPE_BASE']
    SCOPE_ONE = SCOPES['LDAP_SCOPE_ONELEVEL']
    SCOPE_SUB = SCOPES['LDAP_SCOPE_SUBTREE']
    SCOPE_SUBORDINATE = SCOPES['LDAP_SCOPE_SUBORDINATE']        # OpenLDAP extension

    def __init__(self, scheme, host, port=None, dn=None, attrs=None, scope=None, filter=None, extensions=None,
                 has_crit_extension=False):
        self.scheme = str(scheme)
        self.host = str(host)
        self.port = None if port is None else int(port)
        self.dn = None if dn is None else str(dn)
        self.attrs = None if attrs is None else tuple(attrs)
        if isinstance(scope, int):
            if scope not in SCOPES.values():
                raise ValueError
            self.scope = int(scope)
        elif isinstance(scope, str):
            if scope not in SCOPES.keys():
                raise ValueError
            self.scope = SCOPES[scope]
        else:
            self.scope = None
        self.filter = None if filter is None else str(filter)
        self.extensions = None if extensions is None else tuple(extensions)
        self.has_crit_extension = bool(has_crit_extension)

    @classmethod
    def parse_str(cls, url):
        url_desc = ldap_url_parse(ldap_encode(url))
        obj = cls(scheme=url_desc.lud_scheme,
                  host=url_desc.lud_host,
                  port=url_desc.lud_port,
                  dn=url_desc.lud_dn,
                  attrs=url_desc.lud_attrs,
                  scope=url_desc.lud_scope,
                  filter=url_desc.lud_filter,
                  extensions=url_desc.lud_exts,
                  has_crit_extension=url_desc.lud_crit_exts)
        ldap_free_urldesc(url_desc)
        return obj

    @classmethod
    def is_url(cls, string):
        return ldap_is_ldap_url(ldap_encode(string))
