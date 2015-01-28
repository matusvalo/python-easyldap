# pyldap
pyldap is python3 library implementing libldap functionality. It is written in Python and uses ctypes library for connecting to libldap
library. It has simple and easy to use interface, but when needed, low level interface can be used.

## project structure
  * libldap - package containing low level API (almost directly mapping libldap)
    - constants - module containing basic openldap constants
    - functions - modules implementing wrappers of libldap functions
    - ldapexception - module implementing exceptions
    - structures - module mapping libldap structures
    - tools - module implementing low level helpers
  * dn - module implementing classes handling DN
  * ldapconnection - module implementing classes used to connect to LDAP
  * queryresult - module implementing iterating over result of LDAP search and Entry class
  * tools - module containing helper functions
  * url - module supporting URL handling
