-- Configure HANA Express for LDAP Authentication
-- Run this after HANA Express is fully started
-- NOTE: Replace 'openldap' with the actual IP if hostname resolution doesn't work

-- 1. Create LDAP Provider
-- IMPORTANT: ATTRIBUTE DN must be 'distinguishedName' for OpenLDAP (not 'cn')
-- This requires users to have a 'distinguishedName' attribute (via extensibleObject)
CREATE LDAP PROVIDER LDAP_TEST_PROVIDER
  CREDENTIAL TYPE 'PASSWORD' USING 'user=cn=admin,dc=example,dc=com;password=admin123'
  USER LOOKUP URL 'ldap://openldap:389/ou=users,dc=example,dc=com??sub?(cn=*)'
  ATTRIBUTE DN 'distinguishedName'
  ATTRIBUTE MEMBER_OF 'memberOf'
  SSL OFF
  DEFAULT ON
  ENABLE PROVIDER;

-- 2. Create a role mapped to LDAP group (required for LDAP authorization)
CREATE ROLE LDAP_USERS_ROLE LDAP GROUP 'cn=hanausers,ou=groups,dc=example,dc=com';

-- 3. Create HANA users for LDAP authentication
CREATE USER LDAPUSER1 IDENTIFIED EXTERNALLY AS 'cn=ldapuser1,ou=users,dc=example,dc=com';
ALTER USER LDAPUSER1 ENABLE LDAP;
ALTER USER LDAPUSER1 AUTHORIZATION LDAP;

CREATE USER LDAPUSER2 IDENTIFIED EXTERNALLY AS 'cn=ldapuser2,ou=users,dc=example,dc=com';
ALTER USER LDAPUSER2 ENABLE LDAP;
ALTER USER LDAPUSER2 AUTHORIZATION LDAP;

-- 4. Verify configuration
SELECT * FROM SYS.LDAP_PROVIDERS;
SELECT * FROM SYS.LDAP_PROVIDER_URLS;
SELECT USER_NAME, IS_LDAP_ENABLED, AUTHORIZATION_MODE FROM SYS.USERS WHERE USER_NAME LIKE 'LDAP%';

-- 5. Validate LDAP provider (optional - test connection)
-- VALIDATE LDAP PROVIDER LDAP_TEST_PROVIDER;
-- VALIDATE LDAP PROVIDER LDAP_TEST_PROVIDER CHECK USER LDAPUSER1;
