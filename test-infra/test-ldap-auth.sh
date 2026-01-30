#!/bin/bash
set -e

echo "=== Testing LDAP Authentication ==="

echo ""
echo "1. Testing LDAP bind directly..."
podman exec openldap ldapwhoami -x -H ldap://localhost:389 \
    -D "cn=ldapuser1,ou=users,dc=example,dc=com" -w LdapPass123
echo "   LDAP bind successful!"

echo ""
echo "2. Testing HANA connection with SYSTEM user..."
podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u SYSTEM -p HanaExpress1 -d SYSTEMDB \
    "SELECT CURRENT_USER FROM DUMMY"

echo ""
echo "3. Testing HANA connection with LDAP user 1..."
podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u LDAPUSER1 -p LdapPass123 -d SYSTEMDB \
    "SELECT CURRENT_USER FROM DUMMY"

echo ""
echo "4. Testing HANA connection with LDAP user 2..."
podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u LDAPUSER2 -p LdapPass456 -d SYSTEMDB \
    "SELECT CURRENT_USER FROM DUMMY"

echo ""
echo "5. Checking LDAP provider configuration..."
podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u SYSTEM -p HanaExpress1 -d SYSTEMDB \
    "SELECT LDAP_PROVIDER_NAME, IS_DEFAULT, IS_PROVIDER_ENABLED, ATTRIBUTE_DN FROM SYS.LDAP_PROVIDERS"

echo ""
echo "6. Checking LDAP users configuration..."
podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u SYSTEM -p HanaExpress1 -d SYSTEMDB \
    "SELECT USER_NAME, IS_LDAP_ENABLED, AUTHORIZATION_MODE FROM SYS.USERS WHERE USER_NAME LIKE 'LDAP%'"

echo ""
echo "=== All tests passed! ==="
echo ""
echo "You can now test with go-hdb:"
echo "  export GOHDBDSN='hdb://LDAPUSER1:LdapPass123@localhost:39017'"
echo "  go test -v ./driver/..."
