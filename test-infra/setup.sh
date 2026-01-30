#!/bin/bash
set -e

echo "=== HANA Express + OpenLDAP Test Infrastructure ==="

# Check for podman-compose
if ! command -v podman-compose &> /dev/null; then
    echo "Installing podman-compose..."
    pip3 install podman-compose
fi

echo ""
echo "=== Stopping any existing services ==="
podman-compose down -v 2>/dev/null || true

echo ""
echo "=== Starting services ==="
podman-compose up -d

echo ""
echo "=== Waiting for OpenLDAP to be ready ==="
until podman exec openldap ldapsearch -x -b "" -s base &> /dev/null; do
    echo "  Waiting for OpenLDAP..."
    sleep 2
done
echo "  OpenLDAP is ready!"

echo ""
echo "=== Adding LDAP users ==="
sleep 2
podman cp ldap-init/01-users.ldif openldap:/tmp/users.ldif
for i in 1 2 3 4 5; do
    if podman exec openldap ldapadd -x \
        -H ldapi:/// \
        -D "cn=admin,dc=example,dc=com" -w admin123 \
        -f /tmp/users.ldif 2>/dev/null; then
        echo "  Users added successfully!"
        break
    fi
    echo "  Attempt $i failed, retrying..."
    sleep 2
done

echo ""
echo "=== Verifying LDAP users ==="
podman exec openldap ldapsearch -x \
    -D "cn=admin,dc=example,dc=com" -w admin123 \
    -b "ou=users,dc=example,dc=com" "(objectClass=inetOrgPerson)" cn distinguishedName

echo ""
echo "=== Getting OpenLDAP IP address ==="
LDAP_IP=$(podman inspect openldap --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "  OpenLDAP IP: $LDAP_IP"

echo ""
echo "=== Waiting for HANA Express to be ready (this takes 5-10 minutes) ==="
echo "    You can monitor with: podman logs -f hanaexpress"

until podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u SYSTEM -p HanaExpress1 -d SYSTEMDB \
    "SELECT 1 FROM DUMMY" &> /dev/null; do
    echo "  Waiting for HANA Express... ($(date +%H:%M:%S))"
    sleep 30
done
echo "  HANA Express is ready!"

echo ""
echo "=== Setting up LDAP encryption (PSE and Certificate) ==="
# Generate a self-signed certificate with private key for LDAP encryption
# This certificate is used by HANA to encrypt/decrypt LDAP authentication data
CERT_DIR=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/ldap_key.pem" -out "$CERT_DIR/ldap_cert.pem" \
    -days 3650 -nodes -subj "/CN=HANA_LDAP_AUTH" 2>/dev/null

# Read certificate and private key separately
LDAP_CERT_PEM=$(cat "$CERT_DIR/ldap_cert.pem")
LDAP_KEY_PEM=$(cat "$CERT_DIR/ldap_key.pem")

# Create PSE for LDAP
podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u SYSTEM -p HanaExpress1 -d SYSTEMDB \
    "CREATE PSE LDAP_PSE" 2>/dev/null || echo "  PSE already exists, continuing..."

# Set PSE purpose for LDAP
podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u SYSTEM -p HanaExpress1 -d SYSTEMDB \
    "SET PSE LDAP_PSE PURPOSE LDAP" 2>/dev/null || echo "  PSE purpose already set, continuing..."

# Set the PSE's own certificate with private key for encryption/signing
# Escape single quotes in PEM content for SQL
LDAP_CERT_ESCAPED=$(echo "$LDAP_CERT_PEM" | sed "s/'/''/g")
LDAP_KEY_ESCAPED=$(echo "$LDAP_KEY_PEM" | sed "s/'/''/g")
podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u SYSTEM -p HanaExpress1 -d SYSTEMDB \
    "ALTER PSE LDAP_PSE SET OWN CERTIFICATE '${LDAP_CERT_ESCAPED}' PRIVATE KEY '${LDAP_KEY_ESCAPED}'" 2>/dev/null || echo "  Certificate already assigned, continuing..."

# Cleanup temp files
rm -rf "$CERT_DIR"
echo "  LDAP encryption configured!"

echo ""
echo "=== Configuring LDAP in HANA ==="
# Create LDAP provider with the actual OpenLDAP IP (hostname resolution may not work)
podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u SYSTEM -p HanaExpress1 -d SYSTEMDB \
    "CREATE LDAP PROVIDER LDAP_TEST_PROVIDER CREDENTIAL TYPE 'PASSWORD' USING 'user=cn=admin,dc=example,dc=com;password=admin123' USER LOOKUP URL 'ldap://${LDAP_IP}:389/ou=users,dc=example,dc=com??sub?(cn=*)' ATTRIBUTE DN 'distinguishedName' ATTRIBUTE MEMBER_OF 'memberOf' SSL OFF DEFAULT ON ENABLE PROVIDER"

# Create role mapped to LDAP group
podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u SYSTEM -p HanaExpress1 -d SYSTEMDB \
    "CREATE ROLE LDAP_USERS_ROLE LDAP GROUP 'cn=hanausers,ou=groups,dc=example,dc=com'"

# Create HANA users for LDAP authentication
podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u SYSTEM -p HanaExpress1 -d SYSTEMDB \
    "CREATE USER LDAPUSER1 IDENTIFIED EXTERNALLY AS 'cn=ldapuser1,ou=users,dc=example,dc=com'"
podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u SYSTEM -p HanaExpress1 -d SYSTEMDB \
    "ALTER USER LDAPUSER1 ENABLE LDAP"
podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u SYSTEM -p HanaExpress1 -d SYSTEMDB \
    "ALTER USER LDAPUSER1 AUTHORIZATION LDAP"

podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u SYSTEM -p HanaExpress1 -d SYSTEMDB \
    "CREATE USER LDAPUSER2 IDENTIFIED EXTERNALLY AS 'cn=ldapuser2,ou=users,dc=example,dc=com'"
podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u SYSTEM -p HanaExpress1 -d SYSTEMDB \
    "ALTER USER LDAPUSER2 ENABLE LDAP"
podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u SYSTEM -p HanaExpress1 -d SYSTEMDB \
    "ALTER USER LDAPUSER2 AUTHORIZATION LDAP"

echo ""
echo "=== Verifying LDAP configuration ==="
podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u SYSTEM -p HanaExpress1 -d SYSTEMDB \
    "SELECT LDAP_PROVIDER_NAME, IS_PROVIDER_ENABLED, ATTRIBUTE_DN FROM SYS.LDAP_PROVIDERS"

echo ""
echo "=== Testing LDAP authentication ==="
if podman exec hanaexpress /usr/sap/HXE/HDB90/exe/hdbsql \
    -i 90 -u LDAPUSER1 -p LdapPass123 -d SYSTEMDB \
    "SELECT CURRENT_USER FROM DUMMY" &> /dev/null; then
    echo "  LDAP authentication successful!"
else
    echo "  WARNING: LDAP authentication failed. Check configuration."
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Connection details:"
echo "  HANA Host:     localhost"
echo "  HANA Port:     39017 (tenant) / 39013 (system)"
echo "  SYSTEM user:   SYSTEM / HanaExpress1"
echo "  LDAP user 1:   LDAPUSER1 / LdapPass123"
echo "  LDAP user 2:   LDAPUSER2 / LdapPass456"
echo ""
echo "Test with go-hdb:"
echo "  export GOHDBDSN='hdb://LDAPUSER1:LdapPass123@localhost:39017'"
echo "  go test -v ./driver/..."
echo ""
echo "LDAP admin:"
echo "  ldapsearch -x -H ldap://localhost:389 -D 'cn=admin,dc=example,dc=com' -w admin123 -b 'dc=example,dc=com'"
