//go:build ldap

package driver

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

const (
	// LDAP configuration
	ldapURL          = "ldap://localhost:389"
	ldapBaseDN       = "dc=example,dc=com"
	ldapAdminDN      = "cn=admin,dc=example,dc=com"
	ldapAdminPass    = "admin123"
	ldapUserOU       = "ou=users,dc=example,dc=com"
	ldapGroupOU      = "ou=groups,dc=example,dc=com"
	ldapTestUser     = "ldapuser1"
	ldapTestPassword = "LdapPass123"
	ldapTestUserDN   = "cn=ldapuser1,ou=users,dc=example,dc=com"

	// HANA configuration
	hanaSystemDSN = "hdb://SYSTEM:HanaExpress1@localhost:39017"
	hanaLDAPDSN   = "hdb://LDAPUSER1:LdapPass123@localhost:39017"
)

func TestLDAPAuthentication(t *testing.T) {
	if os.Getenv("GOHDB_LDAP_TEST") == "" {
		t.Skip("GOHDB_LDAP_TEST not set - skipping LDAP integration test")
	}

	// Setup
	if err := setupLDAP(); err != nil {
		t.Fatalf("LDAP setup failed: %v", err)
	}
	if err := setupHANA(); err != nil {
		t.Fatalf("HANA setup failed: %v", err)
	}

	// Test LDAP authentication
	connector, err := NewDSNConnector(hanaLDAPDSN)
	if err != nil {
		t.Fatalf("failed to create connector: %v", err)
	}

	db := sql.OpenDB(connector)
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("LDAP authentication failed: %v", err)
	}

	var currentUser string
	if err := db.QueryRow("SELECT CURRENT_USER FROM DUMMY").Scan(&currentUser); err != nil {
		t.Fatalf("failed to query current user: %v", err)
	}

	t.Logf("Successfully authenticated as: %s", currentUser)

	if currentUser != "LDAPUSER1" {
		t.Errorf("expected user LDAPUSER1, got %s", currentUser)
	}
}

func setupLDAP() error {
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(ldapAdminDN, ldapAdminPass); err != nil {
		return fmt.Errorf("failed to bind as admin: %w", err)
	}

	// Create organizational units
	for _, ou := range []string{ldapUserOU, ldapGroupOU} {
		addReq := ldap.NewAddRequest(ou, nil)
		addReq.Attribute("objectClass", []string{"organizationalUnit"})
		addReq.Attribute("ou", []string{ou[3:strings.Index(ou, ",")]}) // extract ou name
		if err := conn.Add(addReq); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			return fmt.Errorf("failed to create OU %s: %w", ou, err)
		}
	}

	// Create test user
	addReq := ldap.NewAddRequest(ldapTestUserDN, nil)
	addReq.Attribute("objectClass", []string{"inetOrgPerson", "posixAccount", "extensibleObject"})
	addReq.Attribute("cn", []string{ldapTestUser})
	addReq.Attribute("sn", []string{"User1"})
	addReq.Attribute("uid", []string{ldapTestUser})
	addReq.Attribute("uidNumber", []string{"10001"})
	addReq.Attribute("gidNumber", []string{"10000"})
	addReq.Attribute("homeDirectory", []string{"/home/" + ldapTestUser})
	addReq.Attribute("userPassword", []string{ldapTestPassword})
	addReq.Attribute("distinguishedName", []string{ldapTestUserDN})
	if err := conn.Add(addReq); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		return fmt.Errorf("failed to create test user: %w", err)
	}

	// Create group
	groupDN := "cn=hanausers," + ldapGroupOU
	addReq = ldap.NewAddRequest(groupDN, nil)
	addReq.Attribute("objectClass", []string{"groupOfUniqueNames"})
	addReq.Attribute("cn", []string{"hanausers"})
	addReq.Attribute("uniqueMember", []string{ldapTestUserDN})
	if err := conn.Add(addReq); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		return fmt.Errorf("failed to create group: %w", err)
	}

	return nil
}

func cleanupHANA() error {
	connector, err := NewDSNConnector(hanaSystemDSN)
	if err != nil {
		return err
	}

	db := sql.OpenDB(connector)
	defer db.Close()

	// Clean up in reverse order of creation (ignore errors if not exists)
	db.Exec(`DROP USER LDAPUSER1`)
	db.Exec(`DROP ROLE LDAP_USERS_ROLE`)
	db.Exec(`DROP LDAP PROVIDER LDAP_TEST_PROVIDER`)

	return nil
}

func setupHANA() error {
	if err := cleanupHANA(); err != nil {
		return err
	}

	connector, err := NewDSNConnector(hanaSystemDSN)
	if err != nil {
		return err
	}

	db := sql.OpenDB(connector)
	defer db.Close()

	// Create LDAP provider
	if _, err = db.Exec(`CREATE LDAP PROVIDER LDAP_TEST_PROVIDER
		CREDENTIAL TYPE 'PASSWORD' USING 'user=cn=admin,dc=example,dc=com;password=admin123'
		USER LOOKUP URL 'ldap://openldap:389/ou=users,dc=example,dc=com??sub?(cn=*)'
		ATTRIBUTE DN 'distinguishedName'
		ATTRIBUTE MEMBER_OF 'memberOf'
		SSL OFF
		DEFAULT ON
		ENABLE PROVIDER`); err != nil {
		return fmt.Errorf("failed to create LDAP provider: %w", err)
	}

	// Create role mapped to LDAP group
	if _, err = db.Exec(`CREATE ROLE LDAP_USERS_ROLE LDAP GROUP 'cn=hanausers,ou=groups,dc=example,dc=com'`); err != nil {
		return fmt.Errorf("failed to create LDAP role: %w", err)
	}

	// Create HANA user for LDAP authentication
	if _, err = db.Exec(`CREATE USER LDAPUSER1 IDENTIFIED EXTERNALLY AS 'cn=ldapuser1,ou=users,dc=example,dc=com'`); err != nil {
		return fmt.Errorf("failed to create LDAP user: %w", err)
	}

	if _, err = db.Exec(`ALTER USER LDAPUSER1 ENABLE LDAP`); err != nil {
		return fmt.Errorf("failed to enable LDAP for user: %w", err)
	}

	if _, err = db.Exec(`ALTER USER LDAPUSER1 AUTHORIZATION LDAP`); err != nil {
		return fmt.Errorf("failed to set LDAP authorization: %w", err)
	}

	return nil
}
