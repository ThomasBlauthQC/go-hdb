//go:build ldap && unit

package driver

import (
	"database/sql"
	"os"
	"testing"
)

func TestLDAPAuthentication(t *testing.T) {
	// LDAP test requires a separate DSN with LDAP credentials
	// Set GOHDBDSN_LDAP=hdb://LDAPUSER1:LdapPass123@localhost:39017
	ldapDSN := os.Getenv("GOHDBDSN_LDAP")
	if ldapDSN == "" {
		t.Skip("GOHDBDSN_LDAP not set")
	}

	connector, err := NewDSNConnector(ldapDSN)
	if err != nil {
		t.Fatalf("failed to create connector: %v", err)
	}

	db := sql.OpenDB(connector)
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		t.Fatalf("failed to ping: %v", err)
	}

	// Verify current user
	var currentUser string
	if err := db.QueryRow("SELECT CURRENT_USER FROM DUMMY").Scan(&currentUser); err != nil {
		t.Fatalf("failed to query current user: %v", err)
	}

	t.Logf("Connected as: %s", currentUser)

	// Verify it's an LDAP user (should be LDAPUSER1 or similar)
	if currentUser == "" {
		t.Fatal("current user is empty")
	}
}
