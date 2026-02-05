//go:build unit

package driver

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-units"
	"github.com/go-ldap/ldap/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// LDAP test configuration
const (
	ldapImage       = "osixia/openldap:latest"
	ldapDomain      = "example.com"
	ldapOrg         = "Test"
	ldapAdminPwd    = "admin123"
	ldapTestUserCN  = "ldapuser1"
	ldapTestUserPwd = "LdapPass123"

	hanaImage     = "saplabs/hanaexpress:latest"
	hanaMasterPwd = "HanaExpress1"
)

// TestLDAPAuthenticationWithTestcontainers runs the LDAP authentication test
// using testcontainers to manage the infrastructure.
//
// Run with: go test -tags integration -v -timeout 15m ./driver -run TestLDAPAuthenticationWithTestcontainers
func TestLDAPAuthenticationWithTestcontainers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()

	// Create a shared network for containers
	testNetwork, err := network.New(ctx, network.WithCheckDuplicate())
	if err != nil {
		t.Fatalf("failed to create network: %v", err)
	}
	defer testNetwork.Remove(ctx) //nolint:errcheck

	// Start OpenLDAP container
	t.Log("Starting OpenLDAP container...")
	ldapContainer, err := startOpenLDAP(ctx, testNetwork.Name)
	if err != nil {
		t.Fatalf("failed to start OpenLDAP: %v", err)
	}
	defer ldapContainer.Terminate(ctx) //nolint:errcheck

	ldapHost, err := ldapContainer.Host(ctx)
	if err != nil {
		t.Fatalf("failed to get LDAP host: %v", err)
	}
	ldapPort, err := ldapContainer.MappedPort(ctx, "389")
	if err != nil {
		t.Fatalf("failed to get LDAP port: %v", err)
	}

	t.Logf("OpenLDAP available at %s:%s", ldapHost, ldapPort.Port())

	// Set up LDAP users
	t.Log("Setting up LDAP users...")
	ldapURL := fmt.Sprintf("ldap://%s:%s", ldapHost, ldapPort.Port())
	if err := setupLDAPUsers(ldapURL); err != nil {
		t.Fatalf("failed to setup LDAP users: %v", err)
	}

	// Start HANA Express container
	t.Log("Starting HANA Express container (this may take 5-10 minutes)...")
	hanaContainer, err := startHANAExpress(ctx, testNetwork.Name)
	if err != nil {
		t.Fatalf("failed to start HANA Express: %v", err)
	}
	defer hanaContainer.Terminate(ctx) //nolint:errcheck

	hanaHost, err := hanaContainer.Host(ctx)
	if err != nil {
		t.Fatalf("failed to get HANA host: %v", err)
	}
	hanaPort, err := hanaContainer.MappedPort(ctx, "39017")
	if err != nil {
		t.Fatalf("failed to get HANA port: %v", err)
	}

	t.Logf("HANA Express available at %s:%s", hanaHost, hanaPort.Port())

	// Configure HANA for LDAP authentication
	// Use the container network alias "openldap" since both containers share the network
	t.Log("Configuring HANA for LDAP authentication...")
	systemDSN := fmt.Sprintf("hdb://SYSTEM:%s@%s:%s", hanaMasterPwd, hanaHost, hanaPort.Port())
	if err := configureHANAforLDAP(systemDSN, "openldap"); err != nil {
		t.Fatalf("failed to configure HANA for LDAP: %v", err)
	}

	// Test LDAP authentication
	t.Log("Testing LDAP authentication...")
	ldapDSN := fmt.Sprintf("hdb://LDAPUSER1:%s@%s:%s", ldapTestUserPwd, hanaHost, hanaPort.Port())
	if err := testLDAPAuth(t, ldapDSN); err != nil {
		t.Fatalf("LDAP authentication test failed: %v", err)
	}

	t.Log("LDAP authentication test passed!")
}

func startOpenLDAP(ctx context.Context, networkName string) (testcontainers.Container, error) {
	req := testcontainers.ContainerRequest{
		Image:        ldapImage,
		ExposedPorts: []string{"389/tcp"},
		Networks:     []string{networkName},
		NetworkAliases: map[string][]string{
			networkName: {"openldap"},
		},
		Env: map[string]string{
			"LDAP_ORGANISATION":   ldapOrg,
			"LDAP_DOMAIN":         ldapDomain,
			"LDAP_ADMIN_PASSWORD": ldapAdminPwd,
			"LDAP_TLS":            "false",
		},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("389/tcp"),
			wait.ForLog("slapd starting"),
		).WithDeadline(2 * time.Minute),
	}

	return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
}

func startHANAExpress(ctx context.Context, networkName string) (testcontainers.Container, error) {
	req := testcontainers.ContainerRequest{
		Image:        hanaImage,
		ExposedPorts: []string{"39017/tcp", "39013/tcp"},
		Networks:     []string{networkName},
		NetworkAliases: map[string][]string{
			networkName: {"hana"},
		},
		Cmd: []string{
			"--master-password", hanaMasterPwd,
			"--agree-to-sap-license",
		},
		// HANA requires specific resource settings
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.Ulimits = []*units.Ulimit{
				{Name: "nofile", Hard: 1048576, Soft: 1048576},
			}
			// HANA requires specific sysctls - these may need host configuration
			hc.Sysctls = map[string]string{
				"kernel.shmmax":  "1073741824",
				"kernel.shmmni":  "4096",
				"kernel.shmall":  "8388608",
			}
			// HANA requires additional syscalls (move_pages, mbind) - disable seccomp
			hc.SecurityOpt = []string{"seccomp=unconfined"}
		},
		// Wait for HANA to be ready - this takes a while
		WaitingFor: wait.ForLog("Startup finished").WithStartupTimeout(15 * time.Minute),
	}

	return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
}

func setupLDAPUsers(ldapURL string) error {
	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	adminDN := "cn=admin,dc=example,dc=com"
	if err := conn.Bind(adminDN, ldapAdminPwd); err != nil {
		return fmt.Errorf("failed to bind as admin: %w", err)
	}

	// Create organizational units
	ous := []struct {
		dn   string
		name string
	}{
		{"ou=users,dc=example,dc=com", "users"},
		{"ou=groups,dc=example,dc=com", "groups"},
	}

	for _, ou := range ous {
		addReq := ldap.NewAddRequest(ou.dn, nil)
		addReq.Attribute("objectClass", []string{"organizationalUnit"})
		addReq.Attribute("ou", []string{ou.name})
		if err := conn.Add(addReq); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			return fmt.Errorf("failed to create OU %s: %w", ou.dn, err)
		}
	}

	// Create test user
	userDN := fmt.Sprintf("cn=%s,ou=users,dc=example,dc=com", ldapTestUserCN)
	addReq := ldap.NewAddRequest(userDN, nil)
	addReq.Attribute("objectClass", []string{"inetOrgPerson", "posixAccount", "extensibleObject"})
	addReq.Attribute("cn", []string{ldapTestUserCN})
	addReq.Attribute("sn", []string{"User1"})
	addReq.Attribute("uid", []string{ldapTestUserCN})
	addReq.Attribute("uidNumber", []string{"10001"})
	addReq.Attribute("gidNumber", []string{"10000"})
	addReq.Attribute("homeDirectory", []string{"/home/" + ldapTestUserCN})
	addReq.Attribute("userPassword", []string{ldapTestUserPwd})
	addReq.Attribute("distinguishedName", []string{userDN})
	if err := conn.Add(addReq); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		return fmt.Errorf("failed to create test user: %w", err)
	}

	// Create group
	groupDN := "cn=hanausers,ou=groups,dc=example,dc=com"
	addReq = ldap.NewAddRequest(groupDN, nil)
	addReq.Attribute("objectClass", []string{"groupOfUniqueNames"})
	addReq.Attribute("cn", []string{"hanausers"})
	addReq.Attribute("uniqueMember", []string{userDN})
	if err := conn.Add(addReq); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		return fmt.Errorf("failed to create group: %w", err)
	}

	return nil
}

func configureHANAforLDAP(systemDSN, ldapHostname string) error {
	connector, err := NewDSNConnector(systemDSN)
	if err != nil {
		return fmt.Errorf("failed to create connector: %w", err)
	}

	db := sql.OpenDB(connector)
	defer db.Close()

	// Wait for HANA to be fully ready
	for i := 0; i < 30; i++ {
		if err := db.Ping(); err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}

	// Clean up any existing configuration (ignore errors)
	db.Exec(`DROP USER LDAPUSER1`)
	db.Exec(`DROP ROLE LDAP_USERS_ROLE`)
	db.Exec(`DROP LDAP PROVIDER LDAP_TEST_PROVIDER`)

	// Create LDAP PSE for encryption (required for LDAP auth)
	db.Exec(`CREATE PSE LDAP_PSE`)
	db.Exec(`SET PSE LDAP_PSE PURPOSE LDAP`)

	// Create LDAP provider
	createProvider := fmt.Sprintf(`CREATE LDAP PROVIDER LDAP_TEST_PROVIDER
		CREDENTIAL TYPE 'PASSWORD' USING 'user=cn=admin,dc=example,dc=com;password=%s'
		USER LOOKUP URL 'ldap://%s:389/ou=users,dc=example,dc=com??sub?(cn=*)'
		ATTRIBUTE DN 'distinguishedName'
		ATTRIBUTE MEMBER_OF 'memberOf'
		SSL OFF
		DEFAULT ON
		ENABLE PROVIDER`, ldapAdminPwd, ldapHostname)

	if _, err = db.Exec(createProvider); err != nil {
		return fmt.Errorf("failed to create LDAP provider: %w", err)
	}

	// Create role mapped to LDAP group
	if _, err = db.Exec(`CREATE ROLE LDAP_USERS_ROLE LDAP GROUP 'cn=hanausers,ou=groups,dc=example,dc=com'`); err != nil {
		return fmt.Errorf("failed to create LDAP role: %w", err)
	}

	// Create HANA user for LDAP authentication
	userDN := fmt.Sprintf("cn=%s,ou=users,dc=example,dc=com", ldapTestUserCN)
	createUser := fmt.Sprintf(`CREATE USER LDAPUSER1 IDENTIFIED EXTERNALLY AS '%s'`, userDN)
	if _, err = db.Exec(createUser); err != nil {
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

func testLDAPAuth(t *testing.T, ldapDSN string) error {
	connector, err := NewDSNConnector(ldapDSN)
	if err != nil {
		return fmt.Errorf("failed to create connector: %w", err)
	}

	db := sql.OpenDB(connector)
	defer db.Close()

	if err := db.Ping(); err != nil {
		return fmt.Errorf("LDAP authentication failed: %w", err)
	}

	var currentUser string
	if err := db.QueryRow("SELECT CURRENT_USER FROM DUMMY").Scan(&currentUser); err != nil {
		return fmt.Errorf("failed to query current user: %w", err)
	}

	t.Logf("Successfully authenticated as: %s", currentUser)

	expectedUser := strings.ToUpper(ldapTestUserCN)
	if currentUser != expectedUser {
		return fmt.Errorf("expected user %s, got %s", expectedUser, currentUser)
	}

	return nil
}
