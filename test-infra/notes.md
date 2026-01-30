 LDAP authentication with HANA Express is now working. Here's a summary of the key findings and changes:

  Key Discovery: The critical fix was changing ATTRIBUTE DN 'cn' to ATTRIBUTE DN 'distinguishedName'. HANA uses this attribute value for the LDAP bind operation, not just for username matching.

  Requirements for OpenLDAP + HANA LDAP Authentication:

  1. LDAP Users need distinguishedName attribute - OpenLDAP doesn't have this natively (Active Directory does). Add extensibleObject objectClass and set distinguishedName: <full DN> on each user.
  2. HANA Provider Configuration:
    - ATTRIBUTE DN 'distinguishedName' - tells HANA which attribute contains the bind DN
    - ATTRIBUTE MEMBER_OF 'memberOf' - for LDAP authorization/group lookup
    - Use IP address instead of hostname if DNS resolution fails between containers
  3. LDAP Groups: Use groupOfUniqueNames with uniqueMember (the default osixia/openldap memberOf overlay configuration)
  4. HANA Users:
    - Create with IDENTIFIED EXTERNALLY AS '<ldap DN>'
    - Enable LDAP: ALTER USER ... ENABLE LDAP
    - Set authorization mode: ALTER USER ... AUTHORIZATION LDAP
    - Map LDAP groups to HANA roles: CREATE ROLE ... LDAP GROUP '<group DN>'

  All test-infra files have been updated with the working configuration.
  


  
  ⏺ The setup is now fully working. LDAP authentication with HANA Express is successful.

  Summary of what's required for HANA + OpenLDAP authentication:

  1. OpenLDAP users need distinguishedName attribute - Add extensibleObject objectClass and set distinguishedName: <full DN>
  2. Use groupOfUniqueNames with uniqueMember for groups (matches osixia/openldap's default memberOf overlay)
  3. HANA LDAP Provider must use ATTRIBUTE DN 'distinguishedName' - not 'cn'
  4. Use container IP (via podman inspect) instead of hostname for LDAP URL - HANA may not resolve container hostnames
  5. HANA users need:
    - IDENTIFIED EXTERNALLY AS '<ldap DN>'
    - ENABLE LDAP
    - AUTHORIZATION LDAP
    - A role mapped to their LDAP group

  You can now test go-hdb LDAP authentication from the EC2 instance:

  export GOHDBDSN='hdb://LDAPUSER1:LdapPass123@localhost:39017'
  go test -v ./driver/...