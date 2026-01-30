# EC2 Connection Info

## SSH Connection
```bash
ssh -i ~/Downloads/hana_test.pem ubuntu@ec2-18-194-46-45.eu-central-1.compute.amazonaws.com
```

## Key Locations on EC2
- hdbcli test venv: `~/test_hdb_cli/`
- Trace output: `/tmp/sqldbc_trace_unlimited.txt`

## HANA Express
- Host: localhost:39017
- LDAP user: LDAPUSER1 / LdapPass123
- hdbsql: `/usr/sap/HXE/HDB90/exe/hdbsql`

## Running hdbcli test
```bash
cd ~/test_hdb_cli && source bin/activate
python test_ldap.py 2>/tmp/trace.txt
```

## Running hdbsql
```bash
/usr/sap/HXE/HDB90/exe/hdbsql -i 90 -d SYSTEMDB -u LDAPUSER1 -p LdapPass123
```
