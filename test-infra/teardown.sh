#!/bin/bash
set -e

echo "=== Stopping and removing containers ==="
podman-compose down

echo ""
echo "=== Removing volumes (optional) ==="
read -p "Remove persistent volumes? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    podman volume rm test-infra_ldap-data test-infra_ldap-config test-infra_hana-data 2>/dev/null || true
    echo "Volumes removed."
else
    echo "Volumes preserved."
fi

echo ""
echo "=== Teardown complete ==="
