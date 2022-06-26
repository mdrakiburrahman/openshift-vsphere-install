#!/bin/bash

echo "Configuring DNS hack..."

cat << EOF > /etc/resolv.conf
# DNS requests are forwarded to the host. DHCP DNS options are ignored.
nameserver 10.216.175.4                 # OCPLab-DC.fg.contoso.com
EOF

exec "$@"