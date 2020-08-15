#!/bin/sh

os=$(uname -s | tr '[:upper:]' '[:lower:]')

MKDIR=/bin/mkdir
RM=/bin/rm
KILL=/bin/kill
SLAPADD=/usr/sbin/slapadd

if [[ "$os" == "darwin" ]]; then
  SLAPD=/usr/libexec/slapd
else
  SLAPD=/usr/sbin/slapd
fi

$RM -rf openldap-data
$MKDIR openldap-data

$SLAPADD -f slapd.$os.conf < startup.ldif
$SLAPD -d999 -f slapd.$os.conf -h "ldap://:1234 ldapi://%2ftmp%2fslapd.sock ldaps://localhost:1235"
SLAPD_PID=$!
# slapd should be running now

