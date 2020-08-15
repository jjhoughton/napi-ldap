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

if [[ -f slapd.pid ]] ; then
  $RM slapd.pid
fi

$SLAPADD -f $SLAPD_CONF < startup.ldif
$SLAPADD -f $SLAPD_CONF < sasl.ldif
$SLAPD -d999 -f sasl.$os.conf -hldap://localhost:1234 > sasl.log 2>&1 &

if [[ ! -f slapd.pid ]] ; then
  sleep 1
fi

# Make sure SASL is enabled
if ldapsearch -H ldap://localhost:1234 -x -b "" -s base -LLL \
    supportedSASLMechanisms | grep -q SASL ; then
    :
else
    echo slapd started but SASL not supported
fi
