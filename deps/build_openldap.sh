#!/bin/bash

export CFLAGS="-I$1"
export LIBRARY_PATH=`pwd`"/openssl-1.1.1k"
unset MAKELEVEL
unset MFLAGS
unset MAKEFLAGS
tar -vxf openldap-2.4.50.tgz
cd openldap-2.4.50
patch -p1 < ../exclude_dirs.patch
echo $CFLAGS
./configure
make VERBOSE=1 -j
cd libraries/liblber
ar cru ./liblber.a .libs/assert.o .libs/decode.o .libs/encode.o .libs/io.o .libs/bprint.o .libs/debug.o .libs/memory.o .libs/options.o .libs/sockbuf.o .libs/stdio.o .libs/version.o
cd ../libldap
ar cru ./libldap.a .libs/bind.o .libs/open.o .libs/result.o .libs/error.o .libs/compare.o .libs/search.o .libs/controls.o .libs/messages.o .libs/references.o .libs/extended.o .libs/cyrus.o .libs/modify.o .libs/add.o .libs/modrdn.o .libs/delete.o .libs/abandon.o .libs/sasl.o .libs/gssapi.o .libs/sbind.o .libs/unbind.o .libs/cancel.o .libs/filter.o .libs/free.o .libs/sort.o .libs/passwd.o .libs/whoami.o .libs/getdn.o .libs/getentry.o .libs/getattr.o .libs/getvalues.o .libs/addentry.o .libs/request.o .libs/os-ip.o .libs/url.o .libs/pagectrl.o .libs/sortctrl.o .libs/vlvctrl.o .libs/init.o .libs/options.o .libs/print.o .libs/string.o .libs/util-int.o .libs/schema.o .libs/charray.o .libs/os-local.o .libs/dnssrv.o .libs/utf-8.o .libs/utf-8-conv.o .libs/tls2.o .libs/tls_o.o .libs/tls_g.o .libs/tls_m.o .libs/turn.o .libs/ppolicy.o .libs/dds.o .libs/txn.o .libs/ldap_sync.o .libs/stctrl.o .libs/assertion.o .libs/deref.o .libs/ldif.o .libs/fetch.o .libs/version.o
