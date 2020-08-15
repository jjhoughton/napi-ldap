#!/bin/bash

unset MAKELEVEL
unset MFLAGS
unset MAKEFLAGS
tar -vxf openssl-1.1.1g.tar.gz
cd openssl-1.1.1g
./Configure linux-x86_64
make VERBOSE=1 -j9
