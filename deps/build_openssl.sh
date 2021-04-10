#!/bin/bash

unset MAKELEVEL
unset MFLAGS
unset MAKEFLAGS
tar -vxf openssl-1.1.1k.tar.gz
cd openssl-1.1.1k
./Configure linux-x86_64
make VERBOSE=1 -j
