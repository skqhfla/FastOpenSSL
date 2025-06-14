#!/bin/bash

cd ../openssl
make clean; make; make install
cd ../example
make clean; make
./do.sh
