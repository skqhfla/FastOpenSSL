#!/bin/bash

cp plaintext.txt.65504 plaintext.txt
./do.sh
echo


cp plaintext.txt.8800 plaintext.txt
./do.sh
echo

cp plaintext.txt.short plaintext.txt
./do.sh
echo

:<<"END"
cp plaintext.txt.65500 plaintext.txt
./do.sh
echo

cp plaintext.txt.under_16 plaintext.txt
./do.sh
echo
END
