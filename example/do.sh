#!/bin/bash


function green() { echo -e "\033[0;32m$1\033[0m"; }
function red()   { echo -e "\033[0;31m$1\033[0m"; }

:<<"END"
    green "GREEN ECHO!"
    red "RED ECHO!"
END

LOOP_CNT=`cat test_common.h | grep LOOP | tr -d ''| cut -d " " -f3`
BUFFER_SIZE=`cat test_common.h | grep " BUFFER_SIZE" | tr -d '' |cut -d " " -f3`
PLAIN_SIZE=`stat -c "%s" "plaintext.txt"`
FAIL_FLAG=0

echo "#### Info"
echo "- LOOP COUNT: ${LOOP_CNT}"
echo "- TEXT SIZE: ${PLAIN_SIZE}"
echo "- BUFFER SIZE: ${BUFFER_SIZE}"
echo

echo "### Fast OpenSSL"
echo "- ENCRYPT"
./AES_encrypt_fast e46858715f6ca44839c66579759307a2332bb751a28b254e8b5347ac193efd61 0ee5c8893a86718f5a0d9852
echo

echo "- DECRYPT"
./AES_decrypt_fast e46858715f6ca44839c66579759307a2332bb751a28b254e8b5347ac193efd61
echo 
echo


echo "### Original OpenSSL"
echo "- ENCRYPT"
./AES_encrypt e46858715f6ca44839c66579759307a2332bb751a28b254e8b5347ac193efd61 0ee5c8893a86718f5a0d9852
echo

echo "- DECRYPT"
./AES_decrypt e46858715f6ca44839c66579759307a2332bb751a28b254e8b5347ac193efd61
echo 

echo "### Check result"
echo "- Check diff encrypt.fast encrypt.norm"
if diff -q encrypt.fast encrypt.norm > /dev/null; then
    echo "Encrypt fast and norm are the Same..."
else
    FAIL_FLAG=1
    echo "Encrypt fast and norm are the Different!!!"
fi
echo

echo "- Check diff decrypt.fast decrypt.norm"
if diff -q decrypt.fast decrypt.norm > /dev/null; then
    echo "Decrypt fast and norm are the Same..."
else
    FAIL_FLAG=1
    echo "Decrypt fast and norm are the Different!!!"
fi
echo

echo "Test Result"
if [ ${FAIL_FLAG} == 1 ]; then
    red "[FAIL] Comparison test failed!!!"
else
    green "[SUCCESS] Comparison test successful..."

fi
