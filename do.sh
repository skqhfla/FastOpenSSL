#!/bin/bash


echo "ENCRYPT"
./AES_encrypt_fast e46858715f6ca44839c66579759307a2332bb751a28b254e8b5347ac193efd61 2>enc_iv.txt
echo

echo "DECRYPT"
./AES_decrypt_fast e46858715f6ca44839c66579759307a2332bb751a28b254e8b5347ac193efd61 2>dec_iv.txt
