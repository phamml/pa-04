#!/bin/bash
echo
echo "Script to generate Master Keys for Amal and Basim"
echo "By: Mohamed Aboutabl"
echo

rm -f genMasterKey   
rm -f kdc/*.bin           amal/*.bin         basim/*.bin

echo
echo "========================================"
echo "Compiling source code for genMasterKey.c"
echo "========================================"
echo
	gcc genMasterKey.c -o genMasterKey -l:libcrypto.so.1.1

echo
echo "========================================="
echo "Generating Master Keys for Amal and Basim"
echo "========================================="
echo

./genMasterKey  amal
./genMasterKey  basim

echo "Sharing those Master Keys with the KDC"
cd   kdc
ln  -s ../amal/amalKey.bin   amalKey.bin
ln  -s ../amal/amalIV.bin    amalIV.bin
ln  -s ../basim/basimKey.bin basimKey.bin
ln  -s ../basim/basimIV.bin  basimIV.bin
cd ..
