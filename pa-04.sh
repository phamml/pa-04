#!/bin/bash
echo
echo "Script to test pa-04"
echo "By: Mohamed Aboutabl"
echo

rm -f dispatcher   kdc/kdc             kdc/logKDC.txt    
rm -f amal/amal    amal/logAmal.txt  
rm -f basim/basim  basim/logBasim.txt
rm -f *.mp4

ln -s  ../bunny.mp4       bunny.mp4

echo
echo "=============================="
echo "Compiling Static source"
echo "=============================="
echo
gcc wrappers.c     dispatcher.c -o dispatcher


# make sure Aboutabl executable have the 'x' flag
chmod +x  *_aboutablEx*

echo
echo "*******************************************************"
echo "Testing STUDENT's Amal against Dr. Aboutabl's KDC+Basim"
echo "*******************************************************"
read -p "Press [Enter] key to continue ..."
echo

    cp  kdc_aboutablExecutable         kdc/kdc
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -l:libcrypto.so.1.1
    cp  basim_aboutablExecutable       basim/basim

    ./dispatcher

    echo
    echo "======  ABOUTABL'S  KDC    LOG  ========="
    cat kdc/logKDC.txt
    echo

    echo
    echo "======  STUDENT's   Amal   LOG  ========="
    cat amal/logAmal.txt

    echo
    echo "======  ABOUTABL's  Basim  LOG  ========="
    cat basim/logBasim.txt
    echo

echo
echo "********************************************************"
echo "Testing STUDENT's KDC  against Dr. Aboutabl's Amal+Basim"
echo "********************************************************"
read -p "Press [Enter] key to continue ..."
echo
    gcc kdc/kdc.c      myCrypto.c   -o kdc/kdc      -l:libcrypto.so.1.1
    cp  amal_aboutablExecutable        amal/amal
    cp  basim_aboutablExecutable       basim/basim
    
    ./dispatcher

    echo
    echo "======  STUDENT's   KDC    LOG  ========="
    cat kdc/logKDC.txt
    echo

    echo
    echo "======  ABOUTABL'S  Amal   LOG  ========="
    cat amal/logAmal.txt

    echo
    echo "======  ABOUTABL'S  Basim  LOG  ========="
    cat basim/logBasim.txt
    echo

echo
echo "*******************************************************"
echo "Testing STUDENT's Basim against Dr. Aboutabl's KDC+Amal"
echo "*******************************************************"
read -p "Press [Enter] key to continue ..."
echo

    cp  kdc_aboutablExecutable         kdc/kdc
    cp  amal_aboutablExecutable        amal/amal
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -l:libcrypto.so.1.1

    ./dispatcher

    echo
    echo "======  ABOUTABL'S  KDC    LOG  ========="
    cat kdc/logKDC.txt
    echo

    echo
    echo "======  ABOUTABL's  Amal   LOG  ========="
    cat amal/logAmal.txt

    echo
    echo "======  STUDENT's   Basim  LOG  ========="
    cat basim/logBasim.txt
    echo

echo
