#!/bin/bash

cd build
mkdir -p debug
mkdir -p release
echo -e "\nBuild Debug:\n"
cd debug && cmake -DCMAKE_BUILD_TYPE=Debug ../.. && make -j4
echo -e "\nBuild Release:\n"
cd ../release && cmake -DCMAKE_BUILD_TYPE=Release ../.. && make -j4
cd ../../bin/release
echo -e "\nRun cclone:"
./cclone
echo -e "\nRun test-cclone:"
./test-cclone