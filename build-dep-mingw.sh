#!/bin/bash

PWD="`pwd`"
VENDOR="$PWD/build/vendor"

cd build
curl http://zlib.net/zlib-1.2.11.tar.gz -o zlib.tar.gz
tar xf zlib.tar.gz
curl https://raw.githubusercontent.com/Alexpux/MSYS2-packages/master/zlib/1.2.7-minizip-cygwin.patch -o 1.2.7-minizip-cygwin.patch
curl https://raw.githubusercontent.com/Alexpux/MSYS2-packages/master/zlib/1.2.7-zlib-symbols.patch -o 1.2.7-zlib-symbols.patch
curl https://raw.githubusercontent.com/Alexpux/MSYS2-packages/master/zlib/1.2.11-cygwin-no-widechar.patch -o 1.2.11-cygwin-no-widechar.patch
curl https://raw.githubusercontent.com/Alexpux/MSYS2-packages/master/zlib/zlib-1.2.11-msys2.patch -o zlib-1.2.11-msys2.patch
cd zlib-1.2.11
patch -p2 -i ../1.2.7-minizip-cygwin.patch
patch -p2 -i ../1.2.7-zlib-symbols.patch
patch -p1 -i ../1.2.11-cygwin-no-widechar.patch
patch -p1 -i ../zlib-1.2.11-msys2.patch
./configure --prefix="$VENDOR/zlib"
make
make install
cd ..
rm -rf zlib*
rm *.patch

curl https://codeload.github.com/libressl-portable/portable/tar.gz/v2.5.3 -o libressl.tar.gz
tar xf libressl.tar.gz
cd portable-2.5.3
./autogen.sh
./configure --prefix="$VENDOR/libressl"
make -j4
make install
cd ..
rm -rf portable*
rm libressl*
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$VENDOR/libressl/lib"

curl -L https://github.com/nghttp2/nghttp2/releases/download/v1.22.0/nghttp2-1.22.0.tar.gz -o nghttp2.tar.gz
tar xf nghttp2.tar.gz
cd nghttp2-1.22.0
./configure --prefix="$VENDOR/nghttp2" OPENSSL_LIBS="-L$VENDOR/libressl/lib -lssl -lcrypto" --enable-lib-only
make
make install
cd ..
rm -rf nghttp2*
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$VENDOR/nghttp2/lib"

curl https://curl.haxx.se/download/curl-7.54.0.tar.gz -o curl.tar.gz
mkdir -p "$VENDOR/curl/etc"
curl https://curl.haxx.se/ca/cacert.pem -o "$VENDOR/curl/etc/cacert.pem"
tar xf curl.tar.gz
cd curl-7.54.0
./configure --prefix="$VENDOR/curl" --with-zlib="$VENDOR/zlib" --with-ca-bundle="$VENDOR/curl/etc/cacert.pem" \
            --with-ssl="$VENDOR/libressl" --with-nghttp2="$VENDOR/nghttp2" --without-libidn --without-libssh2 \
            --without-librtmp --without-libmetalink --disable-ldap --without-libpsl
make
make install
cd ..
rm -rf curl*

curl http://www.digip.org/jansson/releases/jansson-2.10.tar.gz -o jansson.tar.gz
tar xf jansson.tar.gz
cd jansson-2.10
./configure --prefix="$VENDOR/jansson"
make
make install
cd ..
rm -rf jansson*
