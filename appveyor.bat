rem Matrix-driven Appveyor CI script for cclone
rem Currently only does MSYS2 builds.
rem https://www.appveyor.com/docs/installed-software#mingw-msys-cygwin
rem Needs the following vars:
rem    MSYS2_ARCH:  x86_64 or i686
rem    MSYSTEM:  MINGW64 or MINGW32

rem Set the paths appropriately
PATH C:\msys64\%MSYSTEM%\bin;C:\msys64\usr\bin;%PATH%

rem Upgrade the MSYS2 platform
bash -lc "pacman -S --needed --noconfirm pacman-mirrors"
bash -lc "pacman -Syu --noconfirm"

rem Install required tools
bash -xlc "pacman --noconfirm -S --needed base-devel autoconf automake libtool make patch curl"

rem Invoke subsequent bash in the build tree
cd %APPVEYOR_BUILD_FOLDER%
set CHERE_INVOKING=yes

rem Build/test scripting
bash -xlc "set pwd"
bash -xlc "env"

bash -xlc "./build-dep-mingw.sh"
bash -xlc "./build-mingw.sh"
