# libb2

C library providing BLAKE2b, BLAKE2s, BLAKE2bp, BLAKE2sp

## Installation

### Autotools
```
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
```

### CMake
On Windows CMake can generate make/project files for Visual Studio, MinGW and Clang.
The install target will create and install a proper package config. The import project is called `libb2`.

Please note that the CMake project is incapable of configuring OpenMP support on Clang.

## Contact
[contact@blake2.net](mailto:contact@blake2.net)
