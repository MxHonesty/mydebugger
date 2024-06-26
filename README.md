# ToyDebugger

This project is a debugger that target compiled language like C/C++.

It targets ELF binary and Dwarf format for the debug info.

This project has been modified to include 6 vulnerabilities.

## Getting Started

To begin with this project you just could clone it from github.

### Prerequisites

To make it work you need:
- libbfd
- capstone
- elf++/dwarf++

#### External dependencies
```
sudp apt install libcapstone-dev
sudo apt install binutils-dev
sudo apt install libreadline-dev
```

#### Libelfin dependency
Make sure you pulled this repository with the included git submodule libelfin
Building libelfin and exporting library path

```
cd ./external/libelfin
make install
export LD_LIBRARY_PATH=/usr/local/lib
```

### Installing

To compile the project:

```
mkdir build
cd build
cmake ..
make
```

It will create a binary called mygdb.

### How to use this debugger

Launch it:

```
./mygdb programm_to_debug
```

Access the helper:

```
Available command:
        b $addr: set a breakpoint at $addr
        c: Continue to the next breakpoint
        d: Disas from rip value
        d $0xaddr: Disas from 0xaddr
        h: print the helper of commands
        s: Go to next instruction
        p $register: print the value of the $register
        p 0xaddr: print the content at $addr
        l [n]: get [n]  line of the current source code

```

## Authors

* **Clement Magnard** - [Deltova](https://github.com/deltova)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
