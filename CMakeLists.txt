CMAKE_MINIMUM_REQUIRED(VERSION 3.1.0)
SET(PACKAGE_NAME "MYGDB")
SET(MYGDB "mygdb")
SET(INCLUDE_DIRS "include")
set(CMAKE_CXX_STANDARD 17)
PROJECT(${MYGDB} CXX)

ADD_EXECUTABLE(${MYGDB} src/main.cc src/misc/register.cc 
    src/memory/memory_mapping.cc 
    src/elf/info_elf.cc src/debugger/debugger.cc
    src/debugger/debugger-dwarf.cc src/analysis/engine.cc
    src/analysis/external_engine.cc
)

add_compile_options("-std=c++17" "-pedantic" "-no-pie")

TARGET_INCLUDE_DIRECTORIES(${MYGDB} PUBLIC "include")
TARGET_INCLUDE_DIRECTORIES(${MYGDB} PUBLIC "src/analysis")
TARGET_INCLUDE_DIRECTORIES(${MYGDB} PUBLIC "src/parser")
TARGET_INCLUDE_DIRECTORIES(${MYGDB} PUBLIC "src/debugger")
TARGET_INCLUDE_DIRECTORIES(${MYGDB} PUBLIC "src/elf")
TARGET_INCLUDE_DIRECTORIES(${MYGDB} PUBLIC "src/memory")
TARGET_INCLUDE_DIRECTORIES(${MYGDB} PUBLIC "src/misc")
add_subdirectory("src/file-cacher")

target_compile_options(${MYGDB} PUBLIC "-lstdc++fs")
target_link_libraries(${MYGDB} PUBLIC "-lstdc++fs")
target_link_libraries(${MYGDB} PUBLIC bfd)
target_link_libraries(${MYGDB} PUBLIC capstone)
target_link_libraries(${MYGDB} PUBLIC elf++)
target_link_libraries(${MYGDB} PUBLIC dwarf++)
target_link_libraries(${MYGDB} PUBLIC readline)
target_link_libraries(${MYGDB} PUBLIC filecacher)
