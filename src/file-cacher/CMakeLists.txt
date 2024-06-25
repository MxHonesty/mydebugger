cmake_minimum_required(VERSION 3.1)

project(filecacher)
file(GLOB SOURCES "*.cc")
add_library(filecacher SHARED ${SOURCES})

set_target_properties(filecacher PROPERTIES CXX_STANDARD 17)
include_directories(../../${INCLUDE_DIRS})
