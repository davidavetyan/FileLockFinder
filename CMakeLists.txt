cmake_minimum_required(VERSION 3.16)

set(TARGET_NAME FileLockFinder)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/FileLockFinder.cpp
)

set(RC
    ${CMAKE_CURRENT_LIST_DIR}/FileLockFinder.rc
)

add_executable(${TARGET_NAME} ${SOURCES} ${RC})

find_path(PHNT_INCLUDE_DIRS "ntd3dkmt.h")
target_include_directories(${TARGET_NAME} PRIVATE ${PHNT_INCLUDE_DIRS})

target_link_libraries(${TARGET_NAME} ntdll)
