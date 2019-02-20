cmake_minimum_required (VERSION 3.5)
project(ahsbt)

set(CMAKE_CXX_STANDARD 11)

if (UNIX)
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")
endif (UNIX)


find_package (CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIR})
link_directories( ${CURL_LIBRARIES} )


add_executable (ahsbt "ahsbt.cpp")
target_link_libraries(ahsbt curl)
