cmake_minimum_required (VERSION 2.8)

SET(SUB_DIR_LIST "${CMAKE_CURRENT_SOURCE_DIR}/common" "${CMAKE_CURRENT_SOURCE_DIR}/account" "${CMAKE_CURRENT_SOURCE_DIR}/firewall" 
"${CMAKE_CURRENT_SOURCE_DIR}/base" "${CMAKE_CURRENT_SOURCE_DIR}/password"
 "${CMAKE_CURRENT_SOURCE_DIR}/antivirus" "${CMAKE_CURRENT_SOURCE_DIR}")

foreach(SUB_DIR ${SUB_DIR_LIST})
    aux_source_directory(${SUB_DIR} SRC_LIST)
endforeach()

SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../build)

INCLUDE_DIRECTORIES("/usr/include/libxml2/")
INCLUDE_DIRECTORIES("/usr/local/include/")
INCLUDE_DIRECTORIES("common")
INCLUDE_DIRECTORIES("account")
INCLUDE_DIRECTORIES("firewall")
INCLUDE_DIRECTORIES("base")
INCLUDE_DIRECTORIES("antivirus")
INCLUDE_DIRECTORIES("password")
INCLUDE_DIRECTORIES("${CMAKE_CURRENT_SOURCE_DIR}")


LINK_DIRECTORIES("/usr/lib64")
LINK_DIRECTORIES("/usr/local/lib64/")

ADD_DEFINITIONS("-g")

ADD_EXECUTABLE(ksc-defender ${SRC_LIST})

TARGET_LINK_LIBRARIES(ksc-defender "libxml2.so")
TARGET_LINK_LIBRARIES(ksc-defender "libpwquality.so")
TARGET_LINK_LIBRARIES(ksc-defender "libsqlite3.so")
TARGET_LINK_LIBRARIES(ksc-defender "libclamav.so")
TARGET_LINK_LIBRARIES(ksc-defender "libfreshclam.so")

INSTALL(TARGETS ksc-defender RUNTIME DESTINATION bin)

INSTALL(DIRECTORY ../conf/kylin-firewall DESTINATION /etc)

INSTALL(DIRECTORY ../conf/antivirus  DESTINATION /usr/share/ksc-defender)

INSTALL(DIRECTORY ../conf/kylin-password  DESTINATION /usr/share/ksc-defender)

