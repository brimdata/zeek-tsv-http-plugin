
cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(ZeekPluginTsvHttp)

include(ZeekPlugin)


include(FindCURL)

message("CURL_INCLUDE_DIRS: ${CURL_INCLUDE_DIRS}")
message("CURL_LIBRARIES: ${CURL_LIBRARIES}")
message("CURL_VERSION_STRING: ${CURL_VERSION_STRING}")

if ( CURL_FOUND )

    zeek_plugin_begin(Zeek TsvHttp)
    zeek_plugin_cc(src/TsvHttp.cc)
    zeek_plugin_cc(src/Plugin.cc)
    zeek_plugin_bif(src/tsvhttp.bif)
    zeek_plugin_dist_files(README.md CHANGES COPYING VERSION)
    zeek_plugin_link_library(${CURL_LIBRARIES})
    zeek_plugin_end()

    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

    if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
        # Allows building rpm/deb packages via "make package" in build dir.
        include(ConfigurePackaging)
        ConfigurePackaging(${VERSION})
    endif ()
else ()
    message(FATAL_ERROR "LibCURL not found.")
endif ()
