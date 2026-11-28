cmake_minimum_required(VERSION 3.20)
project(JerisLinkHost LANGUAGES CXX)

# JerisLink Windows host, phases H1 (screen capture, MF software H.264, MR02)
# and H2 (SendInput keyboard and mouse, cursor shape, HOST_INFO).
# Dev builds are unsigned (design doc D14, 2026-11-27).
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../../VERSION" JERISLINK_VERSION LIMIT_COUNT 1)
string(STRIP "${JERISLINK_VERSION}" JERISLINK_VERSION)
if(NOT JERISLINK_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
    message(FATAL_ERROR "VERSION must be MAJOR.MINOR.PATCH, got '${JERISLINK_VERSION}'")
endif()
message(STATUS "JerisLink host version ${JERISLINK_VERSION}-h2dev")

set(JERISLINK_HOST_DEFS UNICODE _UNICODE NOMINMAX _CRT_SECURE_NO_WARNINGS
    _WIN32_WINNT=0x0A00 WINVER=0x0A00 JERISLINK_VERSION_STRING="${JERISLINK_VERSION}-h2dev")
set(JERISLINK_HOST_LIBS ws2_32 ole32 oleaut32 mfplat mfuuid wmcodecdspuuid d3d11 dxgi user32 gdi32 uuid)

add_executable(JerisLinkHost host_main.cpp capture.cpp encoder_mf.cpp input_win.cpp)
target_compile_definitions(JerisLinkHost PRIVATE ${JERISLINK_HOST_DEFS})
target_link_libraries(JerisLinkHost PRIVATE ${JERISLINK_HOST_LIBS})

# Wire formats against the viewer's own parsers (video, HOST_INFO, keymap),
# input decoding and pointer mapping, colour values, and an encoder loopback
# through the real MF software encoder. Nothing here injects input.
add_executable(JerisLinkHostTest host_test.cpp encoder_mf.cpp)
target_compile_definitions(JerisLinkHostTest PRIVATE ${JERISLINK_HOST_DEFS})
target_link_libraries(JerisLinkHostTest PRIVATE ${JERISLINK_HOST_LIBS})

if(MSVC)
    target_compile_options(JerisLinkHost PRIVATE /W3 /utf-8)
    target_compile_options(JerisLinkHostTest PRIVATE /W3 /utf-8)
endif()
