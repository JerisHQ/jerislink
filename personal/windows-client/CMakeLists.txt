cmake_minimum_required(VERSION 3.20)
project(Jerislink LANGUAGES CXX RC)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Single source of the version: VERSION at the repository root.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../../VERSION" JERISLINK_VERSION LIMIT_COUNT 1)
string(STRIP "${JERISLINK_VERSION}" JERISLINK_VERSION)
if(NOT JERISLINK_VERSION MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
    message(FATAL_ERROR "VERSION must be MAJOR.MINOR.PATCH, got '${JERISLINK_VERSION}'")
endif()
set(JERISLINK_VERSION_MAJOR ${CMAKE_MATCH_1})
set(JERISLINK_VERSION_MINOR ${CMAKE_MATCH_2})
set(JERISLINK_VERSION_PATCH ${CMAKE_MATCH_3})
configure_file(version.h.in ${CMAKE_CURRENT_BINARY_DIR}/version.h @ONLY)
configure_file(jerislink.manifest.in ${CMAKE_CURRENT_BINARY_DIR}/jerislink.manifest @ONLY)
configure_file(setup.manifest.in ${CMAKE_CURRENT_BINARY_DIR}/setup.manifest @ONLY)
message(STATUS "JerisLink version ${JERISLINK_VERSION}")

set(JERISLINK_LIBS ws2_32 ole32 mfplat mf mfuuid wmcodecdspuuid user32 gdi32 iphlpapi dwmapi d3d11 dxgi advapi32)

add_executable(Jerislink WIN32 viewer.cpp clipboard_channel.cpp hardware_video_pipeline.cpp video_decoder_factory.cpp jerislink.rc)
target_compile_definitions(Jerislink PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_include_directories(Jerislink PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(Jerislink PRIVATE ${JERISLINK_LIBS})
if(MSVC)
    target_link_options(Jerislink PRIVATE "/MANIFEST:EMBED" "/MANIFESTINPUT:${CMAKE_CURRENT_BINARY_DIR}/jerislink.manifest")
endif()

configure_file(setup.rc.in ${CMAKE_CURRENT_BINARY_DIR}/setup.generated.rc @ONLY)
add_executable(JerislinkSetup WIN32 setup_gui.cpp ${CMAKE_CURRENT_BINARY_DIR}/setup.generated.rc)
target_compile_definitions(JerislinkSetup PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_include_directories(JerislinkSetup PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(JerislinkSetup PRIVATE ole32 shell32 advapi32 user32 gdi32 dwmapi)
if(MSVC)
    target_link_options(JerislinkSetup PRIVATE "/MANIFEST:EMBED" "/MANIFESTINPUT:${CMAKE_CURRENT_BINARY_DIR}/setup.manifest")
endif()

option(JERISLINK_BUILD_DIAGNOSTICS "Build decoder/control diagnostic probes" OFF)
if(JERISLINK_BUILD_DIAGNOSTICS)
    add_executable(JerislinkDecodeProbe decoder_probe.cpp)
    target_compile_definitions(JerislinkDecodeProbe PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(JerislinkDecodeProbe PRIVATE ${JERISLINK_LIBS})

    add_executable(JerislinkControlProbe control_client.cpp)
    target_compile_definitions(JerislinkControlProbe PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(JerislinkControlProbe PRIVATE ws2_32)
endif()

# Console unit test for the launch-config rules (viewer_options.hpp).
add_executable(JerislinkOptionsTest viewer_options_test.cpp)

# Console unit test for the MR02 receive / NACK logic (video_receiver.hpp).
add_executable(JerislinkReceiverTest video_receiver_test.cpp)

# Console test for the receive-loop wait set and timer period (loop_wait.hpp).
add_executable(JerislinkLoopWaitTest loop_wait_test.cpp)
target_compile_definitions(JerislinkLoopWaitTest PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
# Console test for the async, size-capped viewer logger (viewer_log.hpp).
add_executable(JerislinkLogTest viewer_log_test.cpp)
target_compile_definitions(JerislinkLogTest PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

# Console test: every mouse button down sent to the host gets one up (mouse_buttons.hpp).
add_executable(JerislinkMouseButtonsTest mouse_buttons_test.cpp)
