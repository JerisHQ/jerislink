cmake_minimum_required(VERSION 3.20)
project(Jerislink LANGUAGES C CXX RC)

# The Microsoft Store (MSIX) build links the C runtime statically, so the package
# needs no VCLibs framework dependency. The normal and Inno Setup builds keep the
# default dynamic runtime (/MD).
option(JERISLINK_STATIC_CRT "Link the MSVC runtime statically (/MT); used by the MSIX build" OFF)
if(JERISLINK_STATIC_CRT)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
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

# libopus (BSD-3-Clause), vendored at a pinned release by
# ../third_party/update-opus.sh: the portable float C sources only.
set(OPUS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/opus")
file(GLOB OPUS_SOURCES CONFIGURE_DEPENDS
    "${OPUS_DIR}/celt/*.c" "${OPUS_DIR}/silk/*.c" "${OPUS_DIR}/silk/float/*.c" "${OPUS_DIR}/src/*.c")
add_library(opus STATIC ${OPUS_SOURCES})
target_compile_definitions(opus PRIVATE OPUS_BUILD USE_ALLOCA HAVE_LRINTF HAVE_LRINT)
target_include_directories(opus PRIVATE "${OPUS_DIR}" "${OPUS_DIR}/celt" "${OPUS_DIR}/silk" "${OPUS_DIR}/silk/float"
                                        "${OPUS_DIR}/src"
                                PUBLIC "${OPUS_DIR}/include")
if(MSVC)
    target_compile_options(opus PRIVATE /w)
endif()

set(JERISLINK_LIBS ws2_32 ole32 mfplat mf mfuuid wmcodecdspuuid user32 gdi32 iphlpapi dwmapi d3d11 dxgi advapi32 avrt bcrypt)

add_executable(Jerislink WIN32 viewer.cpp clipboard_channel.cpp file_session.cpp hardware_video_pipeline.cpp video_decoder_factory.cpp jerislink.rc)
target_compile_definitions(Jerislink PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_include_directories(Jerislink PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(Jerislink PRIVATE ${JERISLINK_LIBS} opus comctl32)
if(MSVC)
    target_link_options(Jerislink PRIVATE "/MANIFEST:EMBED" "/MANIFESTINPUT:${CMAKE_CURRENT_BINARY_DIR}/jerislink.manifest")
endif()

# CI-only: the real settings / volume dialogs rendered to BMP for review.
# Not installed or packaged.
add_executable(JerislinkUiSnapshot WIN32 EXCLUDE_FROM_ALL viewer.cpp clipboard_channel.cpp file_session.cpp hardware_video_pipeline.cpp video_decoder_factory.cpp jerislink.rc)
target_compile_definitions(JerislinkUiSnapshot PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX JERISLINK_UI_SNAPSHOT)
target_include_directories(JerislinkUiSnapshot PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(JerislinkUiSnapshot PRIVATE ${JERISLINK_LIBS} opus comctl32)
if(MSVC)
    target_link_options(JerislinkUiSnapshot PRIVATE "/MANIFEST:EMBED" "/MANIFESTINPUT:${CMAKE_CURRENT_BINARY_DIR}/jerislink.manifest")
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

# Console unit test for the MRA1 audio jitter buffer (audio_jitter.hpp).
add_executable(JerislinkAudioTest audio_jitter_test.cpp)
target_link_libraries(JerislinkAudioTest PRIVATE opus)

# Console unit test for the in-session overlay maths (ui_overlay.hpp).
add_executable(JerislinkOverlayTest ui_overlay_test.cpp)

# Console unit test for the H.264 slice / NAL summary and its log budget (h264_nal_summary.hpp).
add_executable(JerislinkNalSummaryTest h264_nal_summary_test.cpp)

# Console golden test for the Windows -> Mac key mapping (keymap.hpp).
add_executable(JerislinkKeymapTest keymap_test.cpp)

# Console tests for the file transfer wire and received-path rules (file_proto.hpp, file_path_safety.hpp).
add_executable(JerislinkFileProtoTest file_proto_test.cpp)
add_executable(JerislinkFilePathTest file_path_safety_test.cpp)
target_compile_definitions(JerislinkFilePathTest PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(JerislinkFilePathTest PRIVATE normaliz)

# Console test for the Windows -> Mac paste hold, pacer, chip and disconnect confirm (file_upload.hpp).
add_executable(JerislinkFileUploadTest file_upload_test.cpp)
