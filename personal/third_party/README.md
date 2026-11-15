# Third-party code

## opus/

libopus 1.6.1 (BSD-3-Clause, see `opus/COPYING`), used for MRA1 v2 audio
(48 kHz stereo, 10 ms frames, 128 kbps) by the Mac host (encoder) and the
Windows viewer (decoder).

Only the portable float C sources and their headers are kept: no DNN (deep
PLC, DRED, OSCE), no SIMD or architecture-specific code, no tests, demos or
build system. Do not edit files under `opus/`; to update, change `VERSION`
and `SHA256` in `update-opus.sh` and run it:

    ./update-opus.sh   # downloads, checks SHA-256, rewrites opus/

Builds:
- Mac: SwiftPM target `COpus` (`mac-host/Sources/COpus` is a symlink here).
- Windows: CMake static library `opus` in `windows-client/CMakeLists.txt`.
Both define `OPUS_BUILD USE_ALLOCA HAVE_LRINTF HAVE_LRINT` (plus
`HAVE_ALLOCA_H` on the Mac).
