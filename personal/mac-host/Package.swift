// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "JerisLink",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "JerisLinkHost", targets: ["JerisLinkHost"])
    ],
    targets: [
        // libopus 1.6.1, vendored in personal/third_party/opus by
        // update-opus.sh. Sources/COpus is a symlink to it because SwiftPM
        // targets must live under the package root. Portable C only: no
        // SIMD / RTCD, no DNN. Warnings off: third-party code, built as is.
        .target(
            name: "COpus",
            path: "Sources/COpus",
            publicHeadersPath: "include",
            cSettings: [
                .define("OPUS_BUILD"),
                .define("USE_ALLOCA"),
                .define("HAVE_ALLOCA_H"),
                .define("HAVE_LRINTF"),
                .define("HAVE_LRINT"),
                .headerSearchPath("."),
                .headerSearchPath("celt"),
                .headerSearchPath("silk"),
                .headerSearchPath("silk/float"),
                .headerSearchPath("src"),
                .unsafeFlags(["-w"])
            ]
        ),
        // Non-variadic opus_encoder_ctl wrappers for Swift.
        .target(
            name: "COpusShim",
            dependencies: ["COpus"],
            path: "Sources/COpusShim",
            publicHeadersPath: "include"
        ),
        .executableTarget(
            name: "JerisLinkHost",
            dependencies: ["COpus", "COpusShim"],
            linkerSettings: [
                .linkedFramework("ScreenCaptureKit"),
                .linkedFramework("VideoToolbox"),
                .linkedFramework("CoreMedia"),
                .linkedFramework("CoreVideo"),
                .linkedFramework("Carbon"),
                .linkedFramework("AppKit"),
                .linkedFramework("ServiceManagement"),
                .linkedFramework("IOKit")
            ]
        )
    ]
)
