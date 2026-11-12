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
        .executableTarget(
            name: "JerisLinkHost",
            linkerSettings: [
                .linkedFramework("ScreenCaptureKit"),
                .linkedFramework("VideoToolbox"),
                .linkedFramework("CoreMedia"),
                .linkedFramework("CoreVideo"),
                .linkedFramework("Carbon"),
                .linkedFramework("AppKit"),
                .linkedFramework("ServiceManagement")
            ]
        )
    ]
)
