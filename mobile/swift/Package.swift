// swift-tools-version:5.9
//
// Swift Package Manager manifest for the Sidevers mobile SDK.
//
// Consumers add this as a local or remote SwiftPM dependency:
//
//   dependencies: [
//       .package(path: "../sidevers-protocol/mobile/swift"),
//   ],
//   targets: [
//       .target(name: "MyApp", dependencies: [
//           .product(name: "Sidevers", package: "swift"),
//       ]),
//   ]
//
// Before consuming, build the xcframework via:
//
//   ./mobile/build-ios.sh
//
// which produces `Frameworks/SideversFFI.xcframework`.

import PackageDescription

let package = Package(
    name: "Sidevers",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(name: "Sidevers", targets: ["Sidevers"]),
    ],
    targets: [
        // The pre-built xcframework wrapping libsidevers.a + the C header.
        .binaryTarget(
            name: "SideversFFI",
            path: "Frameworks/SideversFFI.xcframework"
        ),
        // Idiomatic Swift wrappers around the C ABI.
        .target(
            name: "Sidevers",
            dependencies: ["SideversFFI"],
            path: "Sources/Sidevers"
        ),
        .testTarget(
            name: "SideversTests",
            dependencies: ["Sidevers"],
            path: "Tests/SideversTests"
        ),
    ]
)
