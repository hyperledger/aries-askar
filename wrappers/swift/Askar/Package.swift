// swift-tools-version: 5.7
import PackageDescription

let package = Package(
    name: "Askar",
    platforms: [
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "Askar",
            targets: ["Askar"]),
    ],
    dependencies: [
    ],
    targets: [
        .target(
            name: "Askar",
            dependencies: ["aries_askarFFI"]),
        .testTarget(
            name: "AskarTests",
            dependencies: ["Askar"]),
        .binaryTarget(
            name: "aries_askarFFI",
            path: "../../../out/aries_askarFFI.xcframework"),
    ]
)
