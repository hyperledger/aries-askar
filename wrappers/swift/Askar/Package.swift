// swift-tools-version: 5.7
import PackageDescription

let package = Package(
    name: "Askar",
    platforms: [
        .iOS(.v15)
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
            dependencies: ["AskarFramework"]),
        .testTarget(
            name: "AskarTests",
            dependencies: ["Askar"]),
        .binaryTarget(
            name: "AskarFramework",
            url: "https://github.com/hyperledger/aries-framework-swift/releases/download/binary-release-askar-v0.2.7/AskarFramework.xcframework.zip",
            checksum: "265fcb222a663866d18d4343415376f72c9e8f6f379a82b96f44dba6f26906ba"
        ),
    ]
)
