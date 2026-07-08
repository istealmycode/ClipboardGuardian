// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "ClipboardGuardian",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "ClipboardGuardian",
            targets: ["ClipboardGuardian"]
        ),
        .executable(
            name: "ClipboardGuardianApp",
            targets: ["ClipboardGuardianApp"]
        ),
    ],
    dependencies: [
        .package(path: "Dependencies/swift-corelibs-xctest")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "ClipboardGuardian"
        ),
        .executableTarget(
            name: "ClipboardGuardianApp",
            dependencies: ["ClipboardGuardian"]
        ),
        .testTarget(
            name: "ClipboardGuardianTests",
            dependencies: [
                "ClipboardGuardian",
                .product(name: "XCTest", package: "swift-corelibs-xctest")
            ]
        ),
    ]
)
