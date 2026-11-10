// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "Lockd",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "Lockd", targets: ["Lockd"]),
        .executable(name: "lockdctl", targets: ["lockdctl"]),
    ],
    targets: [
        .target(name: "LockdCore"),
        .executableTarget(name: "Lockd", dependencies: ["LockdCore"]),
        .executableTarget(name: "lockdctl", dependencies: ["LockdCore"]),
        .testTarget(name: "LockdCoreTests", dependencies: ["LockdCore"]),
    ],
    swiftLanguageModes: [.v5]
)
