#!/bin/bash
# Build script for StreamGuard Java demo

set -e

echo "Building StreamGuard Java Demo"
echo "==============================="
echo

# Detect OS and set library name
OS=$(uname -s)
case "$OS" in
    Darwin*)
        LIB_NAME="libstreamguard.dylib"
        ;;
    Linux*)
        LIB_NAME="libstreamguard.so"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        LIB_NAME="streamguard.dll"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

echo "Step 1: Building native library..."
cd ../..
cargo build --release --features java

if [ ! -f "target/release/$LIB_NAME" ]; then
    echo "Error: Native library not found at target/release/$LIB_NAME"
    exit 1
fi

echo "✓ Native library built: target/release/$LIB_NAME"
echo

echo "Step 2: Compiling Java sources..."
cd examples/java-demo
mvn clean compile

echo "✓ Java compilation complete"
echo

echo "Step 3: Running demo..."
echo
mvn exec:java -Djava.library.path=../../target/release

echo
echo "✅ Build complete!"
echo
echo "To run the demo manually:"
echo "  mvn exec:java -Djava.library.path=../../target/release"
