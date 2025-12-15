#!/bin/bash
# Build script for StreamGuard Python extension

set -e

echo "Building StreamGuard Python extension..."
echo

# Check Python version
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "Python version: $PYTHON_VERSION"

# Check if maturin is installed
if ! command -v maturin &> /dev/null; then
    echo "Installing maturin..."
    python3 -m pip install --user maturin
fi

# Build the extension
echo "Building native extension..."
maturin develop --release --features python

echo
echo "✅ Build complete!"
echo
echo "Run the demo:"
echo "  python3 demo.py"
