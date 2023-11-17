#!/bin/bash

if command -v python3 &> /dev/null; then
    echo "Python 3 is installed. Version: $(python3 --version)"
else
    echo "Python 3 is not installed."
fi