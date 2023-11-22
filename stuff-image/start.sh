#!/bin/bash

# Set the URL and output file
URL="https://api.github.com/repos/TAplutos/autosploit/tarball/flashdrive"
OUTPUT_FILE="flashdrive.tar.gz"

# Curl tarball of necessary files
curl -LJO $URL -o $OUTPUT_FILE

# Create autosploitFlashdrive directory
mkdir autosploitFlashdrive 

# Navigate into autosploitFlashdrive directory
cd autosploitFlashdrive

# Extract the tarball
tar -xvzf ../$OUTPUT_FILE --strip-components=1

# Make main.sh executable
chmod +x main.sh

# Run main.sh
./main.sh