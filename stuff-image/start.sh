#!/bin/bash

# curls tarball of necessary files
curl -LJO https://api.github.com/repos/TAplutos/autosploit/tarball/flashdrive -o flashdrive.tar.gz

mkdir autosploitFlashdrive

tar -xvzf flashdrive.tar.gz -C autosploitFlashdrive --strip-compoonents=1

cd autosploitFlashdrive
sudo chmod +x main.sh
./main.sh