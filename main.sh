#!/bin/bash
echo "installing packages"
sudo ./setup.sh

echo "Setting up server"
sudo ./serverSetup.sh &
sleep 60

echo "Running mainForFlashdrive.py"
python3 mainForFlashdrive.py
echo "Done"