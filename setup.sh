#!/bin/bash
sudo apt-get update
sudo apt-get update --fix-missing
sudo apt install snap
sudo apt install pip
sudo apt install pip
python3 -m pip install --upgrade pip
pip install pymetasploit3
export PATH=$PATH:/snap/bin
echo "SETTING UP SERVER"
msfrpcd -P PASSWORD
echo "FINISHED SETTING UP SERVER"