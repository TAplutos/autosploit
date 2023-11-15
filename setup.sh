#!/bin/bash
sudo apt-get --assume-yes update
sudo apt-get --assume-yes update --fix-missing
sudo apt --assume-yes install snap
sudo apt --assume-yes install pip
sudo apt --assume-yes install pip
snap install nmap
python3 -m pip install --upgrade pip
pip install pymetasploit3
sudo snap install metasploit-framework
export PATH=$PATH:/snap/bin
echo "SETTING UP SERVER"
yes | msfrpcd -P PASSWORD &
sleep 20
echo "FINISHED SETTING UP SERVER"