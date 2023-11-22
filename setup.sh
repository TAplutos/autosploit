#!/bin/bash
export PATH=$PATH:/snap/bin

# TODO: make this quiet
sudo apt-get update
sudo apt-get --assume-yes install apt-utils
sudo apt-get --assume-yes install systemd
sudo apt-get --assume-yes install snap
sudo apt-get --assume-yes install snapd
sudo apt-get --assume-yes install python3
sudo apt-get --assume-yes install python3-pip
sudo apt-get --assume-yes install net-tools
sudo apt-get --assume-yes install nmap

pip3 install pymetasploit3
pip3 install msgpack
pip3 install retry
pip3 install requests

sudo systemctl enable snapd.service
sudo systemctl start snapd.service
sudo snap install metasploit-framework