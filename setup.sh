#!/bin/bash
export PATH=$PATH:/snap/bin
echo "SETTING UP SERVER"
yes | msfrpcd -P PASSWORD &
sleep 38 
echo "FINISHED SETTING UP SERVER"