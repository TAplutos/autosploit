#!/bin/bash
export PATH=$PATH:/snap/bin
echo "SETTING UP SERVER"
yes | msfrpcd -P PASSWORD &
sleep 20
echo "FINISHED SETTING UP SERVER"