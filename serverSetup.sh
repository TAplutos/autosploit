#!/bin/bash
export PATH=$PATH:/snap/bin
yes | msfrpcd -P PASSWORD &
sleep 60