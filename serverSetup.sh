#!/bin/bash
# TODO: make this quiet
export PATH=$PATH:/snap/bin
yes | msfrpcd -P PASSWORD &
sleep 60