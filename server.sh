#!/bin/bash
echo "SETTING UP SERVER"
msfrpcd -P PASSWORD  & # Replace PASSWORD with your actual password
sleep 10
echo "FINISHED SETTING UP SERVER"