# Summary
Create a CSV of all the hosts discovered within a certain number of hours.

# Requirements
This script needs the Tenable.io SDK, which can be found at https://github.com/tenable/Tenable.io-SDK-for-Python/tree/master/tenable_io

# Usage Example With Environment Variables
TIOACCESSKEY="******************"; export TIOACCESSKEY

TIOSECRETKEY="******************"; export TIOSECRETKEY

TIOHOURS="12"; export TIOHOURS

./newhosts.py

This will produce a file called newhosts.csv
