#!/bin/bash

# Compile the server.c program
gcc server.c -o s

# Set ownership to root:root
sudo chown root:root s

# Set the SUID bit
sudo chmod u+s s

# Set capabilities
sudo setcap cap_setuid,cap_setgid+ep s
