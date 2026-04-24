# Python Port Scanner

## Description

This is a simple port scanner written in Python.
It can scan ports of a target and try to identify services like SSH and HTTP.

## Features

* TCP port scan
* Multi-threading
* DNS resolution
* Banner grabbing
* Basic service detection

## Usage

Scan a range:
python main.py -t scanme.nmap.org -b 10 -e 100

Scan one port:
python main.py -t scanme.nmap.org -c 22

## Arguments

-t target
-b begin port
-e end port
-c single port
-th threads

## Example

PORT    STATUS    SERVICE
22      open      SSH
80      open      HTTP

## Notes

- This tool is for learning purposes.
- It is not as accurate as professional tools like nmap.
- Open port detection may produce false positives  
- Service detection relies on basic pattern matching and is limited  
- The scanner may produce inconsistent results depending on network conditions and service behavior.
