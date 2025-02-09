# PyPortScanner

A program to scan the network's hosts for open, closed, and filtered ports.

## Purpose

This tool allows users to scan hosts in a network to identify open, closed, and filtered ports, helping with network security assessments and diagnostics.

---

## Installation

To get started with PyPortScanner, clone the repository using the following command:

```bash
git clone https://github.com/Matirix/PyPortScanner.git
```
Once cloned, navigate to the project directory:
```bash
cd PyPortScanner
```

## Running the Program

To run the program, use the following command structure:

-h	     Shows usage
-t	     Target IP(s) (accepts subnet, range, or specific IP(s))
-p	     Ports (accepts a single port, multiple ports, or a range)
--show	 Filters summary by open, filtered, or closed ports

```bash
python3 main.py -p 10
```
```bash
python3 main.py -t 127.0.0.1 -p 22,80,443
```
```bash
python3 main.py -t 192.168.1.75,192.168.1.80 -p 22,80
```
