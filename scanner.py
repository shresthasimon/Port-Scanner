#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()

print("Welcome to the simple nmap automation tool")
print ("<------------------------------------------>")

ip_addr = input("Please enter the IP address you want to scan:")
print("The IP you entered: ", ip_addr)
type(ip_addr)

resp = input(""" \n Please enter the type of can you would like to perform 
                1) SYN ACK Scan
                2) UDP Scan
                3) Comprehensive scan \n""")

print("You have selected option: ", resp)

if resp == '1':
    print("Nmap Version: ", scanner.nmap_version())
    # scans the ip address with the first 1024 ports with a verbose output with syn ack scan
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    # prints all services and methods
    print(scanner.scaninfo())
    # States whether the ip address is up or not
    print("IP Status: ", scanner[ip_addr].state())
    #prints out the protocols being used 
    print(scanner[ip_addr].all_protocols())
    # ouputs open ports
    print("Open Ports: ",scanner[ip_addr]['tcp'].keys())
elif resp == '2':
    print("Nmap Version: ", scanner.nmap_version())
    # scans the ip address with the first 1024 ports with a verbose output with udp scan
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    # prints all services and methods
    print(scanner.scaninfo())
    # States whether the ip address is up or not
    print("IP Status: ", scanner[ip_addr].state())
    #prints out the protocols being used 
    print(scanner[ip_addr].all_protocols())
    # ouputs open ports
    print("Open Ports: ",scanner[ip_addr]['udp'].keys())
elif resp == '3':
    print("Nmap Version: ", scanner.nmap_version())
    # scans the ip address with the first 1024 ports with a verbose output with everything
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    # prints all services and methods
    print(scanner.scaninfo())
    # States whether the ip address is up or not
    print("IP Status: ", scanner[ip_addr].state())
    #prints out the protocols being used 
    print(scanner[ip_addr].all_protocols())
    # ouputs open ports
    print("Open Ports: ",scanner[ip_addr]['tcp'].keys())
elif resp >= '4':
    print("Please enter a valid option!")
    




