# simplePortTrafficMonitor
This is a simple port traffic monitor based on article in this link: 
https://linuxhint.com/building-your-own-network-monitor-with-pyshark/

## About the project
  This project was born out of need. Long story short; I build a Minecraft Server in an AWS EC2 machine and I desired to close automatically when inactivity. So I found reasonable for me to make a script that control and log port activity. This project uses pyshark, time and json modules for now. You can use this project what ever you like. You can change it, develop it and use it. I hope you use it for good. Remember great power comes with great responsibility. 
 
## Requirements 
- pyshark module
- time module
- json module

## Usage
  Well there is no user input yet. So edit file and write your desired port.
  
  > bpf_filter = "tcp port 8000"
 Then simply start program. It does his thing. If you wanna close use KeyboardInterrupted (CTRL+C) 

