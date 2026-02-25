# Personal Firewall Using Python

A lightweight personal firewall built using Python and Linux iptables.  
This project monitors live network traffic, applies rule-based filtering, logs suspicious activity, and enforces blocking at the system level.

---

## Features

- Live packet sniffing using Scapy
- Rule-based filtering (IP, Port, Protocol)
- System-level blocking using iptables
- Logging of suspicious packets
- Configurable rules via JSON file
- Tested in VirtualBox lab environment

---

## Technologies Used

- Python 3
- Scapy
- Linux iptables
- VirtualBox (for testing)
- JSON (rule configuration)

---

## Project Structure

personal_firewall/
│
├── firewall.py # Main firewall script
├── rules.json # Rule configuration file
├── firewall.log # Generated log file (ignored in Git)
├── sample_firewall.log # Example log file for demo
├── .gitignore
└── README.md


---


