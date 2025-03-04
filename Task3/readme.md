# Network Intrusion Detection System (NIDS) Project

A comprehensive network monitoring and intrusion detection system using Suricata, with real-time visualization and automated response capabilities.

## Table of Contents
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Debian/Ubuntu](#debianubuntu)
  - [Arch Linux](#arch-linux) 
  - [Windows](#windows)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Usage](#usage)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

## Overview

This NIDS project provides:
- Real-time network traffic monitoring
- Custom detection rules for common attacks
- Automated alert handling and response
- Visual analytics of security events
- Email notifications for critical alerts

## Prerequisites

### Minimum System Requirements
- CPU: 4 cores recommended
- RAM: 8GB minimum, 16GB recommended
- Storage: 50GB free space
- Network Interface Card (NIC) supporting promiscuous mode

### Software Requirements
- Python 3.8+
- Suricata
- iptables
- Grafana (optional, for additional visualization)

## Installation

### Debian/Ubuntu




##Install Suricata and dependencies

Update system
sudo apt update && sudo apt upgrade -y
Install Suricata and dependencies
sudo apt install -y suricata
sudo apt install -y python3-pip
sudo apt install -y python3-matplotlib
sudo apt install -y iptables
sudo apt install -y grafana

### Arch Linux

# Update system
sudo pacman -Syu

# Install Suricata and dependencies
sudo pacman -S suricata
sudo pacman -S python-pip
sudo pacman -S python-matplotlib
sudo pacman -S iptables
sudo pacman -S grafana

# Install Python dependencies
pip3 install elasticsearch
pip3 install kibana-api

### Windows
1. Install WSL2 (Windows Subsystem for Linux)
2. Install Ubuntu on WSL2
3. Follow Debian/Ubuntu instructions
4. Additional Windows-specific setup:
```powershell
# Enable Windows Packet Capture (as Administrator)
New-NetFirewallRule -DisplayName "Suricata" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 161
```

## Project Structure
```
project/
├── suricata.yaml          # Suricata configuration
├── rules/
│   └── custom.rules       # Custom detection rules
├── monitor.py             # Visualization script
├── alert_handler.py       # Alert processing script
└── config.json           # Alert handler configuration
```

## Configuration

1. **Create Directory Structure:**
```bash
sudo mkdir -p /etc/suricata/rules
sudo mkdir -p /var/log/suricata
```

2. **Suricata Configuration (suricata.yaml):**
```yaml
# Basic Suricata configuration
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8]"
    EXTERNAL_NET: "!$HOME_NET"

# Configure monitoring interface
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

# Enable outputs
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - ssh
```

3. **Custom Rules (custom.rules):**
```
# Detect SSH brute force attempts
alert ssh any any -> $HOME_NET any (msg:"Potential SSH brute force attempt"; flow:established; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000001; rev:1;)

# Detect port scanning
alert tcp any any -> $HOME_NET any (msg:"Possible port scan detected"; flags:S; threshold:type threshold, track by_src, count 50, seconds 60; classtype:attempted-recon; sid:1000002; rev:1;)

# Detect SQL injection attempts
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SQL Injection attempt detected"; content:"UNION"; nocase; http_uri; pcre:"/UNION.*SELECT/i"; classtype:web-application-attack; sid:1000003; rev:1;)
```

4. **Alert Handler Configuration (config.json):**
```json
{
    "email": {
        "smtp_server": "smtp.gmail.com",
        "port": 587,
        "username": "your-email@gmail.com",
        "password": "your-app-password",
        "from": "your-email@gmail.com",
        "to": "alert-recipient@example.com"
    }
}
```

## Usage

1. **Start Suricata:**
```bash
# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# Start Suricata
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

2. **Start Monitoring:**
```bash
# Run visualization script
python3 monitor.py

# Run alert handler
python3 alert_handler.py
```

## Monitoring

### Alert Types
- SSH Brute Force Attempts
- Port Scanning
- SQL Injection Attempts

### Visualization
The system generates real-time graphs showing:
- Alert frequency over time
- Attack types distribution
- Source IP statistics

### Alert Handling
- Automatic IP blocking for repeated offenders
- Email notifications for critical alerts
- Log generation for all detected events

## Troubleshooting

### Common Issues

1. **Suricata Won't Start**
```bash
# Check logs
sudo tail -f /var/log/suricata/suricata.log

# Verify interface
sudo suricata -c /etc/suricata/suricata.yaml --dump-config | grep interface
```

2. **No Alerts Generated**
```bash
# Check if Suricata is running
sudo systemctl status suricata

# Verify log file permissions
sudo chmod 644 /var/log/suricata/eve.json
```

3. **Email Notifications Not Working**
- Verify SMTP settings in config.json
- Check for firewall blocking SMTP port
- Ensure valid app password for Gmail

### Log Locations
- Suricata Logs: `/var/log/suricata/suricata.log`
- Alert Logs: `/var/log/suricata/eve.json`
- Visualization Output: `./ids_alerts.png`

## Security Considerations

1. **System Hardening**
- Regular system updates
- Minimal required services running
- Proper firewall configuration

2. **Access Control**
- Use sudo for privileged operations
- Restrict access to configuration files
- Monitor system logs

3. **Network Configuration**
- Dedicated monitoring interface
- Proper VLAN segmentation
- Regular network audits

## Maintenance

1. **Regular Updates**
```bash
# Update Suricata rules
sudo suricata-update

# Update system
sudo apt update && sudo apt upgrade
```

2. **Log Rotation**
```bash
# Configure logrotate
sudo nano /etc/logrotate.d/suricata
```

3. **Performance Monitoring**
```bash
# Check Suricata stats
sudo suricatasc -c "stats"
```

## Support

For issues and questions:
- Check Suricata documentation: https://suricata.readthedocs.io/
- Review system logs
- Check GitHub issues

## License

This project is licensed under the MIT License - see the LICENSE file for details.