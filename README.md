#  Network Traffic Monitoring & Attack Detection using Snort
<br> <br/>

# Project Overview
This project presents a beginner-level cybersecurity lab designed to demonstrate the principles of network traffic monitoring and intrusion detection using the open-source tool Snort Intrusion Detection System (IDS). It simulates a controlled environment where malicious traffic is generated and monitored to understand how network-based threats are detected in real time.

The lab is built using a virtualized setup involving two machines:

   + Ubuntu (Defensive Host): Acts as the target system and runs Snort IDS to monitor incoming traffic and generate alerts based on predefined and custom rules.

   + Kali Linux (Attacker): Used to perform various network-based attacks, including port scanning and web vulnerability probing, to simulate real-world threats.

The goal of this project is to detect suspicious activity by analyzing network traffic and triggering alerts using custom and default Snort rules.

<br> <br/>

# Objectives

- Set up Snort IDS on a Ubuntu machine.
- Generate network attacks using Kali Linux tools (e.g., `nmap`, `nikto`).
- Capture and analyze network traffic.
- Write and test custom Snort rules.
- Understand how alerts are generated based on traffic patterns.

<br> <br/>

# Lab Setup

| Component       | Configuration                        |
|----------------|---------------------------------------|
| **Defender**    | Ubuntu 20.04 with Snort 2.x           |
| **Attacker**    | Kali Linux (latest)                   |
| **Network**     | Host-only or Bridged Adapter          |
| **Tools Used**  | Snort, Nmap, Nikto, Wireshark         |

<br> <br/>

# Snort Installation & Configuration (Ubuntu)

## 1. Install Snort

```bash
sudo apt update
sudo apt install snort
```
During installation, set the HOME_NET to your Ubuntu IP (or adjust it later in the config file).
<br> <br/>

## 2. Check Snort Version
```bash
snort -V
```
<br> <br/>

## 3. Configure Snort
**Edit the main config file:**
```bash
sudo nano /etc/snort/snort.conf
```

**Make sure to:**
   + Set HOME_NET to your internal IP or subnet.
   + Include local rules file:

```bash
include $RULE_PATH/local.rules
```

<br> <br/>

# Writing Custom Rules

**Example rule to detect Nmap scans:**
```bash
alert tcp any any -> $HOME_NET any (msg:"Nmap Scan Detected"; flags:S; sid:1000001; rev:1;)
```

**Place the rule in:**
```badh
/etc/snort/rules/local.rules
```

<br> <br/>

### Some snort rules to try out 

#### 1. Detect TCP Port Scan
```bash
alert tcp any any -> $HOME_NET any (msg:"TCP Port Scan Detected"; flags:S; threshold:type threshold, track by_src, count 10, seconds 60; sid:1000001; rev:1;)
```

#### 2. Detect HTTP Traffic to a Specific Port
```bash
alert tcp any any -> $HOME_NET 80 (msg:"HTTP Access Detected"; flow:to_server,established; content:"GET"; http_method; sid:1000003; rev:1;)
```

#### 3. Detect FTP Login Attempt
```bash
alert tcp any any -> $HOME_NET 21 (msg:"FTP Login Attempt"; flow:to_server,established; content:"USER "; sid:1000006; rev:1;)
```

#### 4. Detect Nikto Web Scanner
```bash
alert tcp any any -> $HOME_NET 80 (msg:"Nikto Web Scanner Detected"; flow:to_server,established; content:"Nikto"; http_user_agent; sid:1000007; rev:1;)
```

#### 5. Detect DNS Query for Suspicious Domain
```bash
alert udp any any -> $HOME_NET 53 (msg:"Suspicious DNS Query - Malware Domain"; content:"badexample.com"; sid:1000009; rev:1;)
```

<br> <br/>

# Attacking from Kali Linux
### 1. Nmap Scan
```bash
nmap -sS <ubuntu_ip>
```
### 2. Nikto Web Scan
```bash
nikto -h http://<ubuntu_ip>
```
These scans generate detectable traffic which should trigger alerts in Snort.

<br> <br/>

# Monitoring Traffic
**Run Snort in packet logging mode:**
```bash
sudo snort -A console -q -u snort -g snort -c /etc/snort/snort.conf -i <interface>
```
**Example interface might be eth0 or ens33. Check it with:**
```bash
ip a
```

<br> <br/>

#  Analysis & Findings
**Snort successfully detected:**
      - TCP SYN scans (via Nmap)
      - HTTP enumeration (via Nikto)
+ Alerts were triggered based on rule sid:1000001 and others.
+ Logs were reviewed using both terminal and log files.

**Tools for Analysis**
+ Wireshark to inspect .pcap traffic files.
+ Snort log to analyze triggered alerts.

<br> <br/>

#  What I Learned
+ How to install and configure Snort IDS.
+ Basics of writing detection rules for network threats.
+ How attackers use tools like Nmap and Nikto to gather intel.
+ How IDS tools like Snort detect suspicious traffic patterns.
+ Fundamentals of network analysis with tools like Wireshark.

