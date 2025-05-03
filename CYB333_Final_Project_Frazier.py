# Simple Intrusion Detection System (IDS)
### Author: John Louis Frazier  
### Course: CYB333 Security Automation
### Instructor: Professor Eric Rivard
### Description: This script implements a simple Intrusion Detection System (IDS) using Python. 
### It monitors system logs, analyzes network traffic, and detects anomalies using machine learning techniques. 
### The script uses libraries such as Scapy for network packet analysis and Pyshark for packet capture. 
### It also utilizes the Isolation Forest algorithm from scikit-learn for anomaly detection.
### Note: This is a simplified example and should not be used in production without further enhancements and security measures.

# Install necessary Python packages
# Ensure required packages are installed
import subprocess
import sys

required_packages = ["pandas", "loguru", "scapy", "pyshark", "scikit-learn"]
for package in required_packages:
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

import os
import pandas as pd  # type: ignore
from loguru import logger  # type: ignore
import scapy.all as scapy  # type: ignore
import pyshark  # type: ignore
from sklearn.ensemble import IsolationForest  # type: ignore
import time

# Verify required files exist
if not os.path.exists("system.log"):
    with open("system.log", "w") as file:
        file.write("")  # Create an empty log file
    print("system.log file created.")

if not os.path.exists("network_traffic.csv"):
    with open("network_traffic.csv", "w") as file:
        file.write("feature1,feature2,feature3\n1.0,2.0,3.0\n4.0,5.0,6.0\n7.0,8.0,9.0\n")
    print("network_traffic.csv file created.")

# List available network interfaces
available_interfaces = scapy.get_if_list()
print(f"Available interfaces: {available_interfaces}")

# Replace 'eth0' with an appropriate interface name from the list
interface_name = available_interfaces[0]  # Select the first interface as an example

# Function to monitor system logs
# This function scans the system log file for suspicious patterns (e.g., failed login attempts, unauthorized access).
# If suspicious activity is detected, it logs a warning and prints the details to the console.
def monitor_logs(log_file):
    suspicious_patterns = ["failed login", "unauthorized access", "malware detected"]
    detected_issues = []

    with open(log_file, "r") as file:
        logs = file.readlines()

    for line in logs:
        for pattern in suspicious_patterns:
            if pattern in line.lower():
                detected_issues.append(line.strip())
                logger.warning(f"Suspicious activity detected: {line.strip()}")
                break

    if detected_issues:
        print(f"Suspicious activities found in logs: {len(detected_issues)}")
        for issue in detected_issues:
            print(f" - {issue}")
    else:
        print("No suspicious activities found in logs.")

# Function to analyze network traffic
# This function captures network packets using Scapy and analyzes them for HTTP traffic and malicious content.
# It logs details about captured packets and prints a summary of HTTP and malicious traffic.
def analyze_network_traffic(interface):
    packets = scapy.sniff(iface=interface, count=10)
    http_traffic_count = 0
    malicious_count = 0

    for packet in packets:
        if packet.haslayer(scapy.IP):
            logger.info(f"Packet captured: {packet.summary()}")
            if packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == 80:
                http_traffic_count += 1
                logger.warning(f"HTTP traffic detected: {packet.summary()}")

                if packet.haslayer(scapy.Raw):
                    payload = packet[scapy.Raw].load.decode(errors='ignore')
                    if "malicious" in payload.lower():
                        malicious_count += 1
                        logger.error(f"Malicious content detected in HTTP traffic: {payload}")

    print(f"Network traffic analysis completed. HTTP traffic: {http_traffic_count}, Malicious packets: {malicious_count}")

# Function to analyze network traffic using Pyshark
# This function captures network packets using Pyshark and checks for malicious content in HTTP traffic.
def analyze_network_traffic_pyshark(interface):
    capture = pyshark.LiveCapture(interface=interface)
    for packet in capture.sniff_continuously(packet_count=10):
        logger.info(f"Packet captured: {packet}")
        if hasattr(packet, 'http') and hasattr(packet.http, 'file_data'):
            if "malicious" in packet.http.file_data.lower():
                logger.error(f"Malicious content detected in HTTP traffic: {packet.http.file_data}")

# Function to detect anomalies in network traffic using Isolation Forest
# This function uses the Isolation Forest algorithm to detect anomalies in the provided network traffic data.
# It logs details about detected anomalies and prints a summary.
def detect_anomalies(data):
    model = IsolationForest(contamination=0.1)
    model.fit(data)
    anomalies = model.predict(data)

    anomaly_count = sum(1 for anomaly in anomalies if anomaly == -1)
    print(f"Anomaly detection completed. Total anomalies detected: {anomaly_count}")

    for i, anomaly in enumerate(anomalies):
        if anomaly == -1:
            logger.warning(f"Anomaly detected at index {i}: {data.iloc[i]}")

# Function to load and preprocess data for anomaly detection
# This function loads network traffic data from a CSV file and preprocesses it for anomaly detection.
def load_and_preprocess_data(file_path):
    try:
        data = pd.read_csv(file_path)
        # Preprocess data (e.g., normalization, feature selection)
        # For simplicity, we'll assume the data is already preprocessed
        return data
    except Exception as e:
        logger.error(f"Error loading data: {e}")
        return pd.DataFrame()  # Return an empty DataFrame if there's an error

# Function to send alerts
# This function sends an alert message and logs it as an error.
def send_alert(message):
    print(f"ALERT: {message}")
    logger.error(message)

# Example usage
send_alert("Unauthorized access detected on server!")
log_file = "system.log"  # Corrected path to the log file
monitor_logs(log_file)
analyze_network_traffic(interface_name)
analyze_network_traffic_pyshark(interface_name)

# Load network traffic data and run anomaly detection
data = load_and_preprocess_data("network_traffic.csv")  # Load network traffic data
if not data.empty:
    detect_anomalies(data)  # Run anomaly detection

print("Log monitoring completed. Check the logs for suspicious activity.")
print("Network traffic analysis completed. Check the logs for HTTP traffic or malicious content.")
print("Anomaly detection completed. Check the logs for detected anomalies.")

print("\n--- Intrusion Detection System Summary ---")
print("1. Log monitoring completed. Check logs for suspicious activity.")
print("2. Network traffic analysis completed. Check logs for HTTP traffic or malicious content.")
print("3. Anomaly detection completed. Check logs for detected anomalies.")
print("------------------------------------------------")

# Note: This is a simplified example. In a real-world scenario, you would need to handle exceptions, manage configurations, and implement more robust logging and alerting mechanisms.
# Additionally, you would need to ensure that the script runs continuously and monitors logs and network traffic in real-time.
# You may also want to implement a more sophisticated machine learning model for anomaly detection, depending on the complexity of your network traffic data.
# Finally, ensure that you have the necessary permissions to capture network traffic and access system logs.
# This script is intended for educational purposes only. Always follow ethical guidelines and legal requirements when implementing security solutions.
# Ensure that you have the necessary permissions to capture network traffic and access system logs.

# Test log monitoring
monitor_logs("system_logs.txt")

# Capture network traffic
scapy.sniff(prn=detect_anomalies, count=10)

while True:
    monitor_logs("system.log")
    analyze_network_traffic(interface_name)
    analyze_network_traffic_pyshark(interface_name)
    data = load_and_preprocess_data("network_traffic.csv")
    detect_anomalies(data)
    time.sleep(60)  # Wait for 1 minute before repeating
