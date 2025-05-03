# CYB333 Security Automation Final Project

May 3, 2025

Simple Intrusion Detection System (IDS):

A Python IDS that monitors network traffic and system logs for malicious activity using machine learning algorithms.

CYB333 Security Automation Final Project

Author: John Louis Frazier

Course: CYB333 Security Automation

Instructor: Professor Eric Rivard

Objectives:

Scan for suspicious activity in system logs.

Inspect network traffic with packet inspection.

Anomaly detection with Isolation Forest algorithm.

Alert on unauthorized access or suspected threat.

Setup & Installation:

Prerequisites:
Make sure the following dependencies are installed:

bash
pip install pandas loguru scapy pyshark scikit-learn

Clone Repository
bash
git clone [(https://github.com/louisfrazier641/CYB333)]
cd CYB333_IDS

Running the IDS:
To run the IDS, the following are required:

bash
python main.py
Watches for unauthorized access.

Grabs packets on the network to scan.

Machine learning-based anomaly detection-based.

Usage:

Change Detection Rules: Config.json to use to use for custom security configuration.

Scan Alerts: Prints to alerts.log to watch.

Network Traffic Monitor: Runs in the background to look for anomalies.

AI Tools Usage:

Used GitHub Copilot to:

Created initial design concepts.

Improved networking and log analysis.

Improved coding efficiency with AI-recommended changes.

Challenges & Improvements:

Challenges:
Management of false positives for anomaly detection.

Run-time tuning and real-time.

Optimization to be achieved in the future:
Utilize more advanced ML models in order to have improved detection quality.

Improve dashboard visualization such that monitoring is effectively done.

Contributors

Developer: Louis Frazier

National University – CYB333 Security Automation

License:
This is open-source and under https://opensource.org/license/MIT.
