# HIDS - URL Attack Detection System

This project is a Host-based Intrusion Detection System for identifying URL-based attacks from network and log data.

## Overview

The system ingests traffic and log inputs, extracts URL-related features, and uses a hybrid detection approach to classify suspicious activity. It combines signature-based rules, supervised machine learning, statistical heuristics, and Isolation Forest anomaly detection to help surface both known attacks and unusual zero-day-style behavior.

## Core Capabilities

- Data ingestion from supported network/log sources
- URL and request feature extraction
- Hybrid detection pipeline (rules + ML + statistical checks + Isolation Forest)
- Zero-day-style anomaly detection for unusual traffic patterns
- Local dashboard for monitoring and review
- Automated email reports with attack-specific security playbooks attached as PDF when threats are detected

## Tech Stack

| Layer | Technologies |
|-------|--------------|
| Frontend | React, Tailwind CSS |
| Backend | Node.js (Express), Python (Flask) |
| Data Storage | MongoDB |
| Machine Learning | Scikit-learn |
| Email Reports | Nodemailer, PDFKit |

## Detection Pipeline

1. Extract URL and request features from incoming data.
2. Run regex-based signatures for known attack patterns.
3. Apply supervised classification for attack labeling.
4. Use statistical checks for flood and brute-force behavior.
5. Run Isolation Forest to flag anomalous traffic that does not match known patterns.
6. Save the final classification, confidence, and detection method in the generated reports.
7. Email the report to the user, including a PDF security playbook when an attack is detected.

## Quick Start

```bash
cd hids-dashboard
npm run install:all
npm run dev
```

After startup, open the dashboard in your browser and upload a log, CSV, or PCAP file to generate the analysis report.

## Repository Layout

```text
hids-dashboard/   Full-stack application
data_modules/     Detection and processing modules
sample_data/      Example inputs
output/           Generated output files
logs/             Runtime logs
```

## Note

This README intentionally keeps implementation and runtime details high-level, but it now reflects the latest hybrid detection flow and anomaly-based attack handling.
