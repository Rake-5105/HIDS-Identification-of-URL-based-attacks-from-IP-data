# HIDS - URL Attack Detection System

A Host-based Intrusion Detection System for detecting URL-based web attacks using hybrid ML detection.

## Features

- Log Collection (HTTP logs, PCAP, CSV)
- URL Parsing & Feature Extraction
- Hybrid Detection (Rule-based + ML)
- Interactive Dashboard with Visualizations

## Tech Stack

- **Frontend:** React, Tailwind CSS, Framer Motion
- **Backend:** Node.js (Express), Python (Flask)
- **Database:** MongoDB Atlas
- **ML:** Scikit-learn

## Quick Start

```bash
cd hids-dashboard
npm run install:all
npm run dev
```

**Access:**
- Landing: http://localhost:5173
- Dashboard: http://localhost:5173/app/dashboard

## Attack Types Detected

- SQL Injection
- XSS (Cross-Site Scripting)
- Path Traversal
- Command Injection

## Author

Developed for Mini Project