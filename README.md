# HIDS - URL Attack Detection System

A Host-based Intrusion Detection System for detecting URL-based web attacks using hybrid ML detection.

## Features

- **Log Collection** - HTTP logs, PCAP, CSV ingestion
- **URL Parsing** - Extract IPs, timestamps, parameters
- **Hybrid Detection** - Rule-based + Machine Learning
- **Interactive Dashboard** - Visualizations & filtering

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React, Tailwind CSS, Framer Motion |
| Backend | Node.js (Express), Python (Flask) |
| Database | MongoDB Atlas |
| ML | Scikit-learn |

## Quick Start

```bash
cd hids-dashboard
npm run install:all
npm run dev
```

## Access URLs

- **Landing Page:** http://localhost:5173
- **Login:** http://localhost:5173/login
- **Dashboard:** http://localhost:5173/app/dashboard

## Attack Types Detected

- SQL Injection
- XSS (Cross-Site Scripting)
- Path Traversal
- Command Injection

## Project Structure

```
├── hids-dashboard/      # Full-stack dashboard
│   ├── client/          # React frontend
│   ├── server/          # Express backend
│   └── flask_api/       # Python Flask API
├── data_modules/        # ML detection modules
├── sample_data/         # Sample log files
└── output/              # Detection results
```


---
Built with ❤️ for Cybersecurity
