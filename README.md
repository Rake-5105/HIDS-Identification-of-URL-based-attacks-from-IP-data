# HIDS - URL Attack Detection System

This project is a Host-based Intrusion Detection System for identifying URL-based attacks from network and log data.

## Overview

The system ingests traffic and log inputs, extracts URL-related features, and uses a hybrid detection approach to classify suspicious activity.

## Core Capabilities

- Data ingestion from supported network/log sources
- URL and request feature extraction
- Hybrid detection pipeline (rules + ML)
- Local dashboard for monitoring and review

## Quick Start

```bash
cd hids-dashboard
npm run install:all
npm run dev
```

## Repository Layout

```text
hids-dashboard/   Full-stack application
data_modules/     Detection and processing modules
sample_data/      Example inputs
output/           Generated output files
logs/             Runtime logs
```

## Note

This README intentionally keeps implementation and runtime details high-level.
