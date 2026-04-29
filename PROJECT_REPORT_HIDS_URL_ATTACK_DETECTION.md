# HIDS - Identification of URL-Based Attacks from IP Data Using Artificial Intelligence & Machine Learning

Ms. M. Raghavia, J. Bharath, S. Kabil Yugan, S. Karunakaran  
a Assistant Professor, Department of Cyber Security, SRM Valliammai Engineering College  
b,c,d UG Scholar, Department of Cyber Security, SRM Valliammai Engineering College  
E-mail: raghavim.cys@srmvalliammai.ac.in, bharathjai2005@gmail.com, kabilyuganofficial@gmail.com, karunakarandveloper007@gmail.com

## Abstract
URL-based attacks are among the most common threats against modern web applications and API-driven systems. Traditional signature-only defenses struggle to detect evolving payload variants and mixed malicious behavior patterns. This project proposes an AI and machine learning-driven Host-based Intrusion Detection System (HIDS) for identifying URL-based attacks from IP data. The system combines static URL feature analysis, statistical behavior monitoring, and a hybrid detection framework using Regex rules and Random Forest classification. It supports multi-source input from logs, PCAP, and CSV/IPDR records, and provides near real-time threat identification through a web dashboard. Experimental results from the current implementation show approximately 96.4% ML accuracy with 18 threats detected from 28 analyzed requests. The platform delivers actionable analytics, suspicious IP tracking, and detailed request-level risk visibility, thereby improving detection precision and response speed while maintaining low operational overhead.

Keywords: HIDS, URL Attack Detection, Random Forest, Hybrid Detection, Threat Analysis, Cybersecurity

## Introduction
Cyber attacks increasingly target web request paths and URL parameters to inject malicious commands, steal information, or manipulate backend systems. Attack categories such as SQL Injection, Cross-Site Scripting (XSS), Path Traversal, and Command Injection can appear similar to legitimate traffic, which makes manual inspection and static filtering insufficient. Existing protection methods that rely only on signatures often fail to identify newly obfuscated payloads, while purely statistical or purely machine learning approaches can generate false positives without sufficient context.

To overcome this gap, this project introduces a hybrid HIDS framework that combines deterministic rules, behavioral statistics, and machine learning prediction. The system processes request data from multiple sources, extracts URL-centered features, and classifies each request into normal or attack classes. A full-stack dashboard built with React, Express, and Flask enables authentication, monitoring, upload-based scanning, and detailed analysis. The overall design focuses on practical cybersecurity use cases where fast detection, interpretability, and easy deployment are essential.

## Workflow of URL Attack Detection Using Artificial Intelligence & Machine Learning
The URL attack identification process begins when a user uploads a log, PCAP, or CSV/IPDR file for scanning, or triggers a pipeline run on available local sources. The system first performs parsing and normalization so that records from different input formats are converted into a unified structure containing timestamp, source IP, request method, URL/path, and related metadata. After standardization, the framework extracts URL-focused features such as URL length, suspicious character ratio, script indicators, traversal indicators, and SQL-related lexical cues.

The extracted features are then passed to a hybrid detection module. In the first stage, regex-based signatures detect explicit and known malicious patterns. In the second stage, statistical analysis identifies suspicious temporal behavior such as abnormal request bursts and repeated login attempts from the same source. In the third stage, a Random Forest classifier performs machine learning-based classification and generates confidence scores. These outputs are fused through a priority-based decision policy to produce final labels for each request.

Two outcomes are generated after classification. If no threat is identified, the request is marked normal and included in standard analytics. If an attack is detected, the dashboard highlights the event, displays classification details, confidence, source context, and detection method, and stores the result in report artifacts for further review. By combining rule-based precision with statistical and machine learning adaptability, the workflow improves detection speed, increases reliability, and reduces false positives in practical environments.

Fig 1: Workflow of URL Attack Detection Using AI & ML

## URL Attack Detection System Home Interface
Module 1, called the Home Interface, is the communication layer through which users interact with the URL attack detection system in an effortless and self-explanatory way. The landing screen enables users to start analysis by uploading log, PCAP, or CSV/IPDR files, and also allows direct navigation to request monitoring and analytics sections. The interface highlights key threat metrics and detection outputs in a clear response-oriented layout.

This interface is developed using responsive web technologies to provide consistent behavior across desktop and mobile screens. Functional controls guide users through choosing files, launching scans, and reviewing module outputs with visual prompts, status indicators, and progress messages. The dashboard presents current summary values and analysis results for quick inspection.

The UI design emphasizes real-time monitoring of request behavior, streamlined process visibility, and a minimal but modern visual style. The interface is intentionally built for both technical and non-technical users, so operation does not depend on command-line skills or advanced cybersecurity expertise. By combining usability with transparency, the Home Interface improves trust, encourages regular usage, and supports faster decision-making during suspicious activity analysis.

Fig 2: Home Interface

## URL Attack Detection Report Generation
The second module, called URL Attack Detection Report Generation, is designed to provide detailed and actionable outputs after every scan. Once uploaded data is processed and the hybrid engine completes analysis, the system automatically compiles classification results into a standard reporting stream. Each report includes key information such as timestamp, source IP, URL/request path, predicted class, confidence value, detection method, and overall threat summary metrics.

When suspicious or malicious requests are detected, the report highlights warnings so users can quickly identify high-priority events. The generated summary also includes aggregate indicators such as total requests, detected threats, suspicious IP list, class distribution, and model accuracy. This structure helps users move from raw technical output to immediate operational understanding, particularly during repeated attack attempts from the same source.

Overall, the report module is lightweight, readable, and focused on practical cybersecurity response rather than unnecessary complexity. The output files are suitable for manual review and dashboard ingestion. By improving transparency and traceability, this module strengthens practical threat monitoring and response effectiveness.

Fig 3: Report Generation

## Threat Detection and Risk Classification
The Threat Detection and Risk Classification module evaluates each request and identifies activities that may represent security risk. During execution, the system extracts relevant URL and traffic features and forwards them to the hybrid pipeline for risk determination. Requests are separated into normal and suspicious categories, and detected attacks are further classified into risk-relevant classes such as SQL Injection, XSS, Path Traversal, and Command Injection.

Beyond class labels, abnormal behavior indicators such as repeated high-frequency requests from one source, suspicious payload structures, and unusual parameter patterns contribute to higher risk assignment. Risk classification is supported by regex signatures, statistical threshold checks, and Random Forest prediction confidence, which together reduce overreaction to benign anomalies. This layered design helps maintain low false positives while preserving strong sensitivity to true attacks.

The resulting risk levels are reflected in report outputs and dashboard tables so users can prioritize incident handling based on severity. Lower-risk observations can be reviewed first for verification, while clearly malicious requests are escalated for immediate response. This hierarchical model improves decision quality and response speed without compromising monitoring stability.

Fig 4: Threat Detection and Risk Classification

## Detailed Risk Analysis of High-Risk Requests
The Detailed Risk Analysis of High-Risk Requests module provides a deeper breakdown of requests that were marked suspicious or malicious by the hybrid detector. After initial classification, each high-risk request is analyzed in detail to understand why it was flagged and how strongly it matches attack behavior.

The analysis includes request-level indicators such as source IP, URL pattern complexity, suspicious token presence, detection method origin, and confidence score. These details are especially valuable for requests associated with SQL Injection, Cross-Site Scripting payloads, traversal paths, or command execution attempts.

Pattern correlation across timeline and source activity helps identify repeated exploitation campaigns and persistent malicious origins. Grouping high-risk events by IP and class allows analysts to observe escalation patterns that may not be obvious from single-request inspection.

By combining numerical indicators with interpretable attack evidence, the module supports operational response and detailed review. This enables users and cybersecurity teams to make informed decisions with minimal delay.

Overall, close examination of high-risk request behavior improves classification trust, reduces blind spots, and strengthens the accuracy of threat understanding during active monitoring.

Fig 5: Detailed Risk Analysis of High-Risk Requests

## Output Artifacts
The project generates structured output artifacts after processing, including the hybrid classification CSV, summary JSON, feature dataset CSV, and model report text. These outputs contain request-level classifications, confidence values, method-wise detections, and aggregate metrics such as total requests, total threats, suspicious IPs, and model accuracy.

These artifacts support reproducible analysis and make it easy to validate results directly from files in the output folder. They are used by the dashboard for visualization and can also be reviewed independently for documentation and verification.

Fig 6: Output Artifacts

## Conclusion
This mini project successfully integrates an AI and machine learning-powered HIDS pipeline that identifies malicious URL behavior from IP-linked request data through batch-driven analysis. By combining regex signatures, statistical anomaly checks, and Random Forest-based classification, the system achieves strong detection performance with approximately 96.4% ML accuracy, while maintaining practical balance between sensitivity and false alert control.

The lightweight and modular architecture makes the solution suitable for academic deployment and real-world prototype usage. Through an accessible web interface and structured reporting outputs, the platform improves visibility into web attack activity and supports practical cybersecurity monitoring.
