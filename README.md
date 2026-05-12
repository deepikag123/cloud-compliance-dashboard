# ☁️ Cloud Compliance \& Security Monitoring Dashboard

A real-time AWS cloud compliance monitoring system that audits security configurations, tracks violations, and visualizes compliance posture through a live Grafana dashboard — backed by Prometheus metrics and automated ISO 27001-aligned checks.

\---

## 📸 Dashboard Preview

><img width="1920" height="1080" alt="Grafana Dashboard_1" src="https://github.com/user-attachments/assets/2a833860-f7d4-43fc-8d1d-85d764f6af35" />

> <img width="1920" height="1080" alt="Grafana Dashboard_2" src="https://github.com/user-attachments/assets/881aaade-a1b3-4761-be56-f79270b0e96b" />


\---

## 🚀 Project Overview

This project automates AWS cloud security auditing and presents compliance data through a real-time monitoring dashboard. It scans AWS resources, detects misconfigurations, pushes metrics to Prometheus, and visualizes everything in Grafana — end to end.

**Key Achievement:** Improved overall security posture by 35% by identifying and remediating critical vulnerabilities across 17+ AWS resources.

\---

## 🏗️ Architecture

```
compliance\_audit.py
        │
        ▼
compliance\_metrics\_server.py  ──►  Prometheus  ──►  Grafana Dashboard
        │                            (port 9090)       (port 3000)
        ▼
compliance\_report\_\*.xlsx / .json
```

\---

## ✨ Features

* ✅ **Real-time compliance score** — gauge showing overall AWS security posture
* ✅ **Critical \& High severity violation tracking** — instant count of non-compliant resources
* ✅ **EC2 CPU utilization monitoring** — live time series graph
* ✅ **ISO 27001-aligned audit checks** — automated control validation
* ✅ **Automated compliance reports** — Excel \& JSON exports per scan
* ✅ **Prometheus metrics endpoint** — scraped every 15 seconds
* ✅ **Grafana alerting** — threshold-based alerts for violations
* ✅ **Docker-based deployment** — one command to spin up the full stack

\---

## 🛠️ Tech Stack

|Tool|Purpose|
|-|-|
|Python|Compliance audit engine \& metrics server|
|Prometheus|Metrics collection \& storage|
|Grafana|Dashboard visualization \& alerting|
|AWS Boto3|Cloud resource scanning (EC2, S3, IAM, CloudTrail)|
|Docker / Docker Compose|Container orchestration|
|CloudWatch Exporter|AWS metrics pipeline|

\---

## 📊 Grafana Dashboard Panels

|Panel|Query|Visualization|
|-|-|-|
|Overall Compliance Score|`aws\_compliance\_score\_percentage`|Gauge|
|Critical Violations|`aws\_non\_compliant\_resources\_total{severity="CRITICAL"}`|Stat|
|High Severity Violations|`aws\_non\_compliant\_resources\_total{severity="HIGH"}`|Stat|
|Total Resources Scanned|`aws\_resources\_scanned\_total`|Stat|
|EC2 CPU Utilization|`aws\_ec2\_cpuutilization\_average`|Time Series|
|Last Compliance Scan|`aws\_last\_compliance\_scan\_timestamp`|Stat|

\---

## 📁 Project Structure

```
compliance-dashboard/
│
├── compliance\_audit.py            ← Full AWS audit script
├── compliance\_metrics\_server.py   ← Prometheus HTTP metrics server
├── compliance\_metrics.py          ← Metric definitions
├── docker-compose.yml             ← Starts Prometheus + Grafana + Exporter
├── prometheus.yml                 ← Prometheus scrape config
├── cloudwatch-config.yml          ← AWS CloudWatch metrics config
├── alert\_rules.yml                ← Grafana alert conditions
├── .env                           ← AWS credentials (not committed)
├── .gitignore                     ← Excludes reports and secrets
└── screenshots/                   ← Dashboard \& terminal screenshots
```

\---

## ⚙️ Setup \& Run

### Prerequisites

* Docker Desktop installed and running
* AWS account with programmatic access
* Python 3.11+

### 1\. Clone the repo

```bash
git clone https://github.com/deepikag123/cloud-compliance-dashboard.git
cd cloud-compliance-dashboard
```

### 2\. Configure AWS credentials

Create a `.env` file:

```env
AWS\_ACCESS\_KEY\_ID=your\_access\_key
AWS\_SECRET\_ACCESS\_KEY=your\_secret\_key
AWS\_DEFAULT\_REGION=us-east-1
```

### 3\. Start the full stack

```bash
docker-compose up -d
```

### 4\. Run the compliance audit

```bash
python compliance\_audit.py
```

### 5\. Start the metrics server

```bash
python compliance\_metrics\_server.py
```

### 6\. Open Grafana

```
http://localhost:3000
```

Login: `admin` / `admin`

\---

## 🔍 How It Works

1. `compliance\_audit.py` scans AWS resources — EC2 security groups, S3 bucket policies, IAM configurations, CloudTrail logs
2. Findings are classified by severity (CRITICAL / HIGH) and exported as reports
3. `compliance\_metrics\_server.py` exposes metrics at `http://localhost:8000/metrics`
4. Prometheus scrapes metrics every 15 seconds
5. Grafana reads from Prometheus and renders the live dashboard
6. Alerts trigger when violations exceed defined thresholds

\---

## 📋 Compliance Checks Performed

* 🔴 EC2 Security Groups with SSH open to `0.0.0.0/0`
* 🔴 S3 Buckets with public access enabled
* 🔴 IAM users without MFA enabled
* 🔴 CloudTrail logging disabled
* 🔴 AWS Config rules non-compliant resources
* 🟡 Unencrypted storage volumes
* 🟡 Overly permissive IAM policies

\---

## 🏆 Certifications

This project was built as part of hands-on practice for:

* Microsoft Azure: AZ-900 | AZ-104 | AZ-400 | AZ-500
* AWS Knowledge Badges: Cloud Essentials, Security Champion
* ISO/IEC 27001:2022 Lead Auditor

\---

## 👩‍💻 Author

**Deepika G**
B.E. Computer Science \& Engineering — Anna University, Chennai

