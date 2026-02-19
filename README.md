# Azure Sentinel Identity Monitoring Lab (Microsoft Entra ID + Sentinel)

## 📌 Project Overview
This lab demonstrates how to configure Microsoft Sentinel to ingest Microsoft Entra ID (Azure AD) logs and perform identity-based threat detection using KQL.

The objective of this lab is to simulate a basic SOC environment where identity telemetry is collected, analyzed, and used to create detection rules.

---

## 🏗️ Architecture

Microsoft Entra ID → Diagnostic Settings → Log Analytics Workspace → Microsoft Sentinel → Analytics Rules → Incidents

---

## 🔧 Environment Setup

### 1️⃣ Created Log Analytics Workspace
- Name: LAW-SOC-LAB
- Region: West US 2

### 2️⃣ Deployed Microsoft Sentinel
- Workspace onboarded to Sentinel

### 3️⃣ Enabled Entra ID Data Connector
- Enabled:
  - Sign-in Logs
  - Audit Logs

### 4️⃣ Configured Diagnostic Settings
- Sent Entra ID logs to Log Analytics Workspace

---

## 🧪 Log Verification

Test Query:
```kql
SigninLogs
| take 5
