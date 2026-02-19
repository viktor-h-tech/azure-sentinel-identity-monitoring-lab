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

## 🚨 Incident Walkthrough

### Scenario
Simulated multiple failed login attempts against a user account.

### Detection
Custom KQL analytic rule triggered based on threshold:
> 5 failed logins within 5 minutes from same IP

### Investigation Steps
1. Reviewed SignInLogs in Microsoft Sentinel
2. Filtered by UserPrincipalName
3. Checked ResultType for failures
4. Identified repeated attempts from same IP address
5. Verified no successful login occurred

### Findings
- Source IP: 192.168.x.x (lab environment)
- No successful authentication
- Account not locked
- No risky sign-in flags triggered

### 🕒 Incident Timeline Analysis

| Time (UTC) | Event |
|------------|-------|
| 10:02      | Multiple failed sign-in attempts detected |
| 10:04      | >5 failed logins from same IP within 5 minutes |
| 10:05      | Analytic rule triggered |
| 10:06      | Incident generated in Microsoft Sentinel |
| 10:08      | Manual investigation started |

**Observation:**
All attempts originated from the same source IP within a short timeframe, indicating automated brute-force behavior.

No successful login was recorded.

### Conclusion
This activity was identified as a simulated brute-force attempt conducted within a controlled lab environment. 
No successful authentication occurred, and no indicators of compromise were observed. No escalation was required.

---

## 🎯 MITRE ATT&CK Mapping

**Tactic:** Credential Access  
**Technique:** Brute Force  
**Technique ID:** T1110  

This simulated activity aligns with MITRE ATT&CK technique T1110 (Brute Force), where an attacker attempts multiple password guesses to gain unauthorized access to an account.

The detection logic was designed to identify repeated failed authentication attempts from a single IP address within a short time window.

---

## ⚙️ Detection Rule Configuration

**Rule Name:** Excessive Failed Sign-In Attempts  
**Log Source:** SigninLogs (Microsoft Entra ID)  
**Query Frequency:** Every 5 minutes  
**Lookup Period:** Last 5 minutes  
**Trigger Threshold:** > 5 failed sign-ins from same IP  

### KQL Query Used

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 5
| sort by FailedAttempts desc
```
---

## 🧪 Log Verification

Test Query:
```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| sort by FailedAttempts desc
```
## 📸 Evidence Screenshots

### 1️⃣ Sign-in Logs Showing Failed Attempts
![Failed Logins Screenshot](images/failed-logins.png)

### 2️⃣ KQL Query Results
![KQL Query Results](images/kql-results.png)

### 3️⃣ Sentinel Incident Triggered
![Incident Triggered](images/incident-triggered.png)
