# 🔍 Incident Response Analysis: Brute-Force Attack Investigation

---

## 📌 **Overview**
### 🛠️ **Background**
Brute-force attacks are a common method used by attackers to gain unauthorized access by systematically trying multiple username-password combinations. If a system is exposed to the internet with weak authentication mechanisms, it becomes a high-risk target.

In this analysis, we investigate a brute-force attack on **two Virtual Machines (VMs)** from **two different public IP addresses**. The goal is to:
- **Identify affected VMs** and **track attack sources**.
- **Check if any login attempts were successful**.
- **Contain and mitigate the threat**.

---

## ⚙️ **Tools & Platform Used**
| **Component**           | **Details** |
|------------------------|------------|
| **Cloud Environment**  | Microsoft Azure |
| **Logging Platform**   | Microsoft Defender for Endpoint (MDE) |
| **Query Language**     | Kusto Query Language (KQL) |
| **Authentication Logs**| Azure Sign-In & Event Logs |

---

## 🚀 **Incident Analysis**
### 🔹 **Step 1: Identifying Brute-Force Attempts**
#### 🔍 **Why?**
Brute-force attacks generate a high volume of **failed login attempts** within a short period. By analyzing authentication logs, we can pinpoint **which VMs were targeted and from where**.

#### 📌 **KQL Query Used**
```kql
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated > ago(12h)
| summarize LogonFailureCount = count() by RemoteIP, ActionType, DeviceName
| where LogonFailureCount >= 40
| order by LogonFailureCount desc
```

#### 📊 **Findings**
| **Attacker IP**      | **Action**       | **Targeted VM**                                   | **Failed Logins** |
|----------------------|-----------------|-------------------------------------------------|------------------|
| `185.170.144.3`     | LogonFailed      | `king-vm-final`                                | 98               |
| `117.72.114.128`    | LogonFailed      | `linux-scan-agent-ajs.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net` | 48               |

🛑 **Conclusion**: Two different **public IP addresses** repeatedly attempted to log in to two separate virtual machines, **indicating an active brute-force attack**.

---

### 🔹 **Step 2: Checking for Successful Logins**
#### 🔍 **Why?**
A successful login from these attacker IPs would confirm unauthorized access. If an attacker gained entry, additional **forensic investigation** and **incident containment** would be required.

#### 📌 **KQL Query Used**
```kql
DeviceLogonEvents
| where RemoteIP in ("185.170.144.3", "117.72.114.128")
| where ActionType != "LogonFailed"
```

#### 📊 **Findings**
No records were returned, confirming that **none of the brute-force attempts resulted in a successful login**.

✅ **Conclusion**: The attack was unsuccessful, but the high number of failed attempts indicates **persistent targeting**, requiring proactive mitigation.

---

## 🛡️ **Containment & Mitigation Actions**
### ✅ **Immediate Actions Taken**
1. **Isolated Compromised Devices in Microsoft Defender for Endpoint (MDE)**  
   - Both `king-vm-final` and `linux-scan-agent` were **isolated** to prevent lateral movement.
   - Remote access was **temporarily blocked**.

2. **Conducted Antimalware Scans**
   - Full antivirus scans were triggered on both devices within **Microsoft Defender for Endpoint**.
   - No malware was detected, confirming that **no post-exploitation activity occurred**.

---

### ✅ **Preventive Measures Implemented**
1. **Network Security Group (NSG) Update**
   - **Modified NSG rules** to allow **RDP (3389) connections only from approved IP addresses**.
   - Implemented **Geo-blocking** to prevent access from untrusted regions.
   - Encouraged the use of **Azure Bastion** instead of direct RDP access.

2. **Policy Proposal for Future VMs**
   - **All new Virtual Machines** must follow a **strict NSG policy** requiring:
     - **Zero direct RDP/SSH exposure to the internet**.
     - **VPN or Bastion Host** for remote access.
     - **Multi-Factor Authentication (MFA) enforcement**.
     - **Logging & alerting for failed login attempts exceeding 10 per minute**.

---

## 🔥 **Final Thoughts**
- **No successful logins** were detected, but **persistent brute-force attempts** highlight the need for **stronger access controls**.
- By implementing **NSG restrictions, proactive monitoring, and enforcing security policies**, the risk of unauthorized access is significantly reduced.
- Future VM deployments must adhere to **secure-by-default configurations** to prevent similar attacks.

---

## 📂 **Additional Resources**
- 📂 **Incident Response Playbook**: [GitHub Repository](https://github.com/rasheedjimoh/incident-response-playbook)
- 📌 **Threat Hunting Queries**: [Azure KQL Query Reference](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/)

---

**📌 Author:** Rasheed Jimoh  
**📅 Date:** February 24, 2025  
**🔐 Focus Area:** Threat Hunting & Incident Response  

---

*© Rasheed Jimoh. All rights reserved.* 🚀🔐
