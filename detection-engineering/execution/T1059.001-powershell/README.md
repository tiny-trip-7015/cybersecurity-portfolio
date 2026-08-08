# 🛡️ Detection Rule: Suspicious PowerShell Execution (T1059.001)

## 📋 Overview & Rationale
According to Red Canary's Threat Intelligence reports, **Command and Scripting Interpreter: PowerShell (T1059.001)** remains one of the most frequently observed adversary techniques. 

While PowerShell is essential for standard system administration, threat actors routinely abuse it as a Living-off-the-Land Binary (LOLBin). By leveraging execution parameters such as `-ExecutionPolicy Bypass`, `-NoProfile`, and `-WindowStyle Hidden`, adversaries can download payloads and execute arbitrary code while bypassing basic security controls and remaining hidden from end users.

To mitigate this risk, enterprise defenders require targeted detection engineering to identify anomalous PowerShell invocations—specifically when spawned by non-standard parent processes like Microsoft Office or web servers.

---

## ⚙️ Prerequisites & Log Sources

### Required Telemetry
To catch this behavior, the target host must have one of the following log sources enabled:
* 🛡️ **Sysmon**: Event ID 1 (Process Creation with full command-line details)
* 📜 **Windows Security Log**: Event ID 4688 (Requires GPO setting: *Include command line in process creation events*)
* 💻 **Microsoft Defender for Endpoint**: `DeviceProcessEvents` table

### Target SIEM Engines
This detection logic is provided in formats compatible with:
* 📊 **Microsoft Sentinel** (KQL)
* ⚡ **Splunk** (SPL)
* 🔍 **Elastic SIEM** (EQL / Lucene)

---

## 🧪 Validation & Testing
1. **Sandbox Setup**: Launch an isolated Windows VM with endpoint logging enabled.
2. **Execution**: Open Command Prompt (`cmd.exe`) and execute:
   ```cmd
   powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "Write-Host 'Detection Test'"
