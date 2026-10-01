# ZERO-TRUST TELEMETRY & BACKGROUND PROCESS BLOCKER (EDR-LITE)
### Senior Cybersecurity Engineer Architecture & Safe Testing Guide
**Target Systems:** Windows 10/11 Enterprise & Linux Workstations  
**Compliance Standard:** NIST CSF 2.0 (PR.AC-5, DE.CM-1), CIS Benchmarks Level 2  

---

## 1. Modular Architecture Overview

The tool is partitioned into three decoupled security modules:

1. **Process Scanner (`ProcessScanner`)**:
   - **Mechanism:** Traverses native OS process metadata using Windows Management Instrumentation (`Win32_Process`) or Linux `/proc/[pid]/comm` and `/proc/[pid]/exe`.
   - **Cybersecurity Defense:** Reads the executable file directly from disk and computes its cryptographic **SHA-256 binary hash**. This stops **Process Masquerading (MITRE ATT&CK T1036)** where an attacker renames a malicious beacon to a legitimate name like `svchost.exe`.

2. **Firewall Rule Manager (`FirewallManager`)**:
   - **Mechanism:** Dispatches dynamic outbound block rules into **Windows Defender Firewall** (`netsh advfirewall firewall add rule ... dir=out action=block`) or Linux `iptables` / `nftables`.
   - **Cybersecurity Defense (Anti-Command Injection):** All input parameters (file paths, executable names) are strictly filtered against shell metacharacters (`;`, `|`, `&`, `$`, `` ` ``) and executed via direct argv token arrays (ProcessBuilder) with **no shell interpolation** (`shell=False`).

3. **Zero-Trust Authorization Engine (`ZeroTrustEngine`)**:
   - **Mechanism:** Implements a strict **Default-Deny Stance**. By default, background web traffic is rejected unless the operator explicitly whitelists:
     - The executable's **SHA-256 cryptographic hash** (permanent authentic application).
     - Or the specific runtime **Process ID (PID)** (time-bounded temporary lease).

---

## 2. Compilation & Administrative Privilege Setup

### Option A: Java Core (`ZeroTrustEdrEngine.java`)

#### Prerequisites:
- Java JDK 11 or higher (`javac -version`)

#### Step 1: Compile the Java Class
Open your terminal in the `/desktop/edr/` folder:
```bash
javac ZeroTrustEdrEngine.java
```
This produces `ZeroTrustEdrEngine.class` and its internal module classes.

#### Step 2: Run with Administrative Privileges
Host firewall manipulation (`netsh advfirewall`) requires administrative elevation:

- **On Windows (Administrator Prompt):**
  1. Press `Windows Key`, type `cmd` or `PowerShell`.
  2. Right-click and choose **"Run as Administrator"**.
  3. Navigate to the project directory and execute:
     ```cmd
     java ZeroTrustEdrEngine
     ```

- **On Linux (Root / sudo):**
  ```bash
  sudo java ZeroTrustEdrEngine
  ```

---

### Option B: Python Core (`zero_trust_edr.py`)

#### Prerequisites:
- Python 3.8+ (Zero external pip dependencies required — uses pure standard library `ctypes`, `subprocess`, `hashlib`, `os`).

#### Execution:
- **On Windows (Admin CMD / PowerShell):**
  ```cmd
  python zero_trust_edr.py
  ```

- **On Linux (Terminal):**
  ```bash
  sudo python3 zero_trust_edr.py
  ```

---

## 3. Safe Sandbox Testing Guide (Isolated Verification)

Never test endpoint security tools on an unbacked-up production machine without verification. Follow these three isolated testing procedures:

### Test 1: Isolated Testing in Windows Sandbox (Recommended for Windows)
Windows 10/11 includes a native, disposable Hyper-V sandbox:
1. Press `Win + R`, type `optionalfeatures.exe`, check **"Windows Sandbox"**, and reboot if needed.
2. Launch **Windows Sandbox**.
3. Copy `ZeroTrustEdrEngine.java` or `zero_trust_edr.py` and paste it inside the Sandbox desktop.
4. Run the engine inside the sandbox.
5. Launch Microsoft Edge or a background updater: watch the EDR engine identify `microsoftedgeupdate.exe`, compute its SHA-256 hash, and inject the Windows Defender Firewall outbound block rule!
6. Close the sandbox: the entire virtual machine is discarded with zero trace left on your host PC.

### Test 2: Safe Firewall Verification Command
To verify that the block rule was successfully placed into the Windows Defender Firewall:
```cmd
netsh advfirewall firewall show rule name="ZeroTrustEDR_Block_microsoftedgeupdate.exe"
```
You will observe:
```text
Rule Name:       ZeroTrustEDR_Block_microsoftedgeupdate.exe
Enabled:         Yes
Direction:       Out
Profiles:        Domain,Private,Public
Action:          Block
Program:         C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe
```

### Test 3: Emergency Cleanup / Rollback Command
To remove all injected EDR rules at any time:
```cmd
netsh advfirewall firewall delete rule name=all | findstr "ZeroTrustEDR"
```
Or run the built-in 1-Click Rollback inside the SurfaceGuard desktop application.
