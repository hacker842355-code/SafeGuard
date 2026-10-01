export interface Project2ThreatScenario {
  id: string; // e.g., 'SCN-A1', 'SCN-B1', etc.
  name: string;
  componentLetter: 'A' | 'B' | 'C' | 'D' | 'E';
  componentName: string;
  subComponentCode: string;
  subComponentName: string;
  attackDescription: string;
  attackSteps: string[];
  attackVector: string;
  affectedPhase: string;
  likelihood: 'VERY HIGH' | 'HIGH' | 'MEDIUM' | 'LOW' | 'VERY LOW';
  likelihoodJustification: string;
  impact: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  impactConsequences: string;
  currentMitigation: string;
  gapsInDefense: string;
  recommendedImprovements: string[];
  threatActors: ('Level 1 (Passive)' | 'Level 2 (Active Exploit)' | 'Level 3 (Sophisticated APT)')[];
  crossPlatformNuance: {
    windows: string;
    linux: string;
    macos: string;
  };
}

export const ATTACK_SURFACE_SUBCOMPONENTS = [
  {
    letter: 'A',
    name: 'Network Port Management',
    subComponents: [
      { code: 'A1', name: 'Port enumeration and audit mechanism', count: 1 },
      { code: 'A2', name: 'Firewall rule generation and application', count: 1 },
      { code: 'A3', name: 'Cross-platform firewall API abstraction layer', count: 1 },
      { code: 'A4', name: 'Timing windows and race conditions between audit and enforcement', count: 1 },
      { code: 'A5', name: 'User error scenarios (opening dangerous ports)', count: 1 },
      { code: 'A6', name: 'Legitimate service on unexpected port identification', count: 1 },
      { code: 'A7', name: 'Port fingerprinting and service identification', count: 1 },
    ],
  },
  {
    letter: 'B',
    name: 'Hardware Sandboxing (Camera/Microphone)',
    subComponents: [
      { code: 'B1', name: 'OS driver-level disable mechanisms', count: 1 },
      { code: 'B2', name: 'Firmware-level vulnerabilities and bypasses', count: 1 },
      { code: 'B3', name: 'Windows Audio API access control', count: 1 },
      { code: 'B4', name: 'Temporary enable/disable timeout logic', count: 1 },
      { code: 'B5', name: 'Malware interception of enable requests', count: 1 },
      { code: 'B6', name: 'Hardware-specific bypass techniques', count: 1 },
    ],
  },
  {
    letter: 'C',
    name: 'File System Hardening',
    subComponents: [
      { code: 'C1', name: 'Permission audit logic and decision making', count: 1 },
      { code: 'C2', name: 'Permission application and enforcement', count: 1 },
      { code: 'C3', name: 'System service dependency analysis', count: 1 },
      { code: 'C4', name: 'OS compatibility and service account validation', count: 1 },
      { code: 'C5', name: 'Rollback and recovery mechanisms', count: 1 },
      { code: 'C6', name: 'Race conditions during hardening execution', count: 1 },
    ],
  },
  {
    letter: 'D',
    name: 'Privilege Access Management (PAM)',
    subComponents: [
      { code: 'D1', name: 'Temporary access grant mechanisms and approval workflow', count: 1 },
      { code: 'D2', name: 'Timeout/expiration logic and enforcement', count: 1 },
      { code: 'D3', name: 'Cryptographic protection of enable requests', count: 1 },
      { code: 'D4', name: 'Audit logging and accountability', count: 1 },
      { code: 'D5', name: 'User interface and social engineering risks', count: 1 },
      { code: 'D6', name: 'Malware tampering with timeout mechanisms', count: 1 },
    ],
  },
  {
    letter: 'E',
    name: 'Cross-Platform Implementation',
    subComponents: [
      { code: 'E1', name: 'Windows Registry tampering and Group Policy override', count: 1 },
      { code: 'E2', name: 'Linux iptables persistence and SELinux/AppArmor integration', count: 1 },
      { code: 'E3', name: 'macOS notarization bypass and sandbox containment', count: 1 },
      { code: 'E4', name: 'Cross-platform abstraction layer inconsistencies', count: 1 },
      { code: 'E5', name: 'Platform detection and verification', count: 1 },
      { code: 'E6', name: 'Platform-specific privilege escalation paths', count: 1 },
    ],
  },
];

export const PROJECT2_SCENARIOS: Project2ThreatScenario[] = [
  // ==========================================
  // COMPONENT A: NETWORK PORT MANAGEMENT (5 Scenarios)
  // ==========================================
  {
    id: 'SCN-A1',
    name: 'Audit-to-Enforcement Time-of-Check Time-of-Use (TOCTOU) Socket Injection',
    componentLetter: 'A',
    componentName: 'Network Port Management',
    subComponentCode: 'A4',
    subComponentName: 'Timing windows and race conditions between audit and enforcement',
    attackDescription: 'An active userland malware monitors process execution. When it detects the hardening script executing the network audit routine (e.g. `netstat -ano` or `ss -tulpn`), it deliberately waits 150 milliseconds for the audit loop to finish recording open sockets, and instantly binds an anomalous listening backdoor to an ephemeral port before firewall packet-filtering rules are applied.',
    attackSteps: [
      'Step 1: Malware monitors execution of network socket inspection commands.',
      'Step 2: Script finishes enumerating listening ports and transitions to generating firewall rule set.',
      'Step 3: Malware issues non-blocking bind() syscall on TCP port 4444 during the 500ms compilation delay.',
      'Step 4: Hardening script applies rules based only on pre-recorded socket snapshot, leaving the new port unblocked.'
    ],
    attackVector: 'Local unprivileged/standard user process exploiting timing window during sequential scripting.',
    affectedPhase: 'Phase 1: Network Attack Surface Reduction',
    likelihood: 'HIGH',
    likelihoodJustification: 'Timing attacks are trivial to automate on modern multi-core operating systems when script execution is non-atomic and takes >100ms.',
    impact: 'HIGH',
    impactConsequences: 'Attacker gains an active listening backdoor on the host that bypasses the automated firewall hardening rules completely.',
    currentMitigation: 'Script invokes firewall rule generation immediately following the audit iteration.',
    gapsInDefense: 'Audit and rule generation occur in separate userspace execution cycles without kernel socket locking or an atomic transition state.',
    recommendedImprovements: [
      'Atomic Transaction: Establish a kernel-level netfilter lock or snapshot table before enumeration begins.',
      'Post-Enforcement Re-Verification: Perform an immediate secondary socket sweep within 25ms of rule application.',
      'Kernel Socket Monitoring Hook: Utilize eBPF (Linux) or WFP (Windows) to block new socket bindings during the hardening transaction window.',
      'Default-Deny Inbound Baseline: Set firewall profile to DROP all inbound before auditing active services.'
    ],
    threatActors: ['Level 2 (Active Exploit)', 'Level 3 (Sophisticated APT)'],
    crossPlatformNuance: {
      windows: 'Exploitable via rapid CreateProcess/WinSock socket binding between PowerShell pipeline stages.',
      linux: 'Exploitable via LD_PRELOAD socket monitor intercepting ss/netstat execution.',
      macos: 'pfctl anchor flush window allows binding before new ruleset is committed.'
    }
  },
  {
    id: 'SCN-A2',
    name: 'Command & Parameter Injection in Cross-Platform Abstraction Shell Wrappers',
    componentLetter: 'A',
    componentName: 'Network Port Management',
    subComponentCode: 'A3',
    subComponentName: 'Cross-platform firewall API abstraction layer',
    attackDescription: 'The cross-platform script abstracts firewall commands by concatenating string arguments into shell invocations (`iptables -A INPUT -p tcp --dport ${port} -j DROP` or `netsh advfirewall firewall add rule name=${name} dir=in port=${port}`). An adversary with control over custom port configurations or environment variables injects shell metacharacters (`;`, `|`, `&`) to execute arbitrary commands with elevated root/SYSTEM privileges.',
    attackSteps: [
      'Step 1: Attacker identifies custom port configuration file or CLI argument passed to the hardening tool.',
      'Step 2: Attacker injects payload string: "8000; iptables -F; iptables -P INPUT ACCEPT; #".',
      'Step 3: Hardening script executes shell wrapper using subshell delegation (e.g. bash -c or cmd.exe /c).',
      'Step 4: Injected command executes as root/SYSTEM, completely neutralizing the host firewall.'
    ],
    attackVector: 'Local configuration tampering or unvalidated CLI parameter input passing to shell execution environments.',
    affectedPhase: 'Phase 1: Network Attack Surface Reduction',
    likelihood: 'MEDIUM',
    likelihoodJustification: 'Abstraction scripts frequently rely on string concatenation when targeting multiple different operating systems.',
    impact: 'CRITICAL',
    impactConsequences: 'Complete firewall bypass accompanied by arbitrary remote code execution under root/SYSTEM context.',
    currentMitigation: 'Basic port number regex validation checking for numeric characters.',
    gapsInDefense: 'CLI inputs passed directly to system shell execution rather than parameterized arrays or native C/API bindings.',
    recommendedImprovements: [
      'Eliminate Subshell Invocation: Use execFile without shell interpretation (no /bin/sh or cmd.exe).',
      'Strict Typed Schema: Validate inputs strictly against integer range 1-65535 with zero trailing characters.',
      'Native API Wrappers: Direct binding to Windows Filtering Platform (WFP) and Linux Netlink libmnl.',
      'Input Sanitization Fuzzing: Integrate automated fuzz testing into CI/CD for all firewall string builders.'
    ],
    threatActors: ['Level 2 (Active Exploit)', 'Level 3 (Sophisticated APT)'],
    crossPlatformNuance: {
      windows: 'PowerShell string interpolation allowing `Invoke-Expression` execution of malicious script blocks.',
      linux: 'Bash shell metacharacter injection via unsanitized iptables or ufw string variables.',
      macos: 'pfctl -f /dev/stdin injection via multi-line string manipulation.'
    }
  },
  {
    id: 'SCN-A3',
    name: 'Legitimate Port Tunneling & Protocol Masquerading via Allowed Ports (HTTPS/DNS)',
    componentLetter: 'A',
    componentName: 'Network Port Management',
    subComponentCode: 'A2',
    subComponentName: 'Firewall rule generation and application',
    attackDescription: 'The hardening script closes all unused ports but leaves Port 443 (HTTPS) and Port 53 (DNS) open for system updates and web browsing. An active attacker deploys a covert tunnel (e.g., DNS tunneling via dnscat2 or TLS WebSocket proxy) that multiplexes unauthorized SSH/RDP command-and-control traffic through the approved ports.',
    attackSteps: [
      'Step 1: Hardening script applies Layer-4 firewall rules: drops high ports, allows TCP 443 and UDP 53.',
      'Step 2: Attacker deploys agent that initiates outbound TLS connection on Port 443 to external proxy.',
      'Step 3: Inbound command-and-control channel is established as an encrypted tunnel payload.',
      'Step 4: Layer-4 firewall packet filters inspect only port numbers and pass the malicious traffic unhindered.'
    ],
    attackVector: 'Network protocol encapsulation over legitimate outbound and bidirectional ports.',
    affectedPhase: 'Phase 1: Network Attack Surface Reduction',
    likelihood: 'HIGH',
    likelihoodJustification: 'Attackers routinely use Port 443/80/53 because corporate firewalls must permit standard web egress.',
    impact: 'HIGH',
    impactConsequences: 'Attacker maintains persistent, encrypted command-and-control channel despite 100% port closure compliance.',
    currentMitigation: 'Firewall drop rules for unassigned and legacy ports (e.g. SMB 445, Telnet 23).',
    gapsInDefense: 'Script operates strictly at Layer 4 (TCP/UDP port numbers) without Layer 7 deep packet inspection or process correlation.',
    recommendedImprovements: [
      'Process-to-Port Correlation: Bind firewall rules to specific binary hashes rather than open-ended port numbers.',
      'Layer 7 Protocol Validation: Inspect TLS handshakeSNI and HTTP/2 frames to detect non-standard payloads.',
      'Outbound Egress Hardening: Restrict outbound 443 connections only to approved enterprise destination IP ranges.',
      'DNS Traffic Sandboxing: Enforce system-wide DNS-over-HTTPS (DoH) to authenticated resolvers, blocking raw UDP 53 tunnels.'
    ],
    threatActors: ['Level 2 (Active Exploit)', 'Level 3 (Sophisticated APT)'],
    crossPlatformNuance: {
      windows: 'Windows Defender Application Control (WDAC) required to restrict network access per executable.',
      linux: 'cgroup net_cls or nftables meta skuid matching to confine sockets by user identity.',
      macos: 'NEFilterDataProvider extension required to inspect L7 traffic payloads.'
    }
  },
  {
    id: 'SCN-A4',
    name: 'Heuristic Port Misclassification & Debug Interface Exposure',
    componentLetter: 'A',
    componentName: 'Network Port Management',
    subComponentCode: 'A6',
    subComponentName: 'Legitimate service on unexpected port identification',
    attackDescription: 'To avoid breaking development tools, the script implements a heuristic to detect "developer workflows" by checking for active Node, Python, or Docker processes. An attacker renames a malicious remote shell binary to `node.exe` or `python3` and binds to Port 8000, deceiving the script heuristic into classifying the rogue listener as an approved developer service.',
    attackSteps: [
      'Step 1: Attacker drops malicious reverse shell binary named "node.exe" or "python3.11".',
      'Step 2: Binary binds to Port 8000 or Port 3000.',
      'Step 3: Hardening script runs port audit, inspects parent process name ("node.exe"), and classifies as "dev debug".',
      'Step 4: Hardening script automatically generates an allow rule, legitimizing the attacker listener.'
    ],
    attackVector: 'Process name spoofing and heuristic evasion against automated whitelisting rules.',
    affectedPhase: 'Phase 1: Network Attack Surface Reduction',
    likelihood: 'MEDIUM',
    likelihoodJustification: 'Process names are arbitrary metadata easily forged by unprivileged executables.',
    impact: 'HIGH',
    impactConsequences: 'Attacker listener receives official permanent firewall whitelist exemption.',
    currentMitigation: 'Script prompts user before applying aggressive closures to high ports.',
    gapsInDefense: 'Heuristic inspects process command line / name string without verifying digital signatures or binary hashes.',
    recommendedImprovements: [
      'Cryptographic Binary Verification: Verify digital certificate and SHA-256 hash against official runtime catalog.',
      'Localhost Binding Strictness: Enforce that developer ports can NEVER bind to 0.0.0.0; strictly enforce 127.0.0.1.',
      'Parent Process Lineage Tree: Validate that dev servers spawn directly from verified IDE binaries (e.g. VS Code, IntelliJ).',
      'Interactive Elevation Prompt: Require explicit user confirmation with binary path display before granting exception.'
    ],
    threatActors: ['Level 2 (Active Exploit)', 'Level 3 (Sophisticated APT)'],
    crossPlatformNuance: {
      windows: 'Inspect Authenticode signature on executable before allowing port binding.',
      linux: 'Inspect ELF binary hash and verify against dpkg/rpm database.',
      macos: 'Verify CodeSign entitlement and Apple Notarization status.'
    }
  },
  {
    id: 'SCN-A5',
    name: 'Socially Engineered User Deception into Opening High-Risk Ports (SMB/RDP)',
    componentLetter: 'A',
    componentName: 'Network Port Management',
    subComponentCode: 'A5',
    subComponentName: 'User error scenarios (opening dangerous ports)',
    attackDescription: 'Malware drops a deceptive dialogue box that mimics a native system notification stating: "Printer Sharing & System Update requires Port 445 temporarily enabled for 15 minutes." The user initiates a PAM request and opens Port 445, immediately exposing the host to lateral movement exploits like EternalBlue or SMB relay attacks.',
    attackSteps: [
      'Step 1: Phishing or adware executes in user session, presenting spoofed "Print Management" requirement.',
      'Step 2: Deceived user opens hardening tool UI or PAM prompt and requests Port 445 enable.',
      'Step 3: PAM module validates user credentials and issues temporary firewall allow rule.',
      'Step 4: Network attacker on adjacent LAN segment launches automated SMB credential harvesting and exploit payloads.'
    ],
    attackVector: 'Human factor social engineering exploiting user authorization over firewall configuration.',
    affectedPhase: 'Phase 1: Network Attack Surface Reduction',
    likelihood: 'HIGH',
    likelihoodJustification: 'Users are susceptible to convincing system update or printer configuration error messages.',
    impact: 'CRITICAL',
    impactConsequences: 'System is exposed to remote code execution and lateral credential theft on high-risk legacy ports.',
    currentMitigation: 'PAM authentication required before opening ports.',
    gapsInDefense: 'PAM module treats all port requests uniformly without distinguishing between low-risk web ports and high-risk legacy attack vectors.',
    recommendedImprovements: [
      'Hardcoded Veto Blacklist: Permanently forbid user-level opening of ports 445, 135-139, 3389 without dual admin keys.',
      'Contextual Risk Warnings: Display high-contrast warning banner explaining specific exploit mechanisms.',
      'Mandatory Confirmation Friction: Require user to type the danger reason and port number manually.',
      'Zero-Trust Network Access: Replace direct port opening with authenticated reverse proxies.'
    ],
    threatActors: ['Level 1 (Passive)', 'Level 2 (Active Exploit)'],
    crossPlatformNuance: {
      windows: 'Targeting SMB 445 and RDP 3389 for Pass-the-Hash and remote execution.',
      linux: 'Targeting SSH 22 and NFS 2049 for brute-force lateral movement.',
      macos: 'Targeting Apple Remote Desktop (ARD) 3283 and VNC 5900.'
    }
  },

  // ==========================================
  // COMPONENT B: HARDWARE SANDBOXING (5 Scenarios)
  // ==========================================
  {
    id: 'SCN-B1',
    name: 'Firmware-Level Peripheral DMA Bypass of OS Driver Disable',
    componentLetter: 'B',
    componentName: 'Hardware Sandboxing (Camera/Microphone)',
    subComponentCode: 'B2',
    subComponentName: 'Firmware-level vulnerabilities and bypasses',
    attackDescription: 'The hardening script disables camera and microphone devices at the OS driver layer (e.g. Device Manager or udev). However, an integrated PCIe or Thunderbolt webcam controller contains an unauthenticated microcontroller with Direct Memory Access (DMA). An attacker flashes malicious firmware to the peripheral controller, streaming raw audio/video frames directly into system RAM or transmitting via PCIe.',
    attackSteps: [
      'Step 1: Attacker obtains administrative access or exploits firmware vulnerability in peripheral microcontroller.',
      'Step 2: Malicious firmware is flashed into camera EEPROM/SPI flash.',
      'Step 3: Host OS driver disablement only stops Windows/Linux driver polling.',
      'Step 4: Peripheral continues operating autonomously at the silicon level, capturing sensory data independently of the OS.'
    ],
    attackVector: 'Peripheral microcontroller firmware compromise with bus-level access.',
    affectedPhase: 'Phase 2: Hardware Sandboxing & Peripheral Lockdown',
    likelihood: 'LOW',
    likelihoodJustification: 'Requires firmware reverse engineering or physical/flashing capabilities, typical of sophisticated APT actors.',
    impact: 'CRITICAL',
    impactConsequences: 'Permanent, OS-invisible audio/video eavesdropping that survives full operating system re-installation.',
    currentMitigation: 'OS driver disablement via registry and udev permissions.',
    gapsInDefense: 'Software-level driver disablement cannot prevent autonomous hardware firmware execution or bus DMA.',
    recommendedImprovements: [
      'Kernel DMA Protection: Enforce IOMMU / VT-d / AMD-Vi DMA remapping at the UEFI bootloader level.',
      'Hardware Bus Power Cutoff: Toggle ACPI D3cold power state to completely cut electrical power to peripheral USB/PCIe lanes.',
      'Hardware Cryptographic Attestation: Validate peripheral firmware signatures before permitting bus attachment.',
      'Physical Shutter Policy: Recommend or enforce physical camera privacy slider switches on endpoint hardware.'
    ],
    threatActors: ['Level 3 (Sophisticated APT)'],
    crossPlatformNuance: {
      windows: 'Enforce Kernel DMA Protection in Windows Defender System Guard.',
      linux: 'Enable intel_iommu=on / amd_iommu=on and USBGuard daemon.',
      macos: 'Apple Silicon Unified Memory architecture enforces IOMMU by default for all external Thunderbolt devices.'
    }
  },
  {
    id: 'SCN-B2',
    name: 'Malware Piggybacking and Time Extension on Legitimate PAM Hardware Grants',
    componentLetter: 'B',
    componentName: 'Hardware Sandboxing (Camera/Microphone)',
    subComponentCode: 'B5',
    subComponentName: 'Malware interception of enable requests',
    attackDescription: 'A user legitimately activates their camera via PAM for a scheduled 30-minute Zoom call. Userland spyware detects the peripheral transition from DISABLED to ENABLED, silently taps into the DirectShow / Video4Linux capture pipeline, and streams video frames concurrently while the user believes only Zoom is accessing the sensor.',
    attackSteps: [
      'Step 1: User requests 30-minute camera grant via PAM for a video meeting.',
      'Step 2: PAM module enables hardware camera driver for the operating system.',
      'Step 3: Background malware receives OS device arrival notification (`WM_DEVICECHANGE` or udev event).',
      'Step 4: Malware opens concurrent capture stream to the hardware device node and records undetected.'
    ],
    attackVector: 'Concurrent capture stream interception during authorized operational time windows.',
    affectedPhase: 'Phase 2: Hardware Sandboxing & Peripheral Lockdown',
    likelihood: 'HIGH',
    likelihoodJustification: 'Once a device node is enabled system-wide, any process with appropriate permissions can read the video stream.',
    impact: 'HIGH',
    impactConsequences: 'Unauthorized audio/video surveillance occurring within approved user operational windows.',
    currentMitigation: 'Time-bounded grant window with automated countdown timer.',
    gapsInDefense: 'Hardware is enabled globally for the entire OS rather than sandboxed exclusively to the specific requesting application PID.',
    recommendedImprovements: [
      'PID-Scoped Device Binding: Restrict device read permissions strictly to the calling application process ID.',
      'Exclusive Device Locking: Enforce single-client exclusive capture modes on video/audio device nodes.',
      'Active Hardware Indicator Monitoring: Provide high-visibility desktop alert whenever any process accesses camera streams.',
      'Process Termination Hook: Immediately re-lock peripheral as soon as the authenticated video app process terminates.'
    ],
    threatActors: ['Level 2 (Active Exploit)', 'Level 3 (Sophisticated APT)'],
    crossPlatformNuance: {
      windows: 'Monitor CapabilityAccessManager and use Windows 11 Privacy Auditing to flag concurrent stream consumers.',
      linux: 'Use cgroup device controllers to grant /dev/video0 exclusively to the video conference cgroup.',
      macos: 'TCC enforces app-by-app permission, preventing silent secondary process attachment.'
    }
  },
  {
    id: 'SCN-B3',
    name: 'Secondary Virtual Audio Endpoint & Loopback Audio Query Bypass',
    componentLetter: 'B',
    componentName: 'Hardware Sandboxing (Camera/Microphone)',
    subComponentCode: 'B3',
    subComponentName: 'Windows Audio API access control',
    attackDescription: 'The hardening script disables the physical built-in microphone driver. However, the system retains active virtual audio cables, stereo mix loopback drivers, or USB headset interfaces. Malware queries WASAPI or PulseAudio virtual endpoints, capturing ongoing audio conversations from incoming VoIP speech or secondary acoustic sensors.',
    attackSteps: [
      'Step 1: Hardening script identifies default built-in mic and disables driver via PnP API.',
      'Step 2: Attacker queries Windows Core Audio / WASAPI or PipeWire device enumeration APIs.',
      'Step 3: Attacker discovers secondary loopback endpoint (Stereo Mix, Virtual Audio Cable, or Bluetooth headset).',
      'Step 4: Audio recording begins through secondary endpoint, bypassing physical microphone lockdown.'
    ],
    attackVector: 'Acoustic side-channel and virtual audio driver routing bypass.',
    affectedPhase: 'Phase 2: Hardware Sandboxing & Peripheral Lockdown',
    likelihood: 'HIGH',
    likelihoodJustification: 'Operating systems frequently maintain 3-8 distinct audio capture endpoints across headsets, HDMI, and software mixers.',
    impact: 'HIGH',
    impactConsequences: 'Eavesdropping on room audio or bidirectional VoIP conversations despite primary mic disablement.',
    currentMitigation: 'Driver disablement of primary default microphone.',
    gapsInDefense: 'Fails to audit and disable secondary, virtual, loopback, and Bluetooth audio capture endpoints.',
    recommendedImprovements: [
      'Universal Audio Subsystem Mute: Mute and isolate all audio input capture endpoints simultaneously.',
      'Virtual Audio Driver Purge: Audit and disable unverified third-party virtual audio loopback drivers.',
      'OS Audio Service Enforcement: Restrict audio capture services at the Windows Audio / PulseAudio service layer.',
      'Bluetooth Device Restriction: Automatically sever Bluetooth Headset Profile (HSP/HFP) recording channels when locked.'
    ],
    threatActors: ['Level 2 (Active Exploit)'],
    crossPlatformNuance: {
      windows: 'Audit all endpoints in `CoreAudio` COM interfaces and disable `Stereo Mix`.',
      linux: 'Unload `snd-aloop` kernel module and mute all PulseAudio/PipeWire sources via `pactl`.',
      macos: 'Revoke CoreAudio input taps via System Audio HAL plugin policies.'
    }
  },
  {
    id: 'SCN-B4',
    name: 'Monotonic Scheduling Failure During Power State Transitions (Sleep/Hibernate)',
    componentLetter: 'B',
    componentName: 'Hardware Sandboxing (Camera/Microphone)',
    subComponentCode: 'B4',
    subComponentName: 'Temporary enable/disable timeout logic',
    attackDescription: 'A user opens the camera for 30 minutes. At minute 10, the user closes their laptop lid, triggering ACPI S3 sleep. The userspace timer process halts during sleep. When the laptop wakes 4 hours later, the software timer either drops out or fails to account for elapsed real time, leaving the camera enabled permanently.',
    attackSteps: [
      'Step 1: Camera enabled with userspace countdown timer (setTimeout / thread sleep).',
      'Step 2: Operating system enters ACPI S3 sleep or S4 hibernation.',
      'Step 3: Userspace timer execution is paused; monotonic tick count is interrupted.',
      'Step 4: Machine resumes hours later; timer fails to fire, leaving hardware permanently enabled.'
    ],
    attackVector: 'Power state transition desynchronization exploiting userspace timer limitations.',
    affectedPhase: 'Phase 2: Hardware Sandboxing & Peripheral Lockdown',
    likelihood: 'HIGH',
    likelihoodJustification: 'Laptop lid closures and sleep transitions occur multiple times daily in standard enterprise usage.',
    impact: 'HIGH',
    impactConsequences: 'Prolonged, indefinite exposure of video/audio capture capabilities without user awareness.',
    currentMitigation: 'Userspace countdown timer that triggers disable callback at zero.',
    gapsInDefense: 'Relies on volatile userspace timers that do not hook OS power management events or use RTC monotonic clocks.',
    recommendedImprovements: [
      'Hardware RTC Clocks: Anchor timeout calculations to hardware Real-Time Clocks rather than userland timers.',
      'ACPI Power State Listeners: Register power broadcast listeners to enforce immediate lockdown upon resume.',
      'Kernel Scheduled Tasks: Implement timeouts as OS-level scheduled tasks (Task Scheduler / systemd timers).',
      'Independent Fail-Safe Watchdog: Secondary daemon that asserts lockdown if heartbeat signal is missed.'
    ],
    threatActors: ['Level 2 (Active Exploit)'],
    crossPlatformNuance: {
      windows: 'Register for `RegisterSuspendResumeNotification` and query `QueryUnbiasedInterruptTime`.',
      linux: 'Create systemd sleep hook in `/lib/systemd/system-sleep/` to re-assert lockdown on wake.',
      macos: 'Listen for `NSWorkspaceDidWakeNotification` and query `mach_continuous_time()`.'
    }
  },
  {
    id: 'SCN-B5',
    name: 'Camera Status Indicator Spoofing / LED Decoupling',
    componentLetter: 'B',
    componentName: 'Hardware Sandboxing (Camera/Microphone)',
    subComponentCode: 'B6',
    subComponentName: 'Hardware-specific bypass techniques',
    attackDescription: 'On certain legacy or low-cost webcam hardware, the physical activity LED is controlled via software firmware rather than hardwired directly in series with the camera sensor power rail. An attacker utilizes known firmware exploits to activate the image sensor while suppressing the activity LED, streaming video without visual indication.',
    attackSteps: [
      'Step 1: Attacker identifies webcam model with software-controlled LED register.',
      'Step 2: Attacker sends raw UVC (USB Video Class) vendor-specific extension unit commands.',
      'Step 3: Camera firmware clears the LED status bit while keeping image sensor powered.',
      'Step 4: Video is captured without the user noticing the LED indicator illumination.'
    ],
    attackVector: 'Firmware register manipulation of UVC Extension Units (XU).',
    affectedPhase: 'Phase 2: Hardware Sandboxing & Peripheral Lockdown',
    likelihood: 'LOW',
    likelihoodJustification: 'Modern laptops (Apple, Lenovo, Dell) hardwire LEDs in series with sensor power rails, but older peripherals remain vulnerable.',
    impact: 'CRITICAL',
    impactConsequences: 'Completely stealthy visual surveillance bypassing user physical inspection.',
    currentMitigation: 'User relies on camera LED indicator to detect camera activity.',
    gapsInDefense: 'Script assumes hardware LED is tamper-proof and fails to block vendor-specific UVC control commands.',
    recommendedImprovements: [
      'Block UVC Extension Units: Disallow raw vendor XU commands through USB device filter drivers.',
      'Hardware Assessment Database: Audit endpoint hardware models and flag devices with uncoupled LEDs.',
      'OS Desktop Overlay Banner: Display an unmissable on-screen desktop overlay whenever camera capture is active.',
      'Physical Lens Covers: Standardize physical mechanical sliding privacy covers across corporate endpoints.'
    ],
    threatActors: ['Level 3 (Sophisticated APT)'],
    crossPlatformNuance: {
      windows: 'Filter USB video driver requests via custom lower-filter driver in device stack.',
      linux: 'Inspect uvcvideo kernel module parameters and disable extension controls.',
      macos: 'Apple Silicon enforces hardware-isolated green indicator LED directly in the sensor silicon.'
    }
  },

  // ==========================================
  // COMPONENT C: FILE SYSTEM HARDENING (4 Scenarios)
  // ==========================================
  {
    id: 'SCN-C1',
    name: 'Aggressive ACL Lockdown Severing OS Update and Service Accounts',
    componentLetter: 'C',
    componentName: 'File System Hardening',
    subComponentCode: 'C3',
    subComponentName: 'System service dependency analysis',
    attackDescription: 'The hardening script audits world-writable and shared system directories (e.g. `C:\\ProgramData`, `/tmp`, `/var/tmp`) and aggressively removes read/write permissions for all non-Administrator accounts. Consequently, core system service accounts (such as `NT SERVICE\\TrustedInstaller`, `NetworkService`, or Linux `systemd-resolve`) lose required write privileges, causing critical security patches and DNS daemons to crash.',
    attackSteps: [
      'Step 1: Script runs recursive permission audit, flags ProgramData as overly permissive.',
      'Step 2: Script applies strict ACL: grants SYSTEM and Administrators; strips all other SIDs.',
      'Step 3: Windows Update / Package Manager launches under NetworkService, attempts to stage update files, and fails with ACCESS_DENIED.',
      'Step 4: Machine fails to receive zero-day security patches, creating an unpatched vulnerability window.'
    ],
    attackVector: 'Self-inflicted Denial of Service against critical operating system patch maintenance services.',
    affectedPhase: 'Phase 3: File System Hardening',
    likelihood: 'VERY HIGH',
    likelihoodJustification: 'Aggressive filesystem permission scripts frequently break background services due to hidden service account dependencies.',
    impact: 'HIGH',
    impactConsequences: 'Host becomes permanently unpatchable, leading to subsequent exploitation of unpatched vulnerabilities.',
    currentMitigation: 'Manual user review before applying permission changes.',
    gapsInDefense: 'Lack of automated service account dependency graph analysis before committing restrictive ACL changes.',
    recommendedImprovements: [
      'Service Account Whitelisting: Pre-program explicit preservation rules for known service accounts (NT SERVICE\\*, LocalService, NetworkService).',
      'Pre-Flight Dry Run Simulation: Validate that write tests succeed for all active background service accounts before committing.',
      'Automated Health Verification: Test OS update service functionality within 60 seconds of applying filesystem modifications.',
      'Rapid Snapshot Rollback: Instant 1-click restore of original security descriptors if system anomalies occur.'
    ],
    threatActors: ['Level 2 (Active Exploit)'],
    crossPlatformNuance: {
      windows: 'Preserve inherited permissions for `CREATOR OWNER`, `NT SERVICE\\TrustedInstaller`, and `ALL APPLICATION PACKAGES`.',
      linux: 'Preserve sticky bit (`+t`) on `/tmp` and `/var/tmp` rather than removing write access for standard users.',
      macos: 'Respect System Integrity Protection (SIP) rootless paths; never modify `/System` or `/usr/bin` ACLs.'
    }
  },
  {
    id: 'SCN-C2',
    name: 'Execution Race Condition Exploiting Hardening Phase Gaps',
    componentLetter: 'C',
    componentName: 'File System Hardening',
    subComponentCode: 'C6',
    subComponentName: 'Race conditions during hardening execution',
    attackDescription: 'Hardening executes sequentially: Phase 1 network -> Phase 2 hardware -> Phase 3 filesystem -> Phase 4 PAM. Malware already residing on the host observes Phase 1 finishing and Phase 2 starting. During this 2-3 second window, malware creates a persistent scheduled task in a system directory before Phase 3 filesystem ACLs are locked down.',
    attackSteps: [
      'Step 1: Script launches and begins Phase 1 network socket sweep.',
      'Step 2: Resident malware detects script execution and waits for Phase 1 to terminate.',
      'Step 3: Malware drops persistence payload into `/etc/cron.d/` or `C:\\ProgramData\\Startup` before Phase 3 arrives.',
      'Step 4: Phase 3 applies ACLs to the directory, but the malicious payload has already been written and scheduled.'
    ],
    attackVector: 'Inter-phase execution gap exploitation during sequential script deployment.',
    affectedPhase: 'Phase 3: File System Hardening',
    likelihood: 'MEDIUM',
    likelihoodJustification: 'Multi-stage scripts that take several seconds to execute create observable transition gaps.',
    impact: 'HIGH',
    impactConsequences: 'Malware secures permanent reboot persistence despite subsequent directory hardening.',
    currentMitigation: 'Sequential phased execution model.',
    gapsInDefense: 'Phases operate as isolated sequential batches rather than an atomic single-pass security state change.',
    recommendedImprovements: [
      'Atomic Single-Pass Commitment: Compile all phase configurations into a unified transaction and commit simultaneously.',
      'Early Maintenance State: Temporarily suspend non-essential processes or enter single-user/safe mode during hardening.',
      'Pre-Commit Directory Sweep: Scan target directories for newly created files before applying final permission seals.',
      'Immutable Execution Directory: Execute the hardening tool from an isolated, cryptographically sealed RAM disk.'
    ],
    threatActors: ['Level 2 (Active Exploit)', 'Level 3 (Sophisticated APT)'],
    crossPlatformNuance: {
      windows: 'Deploy via Windows Preinstallation Environment (WinPE) or Early-Launch Antimalware (ELAM).',
      linux: 'Execute during systemd `basic.target` before `multi-user.target` initializes third-party daemons.',
      macos: 'Execute via early boot LaunchDaemon with high nice priority.'
    }
  },
  {
    id: 'SCN-C3',
    name: 'NTFS Alternate Data Streams (ADS) & Symlink Traversal Audit Spoofing',
    componentLetter: 'C',
    componentName: 'File System Hardening',
    subComponentCode: 'C1',
    subComponentName: 'Permission audit logic and decision making',
    attackDescription: 'The hardening audit engine scans files by standard path names to verify permissions and hashes. An attacker stores malicious executable payloads inside NTFS Alternate Data Streams (e.g. `C:\\ProgramData\\legit.txt:backdoor.exe`) or uses POSIX symlinks. The audit script inspects only the primary file stream, reporting the directory as "100% Compliant and Hardened" while the hidden stream remains executable.',
    attackSteps: [
      'Step 1: Attacker writes executable payload into an NTFS Alternate Data Stream on an approved text file.',
      'Step 2: Hardening script audits directory permissions, inspecting only primary stream headers.',
      'Step 3: Audit passes with zero alerts, recording the file as compliant.',
      'Step 4: Attacker executes hidden stream using `wmic process call create "C:\\ProgramData\\legit.txt:backdoor.exe"`.'
    ],
    attackVector: 'Filesystem metadata obfuscation and Alternate Data Stream evasion.',
    affectedPhase: 'Phase 3: File System Hardening',
    likelihood: 'MEDIUM',
    likelihoodJustification: 'Basic scripts frequently rely on standard directory listing cmdlets that omit alternate stream streams.',
    impact: 'HIGH',
    impactConsequences: 'Malware executes from approved system directories while evading automated compliance verification.',
    currentMitigation: 'Standard recursive directory ACL audits.',
    gapsInDefense: 'Audit engine does not enumerate secondary file streams, extended attributes, or resolve symlink targets.',
    recommendedImprovements: [
      'ADS Stream Enumeration: Specifically query `Get-Item -Stream *` on Windows to detect and strip unauthorized secondary streams.',
      'Symlink Dereferencing Controls: Audit symlink targets and forbid cross-privilege boundary symlink creation.',
      'Cryptographic Directory Hashing: Calculate Merkle-tree directory hashes including all extended file attributes.',
      'Noexec Mount Flags: Enforce `noexec` on temporary and scratch storage mounts.'
    ],
    threatActors: ['Level 2 (Active Exploit)', 'Level 3 (Sophisticated APT)'],
    crossPlatformNuance: {
      windows: 'Enumerate and sanitize NTFS Alternate Data Streams on all audited system folders.',
      linux: 'Inspect extended attributes (`getfattr -d -m -`) and restrict symlink following via `fs.protected_symlinks=1`.',
      macos: 'Inspect and strip extended attributes (`xattr -l`) on shared directories.'
    }
  },
  {
    id: 'SCN-C4',
    name: 'Scheduled Hardening Cycle Gaming via Time-Based Evading Artifacts',
    componentLetter: 'C',
    componentName: 'File System Hardening',
    subComponentCode: 'C1',
    subComponentName: 'Permission audit logic and decision making',
    attackDescription: 'To maintain posture, the script runs an automated audit every 60 minutes on the hour. An attacker reverse-engineers the scheduled task schedule, deploys a temporary malicious tool at minute 05, executes malicious tasks, and deletes the payload at minute 55 before the next audit cycle runs, completely evading detection.',
    attackSteps: [
      'Step 1: Attacker examines Task Scheduler / cron jobs to determine exact audit execution intervals.',
      'Step 2: Attacker observes script executes precisely at `XX:00:00`.',
      'Step 3: Attacker drops exploit at `XX:02:00`, executes actions, and cleans up artifacts at `XX:58:00`.',
      'Step 4: Hardening script runs at `XX:00:00`, finds zero non-compliant files, and logs green status.'
    ],
    attackVector: 'Predictable scheduled audit cycle timing exploitation.',
    affectedPhase: 'Phase 3: File System Hardening',
    likelihood: 'HIGH',
    likelihoodJustification: 'Deterministic cron/scheduled task intervals are transparent and easily monitored by local adversaries.',
    impact: 'MEDIUM',
    impactConsequences: 'Attacker operates persistently within the 50-minute inspection vacuum without detection.',
    currentMitigation: 'Periodic scheduled re-auditing of configurations.',
    gapsInDefense: 'Audit schedule is strictly periodic and deterministic rather than continuous or event-driven.',
    recommendedImprovements: [
      'Event-Driven Kernel Auditing: Replace polling with realtime filesystem hooks (ReadDirectoryChangesW / inotify / FSEvents).',
      'Randomized Audit Intervals: Introduce randomized jitter (e.g. 15-45 minutes random delta) between audit cycles.',
      'Continuous Integrity Monitoring: Integrate with OS security auditing (Sysmon Event ID 11 / Linux auditd).',
      'Immutable Audit Logging: Stream filesystem modification events immediately to an out-of-band collector.'
    ],
    threatActors: ['Level 2 (Active Exploit)', 'Level 3 (Sophisticated APT)'],
    crossPlatformNuance: {
      windows: 'Deploy Sysmon file creation events or use FileSystemWatcher API.',
      linux: 'Deploy `auditd` with `-w /etc/ -p wa -k sys_config_change`.',
      macos: 'Integrate with EndpointSecurity framework for `ES_EVENT_TYPE_AUTH_CREATE`.'
    }
  },

  // ==========================================
  // COMPONENT D: PRIVILEGE ACCESS MANAGEMENT (PAM) (5 Scenarios)
  // ==========================================
  {
    id: 'SCN-D1',
    name: 'Repudiation & Audit Evasion via Local Log Truncation',
    componentLetter: 'D',
    componentName: 'Privilege Access Management (PAM)',
    subComponentCode: 'D4',
    subComponentName: 'Audit logging and accountability',
    attackDescription: 'An attacker tricks or coerces an administrative user into granting temporary SSH access via PAM. Following access, the attacker leverages their temporary elevated context to delete or truncate the local log file (`/var/log/hardening-pam.log` or `%ProgramData%\\Hardening\\pam.log`), destroying all forensic evidence of who authorized the elevation.',
    attackSteps: [
      'Step 1: Attacker obtains temporary elevation grant through social engineering or credential theft.',
      'Step 2: PAM module writes plaintext entry to local log file on the host.',
      'Step 3: Attacker accesses the host, locates the plaintext log file, and executes `echo "" > pam.log` or shred.',
      'Step 4: Security forensics team discovers unauthorized network traffic but finds zero record of the grant in local logs.'
    ],
    attackVector: 'Local log file tampering and anti-forensics in privileged execution context.',
    affectedPhase: 'Phase 4: Privilege Access Management (PAM)',
    likelihood: 'MEDIUM',
    likelihoodJustification: 'Adversaries routinely execute log wiping immediately upon gaining root/SYSTEM privileges.',
    impact: 'HIGH',
    impactConsequences: 'Loss of forensic accountability, inability to determine root cause, and repudiation of malicious activity.',
    currentMitigation: 'Standard local text file logging of grant requests.',
    gapsInDefense: 'Logs stored locally in standard writeable files without cryptographic forward-secrecy or remote streaming.',
    recommendedImprovements: [
      'Append-Only Cryptographic Hash Chains: Structure log entries so each record includes the SHA-256 hash of the previous record.',
      'Dual-Logging to OS Native Security Event Logs: Write to Windows Security Event Log (Event ID 4624/4672) or Linux auditd.',
      'Immediate Remote Syslog Forwarding: Stream elevation events over TLS to central SIEM prior to committing firewall changes.',
      'WORM Storage Enforcement: Enforce Write-Once Read-Many flags (`chattr +a` on Linux).'
    ],
    threatActors: ['Level 2 (Active Exploit)', 'Level 3 (Sophisticated APT)'],
    crossPlatformNuance: {
      windows: 'Write events to Windows Security Log via `System.Diagnostics.EventLog` with Event ID registration.',
      linux: 'Integrate with `auditd` subsystem which enforces immutable kernel-level logging.',
      macos: 'Write to Apple Unified Logging system via `os_log` APIs.'
    }
  },
  {
    id: 'SCN-D2',
    name: 'UI Ambiguity Inducing Accidental Indefinite Access Grants',
    componentLetter: 'D',
    componentName: 'Privilege Access Management (PAM)',
    subComponentCode: 'D5',
    subComponentName: 'User interface and social engineering risks',
    attackDescription: 'The PAM user elevation dialogue contains an ambiguous checkbox ("Keep this setting active" or "Remember my choice"). An employee intending to enable camera access for a single client presentation accidentally checks the box, believing it means "remember choice for this call". The PAM module interprets this as a permanent whitelist rule, leaving the sensor open indefinitely.',
    attackSteps: [
      'Step 1: User opens PAM dialog to grant webcam access for a 20-minute video presentation.',
      'Step 2: Dialogue presents a secondary toggle: "Remember configuration".',
      'Step 3: User checks the toggle, assuming it applies only to the current application session.',
      'Step 4: PAM module creates a persistent, unexpiring exception, permanently widening the attack surface.'
    ],
    attackVector: 'User interface dark patterns and ambiguous confirmation affordances leading to permanent permission drift.',
    affectedPhase: 'Phase 4: Privilege Access Management (PAM)',
    likelihood: 'HIGH',
    likelihoodJustification: 'UI ambiguity is one of the leading root causes of cloud and endpoint security misconfigurations.',
    impact: 'HIGH',
    impactConsequences: 'Permanent hardware sensor and network port exposure without user awareness.',
    currentMitigation: 'Configurable time dropdown menu.',
    gapsInDefense: 'Interface allows infinite/permanent grant options without requiring secondary administrative dual-approval.',
    recommendedImprovements: [
      'Strict Maximum Duration Ceiling: Impose hard maximum cap of 60 minutes for any single elevation grant.',
      'Ban Permanent Whitelist Toggles: Completely eliminate "indefinite" or "permanent" options from standard user PAM prompts.',
      'Persistent Visual Elevation Beacon: Display an always-on-top floating pill displaying active grant and remaining minutes.',
      'Application Lifecycle Binding: Automatically terminate the grant immediately when the parent application process closes.'
    ],
    threatActors: ['Level 1 (Passive)', 'Level 2 (Active Exploit)'],
    crossPlatformNuance: {
      windows: 'Display floating system tray notification beacon with quick-revoke context menu.',
      linux: 'Integrate with desktop notifications (libnotify) and Wayland status bar indicator.',
      macos: 'Integrate with macOS Menu Bar extra showing countdown timer and instant kill switch.'
    }
  },
  {
    id: 'SCN-D3',
    name: 'System Time Tampering to Artificially Extend PAM Access Windows',
    componentLetter: 'D',
    componentName: 'Privilege Access Management (PAM)',
    subComponentCode: 'D6',
    subComponentName: 'Malware tampering with timeout mechanisms',
    attackDescription: 'An attacker obtains local administrative access during an authorized 15-minute maintenance grant. To prolong access, the attacker executes `SetSystemTime` or manipulates local NTP configuration, continuously stepping the OS wall-clock backward by 10 minutes every 5 minutes. The PAM daemon, calculating expiration via wall-clock timestamps, fails to expire the grant.',
    attackSteps: [
      'Step 1: Attacker is operating within an active 15-minute temporary port elevation window.',
      'Step 2: Attacker executes script: `date -s "-10 minutes"` or Windows `SetSystemTime()`.',
      'Step 3: PAM expiration daemon checks `CurrentTime > ExpirationTime` using wall-clock time.',
      'Step 4: Because clock is repeatedly wound back, the condition is never met, extending access indefinitely.'
    ],
    attackVector: 'Clock manipulation and NTP spoofing targeting wall-clock dependent expiration algorithms.',
    affectedPhase: 'Phase 4: Privilege Access Management (PAM)',
    likelihood: 'MEDIUM',
    likelihoodJustification: 'Local administrators can alter system time unless explicitly restricted by policy.',
    impact: 'HIGH',
    impactConsequences: 'Attacker keeps sensitive network ports and peripherals open indefinitely.',
    currentMitigation: 'Expiration comparison against system clock.',
    gapsInDefense: 'Expiration logic references wall-clock (`Date.now()`, `time()`) instead of monotonic system clocks.',
    recommendedImprovements: [
      'Monotonic Clock APIs: Enforce `CLOCK_MONOTONIC_RAW` (Linux), `QueryPerformanceCounter` (Windows), and `mach_continuous_time` (macOS).',
      'Time-Jump Anomaly Detection: Detect and flag sudden negative clock adjustments, triggering instant lockdown.',
      'Cryptographic Server Timestamps: Verify expiration against authenticated remote NTP or secure attestation tokens.',
      'Hardware Tick Counter: Enforce timer execution via CPU cycle / TSC hardware counters immune to clock adjustments.'
    ],
    threatActors: ['Level 2 (Active Exploit)', 'Level 3 (Sophisticated APT)'],
    crossPlatformNuance: {
      windows: 'Use `GetTickCount64()` and configure `SeSystemtimePrivilege` restrictions.',
      linux: 'Use `clock_gettime(CLOCK_BOOTTIME, ...)` to account for time spent in sleep.',
      macos: 'Use `mach_continuous_time()` to measure absolute hardware elapsed time.'
    }
  },
  {
    id: 'SCN-D4',
    name: 'Privilege Escalation via Malformed PAM Input & Symlink Race in Grant Dispatcher',
    componentLetter: 'D',
    componentName: 'Privilege Access Management (PAM)',
    subComponentCode: 'D1',
    subComponentName: 'Temporary access grant mechanisms and approval workflow',
    attackDescription: 'The PAM module runs as a setuid root binary or Windows SYSTEM service to apply firewall changes. When a standard user submits a request, the dispatcher writes request parameters to a temporary staging file in `/tmp/pam_req.json`. An unprivileged local user replaces this file with a symlink pointing to `/etc/shadow`, causing the privileged dispatcher to overwrite critical system authentication files.',
    attackSteps: [
      'Step 1: Unprivileged user discovers PAM dispatcher creates temporary staging files in world-writable `/tmp`.',
      'Step 2: Attacker sets up inotify watcher and creates a symlink: `/tmp/pam_req.json -> /etc/shadow`.',
      'Step 3: Attacker triggers a PAM request through the CLI interface.',
      'Step 4: Privileged root daemon follows the symlink and overwrites `/etc/shadow` with attacker-controlled data.'
    ],
    attackVector: 'Insecure temporary file handling and TOCTOU symlink traversal in privileged service.',
    affectedPhase: 'Phase 4: Privilege Access Management (PAM)',
    likelihood: 'MEDIUM',
    likelihoodJustification: 'Symlink race vulnerabilities in root helper daemons are a classic and persistent privilege escalation vector.',
    impact: 'CRITICAL',
    impactConsequences: 'Full local privilege escalation to root/SYSTEM from an unprivileged user account.',
    currentMitigation: 'Input validation on port numbers.',
    gapsInDefense: 'Temporary files created in shared directories without `O_NOFOLLOW` / `O_EXCL` flags and root-only permissions.',
    recommendedImprovements: [
      'Isolated Runtime Directory: Enforce runtime paths strictly inside `/run/hardening/` or `%ProgramData%\\Hardening` with 0700 root ownership.',
      'POSIX Safe File Flags: Always use `O_CREAT | O_EXCL | O_NOFOLLOW` when creating request files.',
      'IPC over Unix Domain Sockets: Eliminate disk files; pass grant parameters via authenticated UNIX domain sockets or named pipes.',
      'Drop Privileges Early: Minimize code executing with full root/SYSTEM capabilities.'
    ],
    threatActors: ['Level 2 (Active Exploit)'],
    crossPlatformNuance: {
      windows: 'Use secure named pipes with security descriptors denying non-admin write access.',
      linux: 'Create dedicated root-owned directory `/run/surfaceguard/` with permissions 0700.',
      macos: 'Use XPC Services with code-signed client entitlements.'
    }
  },
  {
    id: 'SCN-D5',
    name: 'Interception and Manipulation of Elevation Requests via Accessibility APIs',
    componentLetter: 'D',
    componentName: 'Privilege Access Management (PAM)',
    subComponentCode: 'D3',
    subComponentName: 'Cryptographic protection of enable requests',
    attackDescription: 'Malware executing within the user desktop session monitors for the appearance of the PAM authorization dialogue. Utilizing OS accessibility APIs (UI Automation on Windows or X11 synthetic events), the malware programmatically clicks the "Approve" button and modifies the requested port number from `8000` to `445` (SMB) in the text box before the user can react.',
    attackSteps: [
      'Step 1: User legitimately triggers a PAM request for development port 8000.',
      'Step 2: Dialogue opens in standard user desktop session.',
      'Step 3: Background malware hooks `UIAutomation` / `XTest` synthetic input events.',
      'Step 4: Malware replaces target port with 445 and fires programmatic button click, executing the malicious grant.'
    ],
    attackVector: 'Synthetic UI input injection and session hijacking via Accessibility APIs.',
    affectedPhase: 'Phase 4: Privilege Access Management (PAM)',
    likelihood: 'MEDIUM',
    likelihoodJustification: 'User-session malware routinely exploits accessibility APIs to bypass interactive prompts unless displayed on a Secure Desktop.',
    impact: 'HIGH',
    impactConsequences: 'Unauthorized elevation granted without human consent, weaponizing the PAM tool against the system.',
    currentMitigation: 'Standard user confirmation modal prompt.',
    gapsInDefense: 'Dialogue rendered in standard user session window without Secure Desktop isolation or cryptographic request signing.',
    recommendedImprovements: [
      'Secure Desktop Rendering: Display elevation prompts exclusively on the Windows Secure Desktop or Wayland isolated session.',
      'Cryptographic Request Binding: Bind the elevation request to an asymmetric keypair held in hardware TPM/Secure Enclave.',
      'Physical Touch Confirmation: Require physical FIDO2 / YubiKey touch verification before hardware enable.',
      'Out-of-Band Push Notification: Require secondary approval via enterprise mobile authenticator.'
    ],
    threatActors: ['Level 2 (Active Exploit)', 'Level 3 (Sophisticated APT)'],
    crossPlatformNuance: {
      windows: 'Force elevation prompt to run under `promptOnSecureDesktop=true` (UAC credential desktop).',
      linux: 'Enforce Wayland protocol which natively blocks synthetic input injection between unprivileged clients.',
      macos: 'Leverage Touch ID / LocalAuthentication framework requiring biometric confirmation.'
    }
  },

  // ==========================================
  // COMPONENT E: CROSS-PLATFORM IMPLEMENTATION (6 Scenarios)
  // ==========================================
  {
    id: 'SCN-E1',
    name: 'Windows Registry Tampering by Administrative Malware to Revoke Hardening State',
    componentLetter: 'E',
    componentName: 'Cross-Platform Implementation',
    subComponentCode: 'E1',
    subComponentName: 'Windows Registry tampering and Group Policy override',
    attackDescription: 'On Windows, the script stores camera and microphone disable states in registry policies (`HKLM\\SOFTWARE\\Policies\\Microsoft\\Camera: AllowCamera = 0`). Malware possessing local administrator credentials directly calls `RegSetValueEx` to flip the value back to 1. The hardening script, assuming the registry is immutable, reports the system as hardened while surveillance is fully restored.',
    attackSteps: [
      'Step 1: Hardening script sets `AllowCamera = 0` in HKLM registry.',
      'Step 2: Malware executes with local admin privileges.',
      'Step 3: Malware modifies the key to `AllowCamera = 1` and disables telemetry auditing.',
      'Step 4: Host camera activates; hardening script remains unaware until manual re-audit.'
    ],
    attackVector: 'Direct registry manipulation in privileged administrative context.',
    affectedPhase: 'Phase 2: Hardware Sandboxing (Windows Specific)',
    likelihood: 'HIGH',
    likelihoodJustification: 'Administrative malware routinely alters registry keys; standard administrative accounts have write access by default.',
    impact: 'HIGH',
    impactConsequences: 'Silent restoration of surveillance capabilities while status dashboard displays false security posture.',
    currentMitigation: 'Script writes settings to HKLM policy keys.',
    gapsInDefense: 'Registry key ownership is not locked to `NT SERVICE\\TrustedInstaller` and lacks real-time modification callbacks.',
    recommendedImprovements: [
      'TrustedInstaller DACL Locking: Strip write permissions from Administrators; assign exclusive ownership to TrustedInstaller.',
      'Registry Watcher Callbacks: Deploy a persistent service listening to `RegNotifyChangeKeyValue` to instantly revert tampering.',
      'WDAC Application Control: Enforce Windows Defender Application Control to block unapproved binaries from executing RegEdit APIs.',
      'Cryptographic State Signature: Store a signed hash of the registry configuration in an encrypted file vault.'
    ],
    threatActors: ['Level 2 (Active Exploit)', 'Level 3 (Sophisticated APT)'],
    crossPlatformNuance: {
      windows: 'Directly applicable to HKLM registry security descriptors.',
      linux: 'Equivalent to modifying `/etc/modprobe.d/` blacklists.',
      macos: 'Equivalent to modifying `/Library/Preferences/` plist files.'
    }
  },
  {
    id: 'SCN-E2',
    name: 'Group Policy Background Refresh Overriding Local Security Hardening',
    componentLetter: 'E',
    componentName: 'Cross-Platform Implementation',
    subComponentCode: 'E1',
    subComponentName: 'Windows Registry tampering and Group Policy override',
    attackDescription: 'An enterprise endpoint is joined to an Active Directory domain. The hardening script applies restrictive local firewall and peripheral policies. However, the domain GPO engine automatically refreshes every 90 minutes (`gpupdate /force`). A legacy domain policy designed for remote maintenance pushes down an override, silently reopening Port 445 and resetting firewall rules to domain defaults.',
    attackSteps: [
      'Step 1: Local script hardens endpoint, closes Port 445, blocks incoming NetBIOS.',
      'Step 2: Endpoint background Group Policy Engine triggers periodic 90-minute refresh cycle.',
      'Step 3: Domain Controller pushes legacy domain firewall profile.',
      'Step 4: Local rules are overwritten by domain GPO precedence; attack surface expands without administrator notice.'
    ],
    attackVector: 'Enterprise directory service policy precedence clashing with local endpoint script configuration.',
    affectedPhase: 'Phase 1 & Phase 2 (Enterprise Windows Specific)',
    likelihood: 'HIGH',
    likelihoodJustification: 'Domain-joined Windows machines refresh Group Policy automatically every 90 minutes (+/- 30 min random offset).',
    impact: 'HIGH',
    impactConsequences: 'Automated erosion of endpoint hardening posture through authoritative domain overrides.',
    currentMitigation: 'Local script execution.',
    gapsInDefense: 'Script operates at local policy level without integrating into Active Directory Central GPO templates (.admx).',
    recommendedImprovements: [
      'WFP Callout Sub-Layer Precedence: Implement firewall rules in a custom Windows Filtering Platform sub-layer prioritized above GPO.',
      'GPO Integrity Watcher: Detect when `gpupdate` completes and immediately re-assert local attack surface reductions.',
      'Enterprise ADMX Template: Provide central Active Directory Group Policy Administrative Templates alongside local scripts.',
      'Local Policy Enforcement Service: Continuous background enforcement service that overrides standard GPO inheritance.'
    ],
    threatActors: ['Level 1 (Passive)', 'Level 2 (Active Exploit)'],
    crossPlatformNuance: {
      windows: 'Active Directory GPO precedence (`LSDOU` hierarchy).',
      linux: 'Ansible / Puppet / SaltStack configuration management drift.',
      macos: 'Mobile Device Management (MDM) profile push updates.'
    }
  },
  {
    id: 'SCN-E3',
    name: 'Linux Firewall Volatility Across Reboots Due to Missing Systemd Persistence Units',
    componentLetter: 'E',
    componentName: 'Cross-Platform Implementation',
    subComponentCode: 'E2',
    subComponentName: 'Linux iptables persistence and SELinux/AppArmor integration',
    attackDescription: 'On Linux, the hardening script applies packet filter drop rules using the `iptables` CLI tool. The system administrator reboots the server for a kernel update. Because raw `iptables` rules reside in volatile kernel memory and the script failed to configure `iptables-persistent` or a `systemd` early-boot unit, the host boots up with a permissive default ACCEPT policy, leaving all sockets exposed.',
    attackSteps: [
      'Step 1: Script applies firewall rules via in-memory `iptables -A INPUT ...` commands.',
      'Step 2: Server undergoes planned reboot or crash recovery.',
      'Step 3: Network interfaces initialize and obtain DHCP IP addresses.',
      'Step 4: Because rules were never saved to `/etc/iptables/rules.v4`, firewall defaults to ACCEPT ALL on all ports.'
    ],
    attackVector: 'Reboot persistence failure in volatile memory-based packet filter architectures.',
    affectedPhase: 'Phase 1: Network Attack Surface Reduction (Linux Specific)',
    likelihood: 'HIGH',
    likelihoodJustification: 'A standard Linux reboot clears raw iptables rules unless explicitly saved and restored by a persistent service unit.',
    impact: 'CRITICAL',
    impactConsequences: 'Complete restoration of exposed attack surface on every reboot before hardening script can be manually re-run.',
    currentMitigation: 'Script executes iptables commands.',
    gapsInDefense: 'Failure to install and configure persistent firewall managers (`ufw`, `firewalld`, or `nftables.service`).',
    recommendedImprovements: [
      'Atomic nftables Unit: Deploy declarative `/etc/nftables.conf` managed directly by `nftables.service`.',
      'Systemd network-pre.target Hook: Order firewall restoration strictly before `network-pre.target` so interfaces initialize blocked.',
      'Reboot Integrity Assertion: Deploy a post-boot health checker verifying rule existence within 5 seconds of startup.',
      'Immutable Ruleset Backup: Store persistent copies in `/etc/iptables/rules.v4` with file permissions 0600.'
    ],
    threatActors: ['Level 1 (Passive)', 'Level 2 (Active Exploit)'],
    crossPlatformNuance: {
      windows: 'Windows Defender Firewall rules are persistent in the registry by default.',
      linux: 'Must explicitly manage persistence across Ubuntu (ufw), Debian (nftables), and RHEL (firewalld).',
      macos: 'pfctl rules must be configured in `/etc/pf.conf` and enabled via launchd plist.'
    }
  },
  {
    id: 'SCN-E4',
    name: 'Unconfined Daemon Exploitation of DAC vs MAC Disconnect (SELinux/AppArmor)',
    componentLetter: 'E',
    componentName: 'Cross-Platform Implementation',
    subComponentCode: 'E2',
    subComponentName: 'Linux iptables persistence and SELinux/AppArmor integration',
    attackDescription: 'The hardening script tightens Linux file permissions via discretionary access control (`chmod 0700` and `chown root:root`). However, it ignores Mandatory Access Control (MAC). A compromised container daemon or third-party service running in the `unconfined_t` SELinux domain exploits local file capabilities to bypass directory hardening and access raw peripheral device nodes.',
    attackSteps: [
      'Step 1: Script restricts permissions on files and device nodes via standard DAC chmod.',
      'Step 2: Malware compromises daemon operating under permissive/unconfined AppArmor profile.',
      'Step 3: Daemon utilizes POSIX capabilities (`CAP_DAC_OVERRIDE`) granted to its security context.',
      'Step 4: DAC permissions are overridden by kernel capability, granting full read access to hardened files.'
    ],
    attackVector: 'Discretionary Access Control (DAC) bypass via unconfined Mandatory Access Control (MAC) domains.',
    affectedPhase: 'Phase 3: File System Hardening (Linux Specific)',
    likelihood: 'MEDIUM',
    likelihoodJustification: 'Many Linux systems operate in SELinux Permissive mode or with generic unconfined AppArmor profiles.',
    impact: 'HIGH',
    impactConsequences: 'Filesystem and hardware hardening bypassed by any process holding elevated kernel capabilities.',
    currentMitigation: 'Standard chmod/chown execution.',
    gapsInDefense: 'Script fails to audit, generate, or enforce AppArmor / SELinux MAC policy profiles.',
    recommendedImprovements: [
      'AppArmor Profile Generation: Ship explicit AppArmor profiles confining peripheral access (`deny /dev/video* rw`).',
      'Enforce SELinux Enforcing Mode: Validate that `getenforce` returns `Enforcing` and generate targeted type enforcement modules.',
      'POSIX Capability Stripping: Drop `CAP_DAC_OVERRIDE` and `CAP_SYS_ADMIN` from systemd service units.',
      'Audit MAC Transitions: Log all denied MAC operations via `auditd` to detect capability abuse.'
    ],
    threatActors: ['Level 2 (Active Exploit)', 'Level 3 (Sophisticated APT)'],
    crossPlatformNuance: {
      windows: 'Equivalent to AppLocker / WDAC policy bypassing standard NTFS permissions.',
      linux: 'Requires coordinated DAC + MAC (SELinux / AppArmor) enforcement.',
      macos: 'Enforced by System Integrity Protection (SIP) and Apple Sandbox.'
    }
  },
  {
    id: 'SCN-E5',
    name: 'macOS Cached TCC Rights Exploitation via Pre-Notarized Developer Binaries',
    componentLetter: 'E',
    componentName: 'Cross-Platform Implementation',
    subComponentCode: 'E3',
    subComponentName: 'macOS notarization bypass and sandbox containment',
    attackDescription: 'On macOS, the hardening script executes `tccutil reset Camera` to revoke permissions. However, Transparency, Consent, and Control (TCC) records permissions per bundle identifier and code-signing identity. An attacker drops a malicious plugin into the directory of a pre-approved, notarized developer tool that already holds valid camera entitlements, hijacking the cached permission without triggering a TCC prompt.',
    attackSteps: [
      'Step 1: Script resets TCC camera database for generic applications.',
      'Step 2: Attacker identifies an existing installed developer tool (e.g. Electron IDE, test runner) with camera rights.',
      'Step 3: Attacker injects code via dylib hijacking or plugin directory loading into the approved app bundle.',
      'Step 4: Process launches under the approved code-signing identity and accesses camera with zero OS prompts.'
    ],
    attackVector: 'Dylib hijacking and code injection into pre-authorized, notarized application bundles.',
    affectedPhase: 'Phase 2: Hardware Sandboxing (macOS Specific)',
    likelihood: 'MEDIUM',
    likelihoodJustification: 'dylib hijacking of third-party notarized applications is a well-documented macOS persistence and privilege escalation technique.',
    impact: 'HIGH',
    impactConsequences: 'Stealthy camera and microphone surveillance on macOS without user consent or TCC warnings.',
    currentMitigation: 'Execution of `tccutil reset` command.',
    gapsInDefense: 'tccutil reset only affects user domains and cannot prevent dylib hijacking of existing signed binaries with cached entitlements.',
    recommendedImprovements: [
      'MDM Configuration Profiles: Deploy localized MDM profile locking Camera and Microphone payloads at system level.',
      'Hardened Runtime Validation: Verify that all installed apps with camera entitlements enforce Apple Hardened Runtime with library validation.',
      'Endpoint Security Framework (ESF): Monitor for `ES_EVENT_TYPE_NOTIFY_EXEC` matching camera entitlements.',
      'Audit TCC Database Directly: Inspect `/Library/Application Support/com.apple.TCC/TCC.db` for rogue bundle authorizations.'
    ],
    threatActors: ['Level 2 (Active Exploit)', 'Level 3 (Sophisticated APT)'],
    crossPlatformNuance: {
      windows: 'CapabilityAccessManager consent store manipulation.',
      linux: 'PipeWire portal authorization hijacking.',
      macos: 'TCC.db protected by System Integrity Protection (SIP).'
    }
  },
  {
    id: 'SCN-E6',
    name: 'Platform Detection Spoofing Inducing Silent Cross-Platform Enforcement Failure',
    componentLetter: 'E',
    componentName: 'Cross-Platform Implementation',
    subComponentCode: 'E5',
    subComponentName: 'Platform detection and verification',
    attackDescription: 'The cross-platform script relies on environment variables (`OSTYPE`, `OS`, `uname -s`) to branch between Windows, Linux, and macOS execution routines. A resident attacker or container environment spoofs `OSTYPE="darwin"` on a Linux server. The script executes macOS commands (`pfctl`, `tccutil`), which fail silently or are skipped, leaving the host attack surface completely unhardened.',
    attackSteps: [
      'Step 1: Attacker modifies user environment or launches script inside subshell: `export OSTYPE=darwin`.',
      'Step 2: Script detects OS using naive check: `if [[ "$OSTYPE" == "darwin"* ]]`.',
      'Step 3: Script branches to macOS hardening module on a Linux host.',
      'Step 4: macOS commands fail with "command not found"; script terminates successfully with zero Linux hardening applied.'
    ],
    attackVector: 'Environment variable spoofing and execution branch subversion.',
    affectedPhase: 'All Phases (Cross-Platform Orchestration)',
    likelihood: 'HIGH',
    likelihoodJustification: 'Environment variables are mutable, untrusted inputs easily altered by child processes.',
    impact: 'CRITICAL',
    impactConsequences: 'Complete silent failure of the hardening script, presenting a false illusion of security.',
    currentMitigation: 'Standard environment variable or uname checks.',
    gapsInDefense: 'Script trusts mutable environment variables without performing cryptographic kernel verification.',
    recommendedImprovements: [
      'Multi-Source Kernel Attestation: Verify OS via immutable kernel files (`/proc/version`, `/System/Library/CoreServices/SystemVersion.plist`, `Kernel32.dll`).',
      'Direct Syscall Verification: Use native POSIX `uname()` syscalls rather than mutable shell variables.',
      'Fail-Closed Error Handling: If any platform-specific command fails with "command not found", immediately abort with non-zero exit code.',
      'Clean Environment Sanitization: Sanitize and reset `PATH` and all environment variables at the root entry point.'
    ],
    threatActors: ['Level 2 (Active Exploit)'],
    crossPlatformNuance: {
      windows: 'Verify via `[System.Environment]::OSVersion.Platform` and WMI `Win32_OperatingSystem`.',
      linux: 'Verify `/etc/os-release` and kernel proc filesystem.',
      macos: 'Verify via `/usr/bin/sw_vers` and `sysctl kern.ostype`.'
    }
  }
];

export const INITIAL_OBSERVATIONS = {
  mostCriticalVulnerability: {
    title: 'Audit-to-Enforcement TOCTOU Socket Injection (SCN-A1) & Reboot Volatility (SCN-E3)',
    explanation: 'Sequential non-atomic operations permit userland malware to slip between audit and firewall application within 150ms. Additionally, in-memory firewall rules that fail to survive reboots create a recurrent zero-protection vulnerability window.'
  },
  mostLikelyAttackVector: {
    title: 'Socially Engineered Port Elevation (SCN-A5) & Ambient Video Interception (SCN-B2)',
    explanation: 'Human users are easily deceived by fake system update prompts into authorizing high-risk ports (SMB 445). Concurrently, once peripherals are legitimately opened for meetings, any background spyware can tap into the enabled video/audio device nodes.'
  },
  largestGapInDefense: {
    title: 'Lack of Atomic Multi-Phase Transactions & Pre-Flight Dependency Graphs',
    explanation: 'Hardening executes in serial userspace steps without entering an isolated maintenance transaction state, and aggressive filesystem permissions risk breaking core OS update and service accounts without dry-run validation.'
  },
  crossPlatformInconsistencyRisks: {
    title: 'Divergent OS Security Models (Registry vs nftables vs TCC)',
    explanation: 'Abstracting disparate OS mechanisms creates false uniformity assumptions: Windows relies on registry policies prone to GPO overrides; Linux relies on packet filter persistence; macOS relies on SIP-protected TCC databases susceptible to dylib hijacking.'
  },
  pamModuleVulnerabilities: {
    title: 'Wall-Clock Dependent Expirations & Plaintext Local Logging',
    explanation: 'Relying on mutable system time allows attackers to step clocks backward and prolong grants, while storing audit logs in standard local files allows privileged attackers to destroy forensic trails.'
  }
};
