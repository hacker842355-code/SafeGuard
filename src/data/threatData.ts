import { ThreatItem, PlatformThreat, ZeroTrustPrinciple } from '../types/security';

export const THREAT_ITEMS: ThreatItem[] = [
  // COMPONENT A: NETWORK PORT MANAGEMENT
  {
    id: 'A1',
    code: 'FIN-001',
    title: 'Port Enumeration Race Condition',
    component: 'network',
    componentName: 'Network Port Management',
    osScope: ['windows', 'linux', 'macos'],
    description: 'Malware creates and launches a listening network service during the audit phase, right before firewall rules are compiled and committed.',
    attackVector: 'Time-of-Check to Time-of-Use (TOCTOU) race condition during non-atomic network enumeration and rule application.',
    impactLevel: 3,
    likelihoodLevel: 3,
    riskScore: 9,
    severity: 'HIGH',
    currentMitigation: 'Script applies firewall rules sequentially immediately following the audit iteration.',
    gapAnalysis: 'An indeterminate time delta (50ms–2000ms) exists between port enumeration and netfilter/packet-filter commitment.',
    improvedDefense: [
      'Atomic transactional execution (audit + firewall commit in a single kernel snapshot lock)',
      'Process table lock and socket creation monitor during enumeration window',
      'Post-application validation pass: re-audit socket table immediately and terminate anomalies',
      'Kernel eBPF / ETW network socket creation hook to intercept unauthorized bindings during lockdown'
    ],
    remediationTimeline: '30-60 days',
    remediationEffort: '2-3 weeks engineering',
    owner: 'Core Architecture & Network Team',
    phase: 1
  },
  {
    id: 'A2',
    code: 'FIN-002',
    title: 'Firewall Rule Bypass via Proxy / Legitimate Tunneling',
    component: 'network',
    componentName: 'Network Port Management',
    osScope: ['windows', 'linux', 'macos'],
    description: 'Aggressive script closes port 443 or VPN ports; user is compelled to manually reopen it or attackers route egress through allowed standard tunnels.',
    attackVector: 'Port reuse and user-prompted manual unblocking without service identity verification.',
    impactLevel: 3,
    likelihoodLevel: 2,
    riskScore: 6,
    severity: 'MEDIUM',
    currentMitigation: 'User-controlled PAM module permits temporary unblocking on request.',
    gapAnalysis: 'No automated cryptographic verification of the binary binding to the unblocked port; user lacks protocol insight.',
    improvedDefense: [
      'Cryptographic binary whitelisting (only allow verified executable signatures on specific ports)',
      'Port-level scoped firewall binding (restrict listening interfaces to localhost or approved subnet)',
      'Inline user risk warning showing active process PID, hash, and TLS certificate details',
      'Dynamic layer-7 protocol inspection to detect protocol masquerading'
    ],
    remediationTimeline: '60-90 days',
    remediationEffort: '3 weeks engineering',
    owner: 'Network Security Engineering',
    phase: 1
  },
  {
    id: 'A3',
    code: 'FIN-003',
    title: 'Cross-Platform Abstraction Layer Vulnerabilities',
    component: 'network',
    componentName: 'Network Port Management',
    osScope: ['windows', 'linux', 'macos'],
    description: 'Abstraction wrapper translates high-level port closures into iptables, netsh/PowerShell, or pfctl. Unsanitized parameter inputs permit command injection.',
    attackVector: 'Shell injection or parameter tampering in string-concatenated firewall CLI invocation across heterogeneous operating systems.',
    impactLevel: 4,
    likelihoodLevel: 2,
    riskScore: 8,
    severity: 'HIGH',
    currentMitigation: 'Basic API abstraction layer wrapping platform-native firewall calls.',
    gapAnalysis: 'Commands executed through child_process shell wrappers with string interpolation rather than direct native syscalls/APIs.',
    improvedDefense: [
      'Direct OS native APIs (Windows Filtering Platform / WFP API, Linux Netlink socket API, macOS NetworkExtension)',
      'Strict typed input validation schema denying any non-numeric port ranges or metacharacters',
      'Parameterized execution arrays with zero subshell delegation (execFile without sh/cmd)',
      'Continuous automated fuzz testing across Windows, Ubuntu, and macOS runners'
    ],
    remediationTimeline: '30-90 days',
    remediationEffort: '4 weeks engineering',
    owner: 'Cross-Platform Systems Engineering',
    phase: 1
  },
  {
    id: 'A4',
    code: 'FIN-004',
    title: 'Legitimate Service Interruption on High Debug Ports',
    component: 'network',
    componentName: 'Network Port Management',
    osScope: ['windows', 'linux', 'macos'],
    description: 'Script closes dynamic ephemeral or developer debugging ports (e.g. 8000, 9229, 3000, 5173), breaking legitimate development workflows.',
    attackVector: 'Developer frustrates and disables hardening script entirely or creates permanent wildcards (`0.0.0.0/0 allow`).',
    impactLevel: 2,
    likelihoodLevel: 3,
    riskScore: 6,
    severity: 'MEDIUM',
    currentMitigation: 'Manual port re-enable option through interactive prompts.',
    gapAnalysis: 'No automated awareness of developer environments or heuristic identification of IDE debug hooks.',
    improvedDefense: [
      'Pre-execution environment profiling (detect IDEs, language runtimes, Docker daemon, node processes)',
      'Localhost-only boundary enforcement (allow 127.0.0.1 bindings on dev ports while blocking external 0.0.0.0 interfaces)',
      'Dry-run simulation mode highlighting planned port closures with 1-click developer whitelist flags',
      'Role-based hardening profiles (Production Server vs Developer Workstation)'
    ],
    remediationTimeline: '60-90 days',
    remediationEffort: '1-2 weeks engineering',
    owner: 'DevOps & Architecture Team',
    phase: 1
  },

  // COMPONENT B: HARDWARE SANDBOXING
  {
    id: 'B1',
    code: 'FIN-005',
    title: 'Firmware-Level Camera / Microphone Disable Bypass',
    component: 'hardware',
    componentName: 'Hardware Sandboxing (Peripherals)',
    osScope: ['windows', 'linux', 'macos'],
    description: 'Hardware peripheral or embedded microcontroller possesses independent firmware vulnerabilities or rogue DMA that circumvents OS driver disablement.',
    attackVector: 'Peripheral DMA exploitation, rogue USB firmware implant, or BIOS-level persistence bypassing host OS device trees.',
    impactLevel: 4,
    likelihoodLevel: 1,
    riskScore: 4,
    severity: 'MEDIUM',
    currentMitigation: 'OS-level driver disablement via Device Manager APIs and udev rules.',
    gapAnalysis: 'OS disablement only instructs the software stack; the physical hardware remains powered and susceptible to bus-level manipulation.',
    improvedDefense: [
      'Hardware bus power cutoff via ACPI D3cold state where hardware supported',
      'IOMMU / VT-d DMA protection tables enforced at boot time',
      'USB device authorization policies (USBGuard on Linux, DeviceGuard on Windows)',
      'Cryptographic firmware attestation and hardware whitelist'
    ],
    remediationTimeline: '90-180 days',
    remediationEffort: '4 weeks firmware research',
    owner: 'Hardware Security Research Team',
    phase: 2
  },
  {
    id: 'B2',
    code: 'FIN-006',
    title: 'Malware Interception of Hardware Enable Prompts',
    component: 'hardware',
    componentName: 'Hardware Sandboxing (Peripherals)',
    osScope: ['windows', 'linux', 'macos'],
    description: 'Malware running in user session intercepts the PAM permission request and piggybacks audio/camera capture or expands the time window indefinitely.',
    attackVector: 'UI clickjacking, session injection, or Windows Accessibility / X11 synthetic input manipulation.',
    impactLevel: 3,
    likelihoodLevel: 2,
    riskScore: 6,
    severity: 'MEDIUM',
    currentMitigation: 'PAM authentication dialog prompts user before enabling hardware.',
    gapAnalysis: 'Lack of secure desktop isolation (such as Windows Secure Desktop UAC / Wayland isolated layer).',
    improvedDefense: [
      'Enforce hardware grant prompts strictly on an isolated Secure Desktop (elevation ring 0 context)',
      'Immutable cryptographic token generation tied to specific calling parent process PID and hash',
      'Hardware token / FIDO2 physical touch confirmation requirement for camera re-engagement',
      'Independent audit logging of every elevation event sent to a protected immutable journal'
    ],
    remediationTimeline: '60-90 days',
    remediationEffort: '3 weeks engineering',
    owner: 'Endpoint Platform Security',
    phase: 2
  },
  {
    id: 'B3',
    code: 'FIN-007',
    title: 'Audio API Query & Audio-Jack Side-Channel Bypass',
    component: 'hardware',
    componentName: 'Hardware Sandboxing (Peripherals)',
    osScope: ['windows', 'linux', 'macos'],
    description: 'Script disables default capture driver, but secondary virtual audio devices, loopback interfaces, or raw Wasapi/CoreAudio endpoints remain readable.',
    attackVector: 'Secondary audio interface query, virtual loopback driver monitoring, or line-in jack impedance eavesdropping.',
    impactLevel: 3,
    likelihoodLevel: 2,
    riskScore: 6,
    severity: 'MEDIUM',
    currentMitigation: 'OS driver disable on standard built-in microphone device nodes.',
    gapAnalysis: 'Disables one specific hardware driver ID while leaving audio daemon services (PulseAudio/PipeWire/Windows Audio) active.',
    improvedDefense: [
      'Mute and isolate the entire OS Audio Subsystem pipeline when in locked state',
      'Block audio device queries in registry/TCC permission databases for all untrusted binaries',
      'Disable stereo mix, loopback interfaces, and virtual audio cables simultaneously',
      'Real-time watchdog scanning for newly mounted USB audio or Bluetooth endpoints'
    ],
    remediationTimeline: '60-90 days',
    remediationEffort: '2 weeks engineering',
    owner: 'Endpoint Platform Security',
    phase: 2
  },
  {
    id: 'B4',
    code: 'FIN-008',
    title: 'Temporary Hardware Window Timeout Scheduling Failure',
    component: 'hardware',
    componentName: 'Hardware Sandboxing (Peripherals)',
    osScope: ['windows', 'linux', 'macos'],
    description: 'User enables camera for a 30-minute conference. If the PC goes to sleep, hibernates, or the userland timer process crashes, the camera remains permanently active.',
    attackVector: 'System power transitions (ACPI S3 sleep/resume), thread starvation, or kill signal to userspace timer daemon.',
    impactLevel: 3,
    likelihoodLevel: 2,
    riskScore: 6,
    severity: 'MEDIUM',
    currentMitigation: 'Userspace countdown timer invokes disable command at zero.',
    gapAnalysis: 'Userspace timer state is volatile and loses synchronization during suspend/hibernate states.',
    improvedDefense: [
      'OS-level kernel scheduled task / systemd timer backed by RTC monotonic hardware clock',
      'Power event listener (ACPI resume hook): immediate re-assertion of lockdown state upon wake',
      'Independent watchdog daemon that forces device disablement if heartbeats expire',
      'Clear high-visibility screen banner displaying active countdown with instant 1-click kill switch'
    ],
    remediationTimeline: '30-60 days',
    remediationEffort: '2 weeks engineering',
    owner: 'Systems Architecture Team',
    phase: 2
  },

  // COMPONENT C: FILE SYSTEM HARDENING
  {
    id: 'C1',
    code: 'FIN-009',
    title: 'Aggressive Permission Hardening Breaks Critical OS Services',
    component: 'filesystem',
    componentName: 'File System Hardening',
    osScope: ['windows', 'linux', 'macos'],
    description: 'Script tightens permissions on ProgramData or /tmp too aggressively, preventing Windows Update, NetworkService, or log daemons from writing.',
    attackVector: 'Denial of Service of core OS patching mechanisms, leading to unpatched vulnerability exploitation.',
    impactLevel: 3,
    likelihoodLevel: 3,
    riskScore: 9,
    severity: 'HIGH',
    currentMitigation: 'User-controlled audit and restriction mode.',
    gapAnalysis: 'Lack of automated service account dependency graph analysis before applying restrictive ACLs.',
    improvedDefense: [
      'Comprehensive Service Account Whitelisting (NT SERVICE\\*, LocalSystem, NetworkService, syslog, systemd)',
      'Mandatory Dry-Run simulation with system impact report prior to ACL commitment',
      'Automated rollback transaction: automated health check of OS patch services within 120s of change',
      'Gradual phased hardening: audit mode -> warning telemetry -> enforced lockdown'
    ],
    remediationTimeline: '30-60 days',
    remediationEffort: '3 weeks engineering',
    owner: 'Core Systems & Reliability Team',
    phase: 3
  },
  {
    id: 'C2',
    code: 'FIN-010',
    title: 'Malware Execution Window During Sequential Phasing',
    component: 'filesystem',
    componentName: 'File System Hardening',
    osScope: ['windows', 'linux', 'macos'],
    description: 'Hardening executes sequentially (network -> hardware -> filesystem -> PAM). Malware executes during phase transitions to achieve persistence.',
    attackVector: 'Execution race condition between initialization phases.',
    impactLevel: 3,
    likelihoodLevel: 2,
    riskScore: 6,
    severity: 'MEDIUM',
    currentMitigation: 'Sequential phased execution pipeline.',
    gapAnalysis: 'Phases execute in serial userspace steps without entering an isolated maintenance execution state.',
    improvedDefense: [
      'Atomic execution wrapper: compile all policies into a single immutable configuration block',
      'Safe-mode or early boot execution (execute as early boot filter driver or systemd EarlyBoot target)',
      'Temporary process suspension or execution restriction during script execution',
      'Pre-hardening integrity check ensuring no active suspicious processes in memory'
    ],
    remediationTimeline: '60-90 days',
    remediationEffort: '3-4 weeks engineering',
    owner: 'Core Architecture Team',
    phase: 3
  },
  {
    id: 'C3',
    code: 'FIN-011',
    title: 'Attacker Exploits Hardening Verification Heuristics',
    component: 'filesystem',
    componentName: 'File System Hardening',
    osScope: ['windows', 'linux', 'macos'],
    description: 'Attacker analyzes the script logic, creating files with identical permission bits or hidden alternate data streams (ADS) that spoof "hardened" states.',
    attackVector: 'Heuristic gaming, NTFS Alternate Data Streams (ADS), or symlink race attacks to bypass auditing checks.',
    impactLevel: 2,
    likelihoodLevel: 2,
    riskScore: 4,
    severity: 'MEDIUM',
    currentMitigation: 'Periodic directory permission and ownership audit.',
    gapAnalysis: 'Auditor inspects surface ACL flags but does not compute cryptographic file hashes or verify extended attributes.',
    improvedDefense: [
      'Cryptographic baseline hashes of all verified system directories and binaries',
      'Detection and stripping of NTFS Alternate Data Streams and rogue POSIX ACLs',
      'Randomized non-deterministic audit intervals to prevent scheduled timing bypasses',
      'Immutable filesystem flag enforcement (`chattr +i` on Linux, SIP / FileVault on macOS)'
    ],
    remediationTimeline: '90-180 days',
    remediationEffort: '2 weeks engineering',
    owner: 'Security Audit & Compliance Team',
    phase: 3
  },

  // COMPONENT P: PRIVILEGE ACCESS MANAGEMENT (PAM)
  {
    id: 'P1',
    code: 'FIN-012',
    title: 'Lack of Tamper-Evident Audit Trail for Temporary Grants',
    component: 'pam',
    componentName: 'Privilege Access Management (PAM)',
    osScope: ['windows', 'linux', 'macos'],
    description: 'Ports or hardware are temporarily enabled, but logs are stored locally in plaintext where an attacker with elevated access can erase their activity.',
    attackVector: 'Log wiping, audit tampering, and repudiation of unauthorized access grants.',
    impactLevel: 2,
    likelihoodLevel: 1,
    riskScore: 2,
    severity: 'LOW',
    currentMitigation: 'Local event logging of PAM requests in standard console or text log.',
    gapAnalysis: 'Local log files lack forward-secure cryptographic signatures and out-of-band replication.',
    improvedDefense: [
      'Cryptographically signed, append-only hash-chained journal for every PAM grant',
      'Dual logging to Windows Event Log (Security Log) / Linux auditd daemon',
      'Optional remote syslog / webhook forwarding to SIEM with zero local truncation capability',
      'Detailed metadata collection: user identity, requesting parent PID, executable hash, duration, justification'
    ],
    remediationTimeline: 'Ongoing / 90 days',
    remediationEffort: '1-2 weeks engineering',
    owner: 'Security Operations & Governance',
    phase: 4
  },
  {
    id: 'P2',
    code: 'FIN-013',
    title: 'Social Engineering of Users into Opening High-Risk Ports (SMB/RDP)',
    component: 'pam',
    componentName: 'Privilege Access Management (PAM)',
    osScope: ['windows', 'linux', 'macos'],
    description: 'Malware or phishing script generates a deceptive modal requesting user to open Port 445 (SMB) or Port 3389 (RDP) disguised as "System Update Service".',
    attackVector: 'User social engineering, credential harvesting, or deceptive prompt execution.',
    impactLevel: 3,
    likelihoodLevel: 3,
    riskScore: 9,
    severity: 'HIGH',
    currentMitigation: 'User confirmation prompt required before opening port.',
    gapAnalysis: 'Standard confirmation prompt lacks explicit threat context, severity badges, and blocked-list vetoes.',
    improvedDefense: [
      'Hardcoded "Blacklist Ports" (445 SMB, 135-139 NetBIOS, 3389 RDP) requiring administrative dual-key approval',
      'High-contrast visual risk warnings displaying known exploit mechanisms associated with the requested port',
      'Mandatory friction step: require user to manually type the specific danger reason and port number',
      'Default deny with automated timeout of prompt (prompt self-terminates after 20 seconds of inaction)'
    ],
    remediationTimeline: '30-60 days',
    remediationEffort: '2 weeks engineering',
    owner: 'Product Security & UX Architecture',
    phase: 4
  },
  {
    id: 'P3',
    code: 'FIN-014',
    title: 'Accidental Permanent Grant Due to Ambiguous PAM Interface',
    component: 'pam',
    componentName: 'Privilege Access Management (PAM)',
    osScope: ['windows', 'linux', 'macos'],
    description: 'User intended to enable camera or port for a single meeting or debug run, but accidentally selected a "Remember this setting" or indefinite toggle.',
    attackVector: 'Configuration drift, human error, and permanent enlargement of attack surface.',
    impactLevel: 3,
    likelihoodLevel: 2,
    riskScore: 6,
    severity: 'MEDIUM',
    currentMitigation: 'Configurable time duration dropdown.',
    gapAnalysis: 'UI lacks prominent continuous indicator showing active elevation state and automatic failsafe revert.',
    improvedDefense: [
      'Strict maximum time ceiling (hard cap at 60 minutes for any single temporary grant)',
      'Persistent system tray / floating status beacon showing active grant countdown in real time',
      'One-click instant "Revoke All & Lock Down" panic button available from tray and keyboard shortcut',
      'Automatic closure when the associated calling application process exits'
    ],
    remediationTimeline: '60-90 days',
    remediationEffort: '1-2 weeks engineering',
    owner: 'Product Security & UX Architecture',
    phase: 4
  },
  {
    id: 'P4',
    code: 'FIN-015',
    title: 'Malware Manipulation of System Time and Watchdog Timers',
    component: 'pam',
    componentName: 'Privilege Access Management (PAM)',
    osScope: ['windows', 'linux', 'macos'],
    description: 'Malware with administrator rights alters the OS system clock backward to prolong an active PAM temporary access window.',
    attackVector: 'Time tampering via `SetSystemTime`, NTP spoofing, or virtualization clock throttling.',
    impactLevel: 3,
    likelihoodLevel: 2,
    riskScore: 6,
    severity: 'MEDIUM',
    currentMitigation: 'Timer calculates expiration based on OS system clock.',
    gapAnalysis: 'Vulnerable to wall-clock manipulation and lacks monotonic clock enforcement.',
    improvedDefense: [
      'Enforce monotonic clock APIs (`CLOCK_MONOTONIC_RAW` on Linux, `QueryPerformanceCounter` on Windows, `mach_continuous_time` on macOS)',
      'Secure NTP attestation and alert on clock skews exceeding 15 seconds',
      'Secondary independent watchdog daemon enforcing maximum elapsed tick count',
      'Immediate lockdown if system time jump is detected'
    ],
    remediationTimeline: '60-90 days',
    remediationEffort: '2 weeks engineering',
    owner: 'Platform Security Engineering',
    phase: 4
  }
];

export const PLATFORM_THREATS: PlatformThreat[] = [
  {
    id: 'W1',
    platform: 'windows',
    platformName: 'Microsoft Windows (10/11 & Server)',
    title: 'Registry Tampering by Malware',
    description: 'Camera, microphone, and firewall states stored in registry keys are manipulated by malware possessing local administrator or SYSTEM privileges.',
    vector: 'RegEdit or PowerShell registry write to `HKLM\\SOFTWARE\\Policies\\Microsoft\\Camera` to disable restrictions.',
    attackScenario: 'Malware modifies registry values to re-enable camera without firing the hardening script audit cycle.',
    mitigations: [
      'Lock registry keys using kernel-level ACLs restricting modification even to Administrators (TrustedInstaller ownership)',
      'Watchdog service monitors registry key change notifications using `RegNotifyChangeKeyValue`',
      'Cryptographic state signing: script verifies hash of registry configuration every 60 seconds',
      'Deploy Windows Defender Application Control (WDAC) to prevent unauthorized registry modification'
    ],
    nativeApi: 'Advapi32.dll / Win32 Registry API, Windows Filtering Platform (WFP), PowerShell NetSecurity cmdlets',
    fallbackRisk: 'Registry changes can silently persist without system restart, deceiving status monitors.'
  },
  {
    id: 'W2',
    platform: 'windows',
    platformName: 'Microsoft Windows (10/11 & Server)',
    title: 'Group Policy (GPO) Override and Precedence Clashes',
    description: 'Script applies local policy hardening, but Domain Group Policy (GPO) refreshes every 90 minutes and resets firewall or camera permissions.',
    vector: 'Automated GPO background refresh (`gpupdate /force`) re-opening legacy ports for domain compatibility.',
    attackScenario: 'A domain-wide legacy GPO unintentionally invalidates endpoint attack surface reduction, opening SMB/RPC ports.',
    mitigations: [
      'Implement WFP filter callouts at sub-layer precedence higher than Group Policy standard rules',
      'Local policy integrity monitoring: trigger immediate alert when GPO overrides security posture',
      'Provide Active Directory administrative GPO template (.admx/.adml) alongside script',
      'Secondary enforcement service continuously re-asserts local attack surface reduction'
    ],
    nativeApi: 'Group Policy Management API, `gpresult.exe`, SecEdit.exe',
    fallbackRisk: 'High corporate friction if local endpoint script contradicts central sysadmin domain policies.'
  },
  {
    id: 'L1',
    platform: 'linux',
    platformName: 'Linux (Ubuntu, Debian, RHEL, Fedora)',
    title: 'iptables / nftables Volatility Across System Reboots',
    description: 'Firewall rules committed in memory using raw `iptables` commands do not survive system reboots unless saved to persistent unit files.',
    vector: 'System reboot or network-manager restart drops in-memory firewall rules, leaving all listening sockets exposed.',
    attackScenario: 'Adversary reboots host or crashes networking; machine boots up with default ACCEPT policy before daemon starts.',
    mitigations: [
      'Integrate directly with persistent managers: `ufw`, `firewalld`, or `iptables-persistent`',
      'Deploy a systemd drop-in unit (`/etc/systemd/system/hardening-firewall.service`) linked to `network-pre.target`',
      'Set kernel default policies to DROP immediately before interfaces come up',
      'Post-boot self-check script verifying active firewall rule hash within 5 seconds of boot'
    ],
    nativeApi: 'Netlink / libmnl, nftables kernel subsystem, systemd networkd, udev subsystem',
    fallbackRisk: 'Different Linux distros use conflicting firewall backends (UFW on Ubuntu, Firewalld on RHEL, NFT on Debian).'
  },
  {
    id: 'L2',
    platform: 'linux',
    platformName: 'Linux (Ubuntu, Debian, RHEL, Fedora)',
    title: 'SELinux / AppArmor Profile Inconsistencies & Bypass',
    description: 'Script restricts DAC (discretionary access controls) via chmod/chown, but leaves MAC (Mandatory Access Control) unconfigured.',
    vector: 'Malware operating under an unconfined AppArmor/SELinux domain bypasses local file restrictions.',
    attackScenario: 'Container breakout or daemon running as root bypasses userspace file tightening due to permissive SELinux context.',
    mitigations: [
      'Ship tailored AppArmor / SELinux profiles confining peripheral access to approved binaries',
      'Enforce MAC rules forbidding video device nodes (`/dev/video*`, `/dev/snd/*`) to unconfined profiles',
      'udev rules to chmod 000 peripheral nodes at the kernel driver layer',
      'Audit log monitoring via `auditd` for permission denial and profile transitions'
    ],
    nativeApi: 'AppArmor parser, SELinux semodule, udevadm, Linux PAM (`/etc/pam.d/`)',
    fallbackRisk: 'Strict SELinux enforcement can break third-party packages if contexts are not correctly labeled.'
  },
  {
    id: 'M1',
    platform: 'macos',
    platformName: 'Apple macOS (Sonoma, Sequoia, & later)',
    title: 'Notarization & Cached TCC (Privacy Database) Bypass',
    description: 'macOS Transparency, Consent, and Control (TCC) stores permissions in `/Library/Application Support/com.apple.TCC/TCC.db`.',
    vector: 'Previously approved notarized applications retain cached camera/mic access even after script attempts disablement.',
    attackScenario: 'Attacker launches an existing notarized developer utility that previously held microphone privileges.',
    mitigations: [
      'Execute `tccutil reset Camera` and `tccutil reset Microphone` across all user domains',
      'Deploy a localized MDM Configuration Profile (`.mobileconfig`) locking Camera & Microphone payloads',
      'Monitor changes to TCC database using macOS Endpoint Security Framework (ESF)',
      'Hardware microphone disconnect notification (detect and verify orange indicator dot)'
    ],
    nativeApi: 'Endpoint Security Framework (ESF), System Integrity Protection (SIP), `tccutil`, `pfctl`',
    fallbackRisk: 'SIP prevents even root from directly modifying TCC.db without MDM or user approval in System Settings.'
  },
  {
    id: 'M2',
    platform: 'macos',
    platformName: 'Apple macOS (Sonoma, Sequoia, & later)',
    title: 'Application Sandbox Breakout & Packet Filter (PF) Anchor Override',
    description: 'macOS uses `pfctl` with anchor files. Third-party software or VPN clients frequently flush or overwrite the main `pf.conf`.',
    vector: 'VPN or virtualization software re-initializes PF anchors, blowing away custom port closure rules.',
    attackScenario: 'Launching a VPN client flushes `pf` rules, inadvertently exposing previously restricted local developer ports.',
    mitigations: [
      'Anchor dedicated hardening rules inside `/etc/pf.anchors/com.security.hardening` with high evaluation order',
      'Background daemon continuously monitors `pfctl -s info` and reloads anchors if state drops',
      'Network System Extension (NEFilterProvider) providing packet filtering impervious to `pfctl` flushes',
      'Audit logging via unified logging (`log stream --predicate "subsystem == \'com.apple.pf\'"`)'
    ],
    nativeApi: 'NetworkExtension Framework, pfctl, LaunchDaemons (`/Library/LaunchDaemons/`)',
    fallbackRisk: 'Modifying pf.conf requires administrative password and can conflict with macOS Internet Sharing.'
  },
  {
    id: 'X1',
    platform: 'abstraction',
    platformName: 'Cross-Platform Abstraction Layer',
    title: 'Semantic & Behavioral Inconsistencies Across Platforms',
    description: 'The abstraction layer exposes unified functions (e.g. `disable_camera()`, `block_port()`), but underlying OS mechanisms behave fundamentally differently.',
    vector: 'Architectural mismatch: Windows registry change vs Linux udev rule vs macOS TCC reset.',
    attackScenario: 'Security engineer assumes `block_port(22)` works identically, but on macOS it only filters external packets while Linux drops local loopback bindings.',
    mitigations: [
      'Formal state verification engine: after invoking abstraction, run OS-specific assertion tests',
      'Clear capability matrix documenting explicit semantics per OS (e.g. loopback vs external interface)',
      'Unified error handling schema with strict non-silent failure contracts',
      'Automated integration testing matrix executing across native virtual machines for all 3 OSes'
    ],
    nativeApi: 'Standardized JSON abstraction schema, platform-specific native backend adapters',
    fallbackRisk: 'Developers may rely on false uniformity assumptions, leading to platform-specific security blindspots.'
  },
  {
    id: 'X2',
    platform: 'abstraction',
    platformName: 'Cross-Platform Abstraction Layer',
    title: 'Platform Detection Spoofing & Environment Hijacking',
    description: 'Script relies on environment variables (`OSTYPE`, `OS`, `uname -s`) to decide which platform driver to execute. Malware tampers with environment.',
    vector: 'Environment variable injection (`export OSTYPE=darwin` on Linux) causing script to execute wrong hardening branch.',
    attackScenario: 'Script runs macOS hardening commands on a Linux server, which fail silently without hardening the actual Linux attack surface.',
    mitigations: [
      'Cryptographic OS verification: inspect binary kernel signatures and system syscall tables (not mutable env vars)',
      'Multi-source platform validation (check filesystem paths `/proc/version`, `/System/Library/CoreServices/SystemVersion.plist`, and `Kernel32.dll`)',
      'Fail-closed execution: if platform detection yields ambiguous or conflicting results, abort and lock system down',
      'Immutable root execution environment sanitizing all inherited environment variables'
    ],
    nativeApi: 'Node.js `process.platform`, POSIX `uname()` syscall, Windows `GetVersionExW` / registry validation',
    fallbackRisk: 'Containers and WSL (Windows Subsystem for Linux) can exhibit mixed environment traits.'
  }
];

export const ZERO_TRUST_PRINCIPLES: ZeroTrustPrinciple[] = [
  {
    id: 'ZT-1',
    number: 1,
    title: 'Never Trust Default Settings',
    tagline: 'Default configurations in commercial OSes prioritize developer convenience and compatibility over hostile resistance.',
    percentImplemented: 68,
    implemented: [
      'Script assumes all listening network ports are untrusted and initiates proactive closure',
      'Peripherals (microphones, webcams) are treated as surveillance vectors and disabled by default',
      'Default permissive filesystem permissions on common shared directories are actively restricted'
    ],
    notImplemented: [
      'Does not dynamically verify existing custom hardening baseline vs vendor OEM factory defaults',
      'Assumes previously hardened state is intact without cryptographic self-attestation on script startup'
    ],
    recommendations: [
      'Implement a pre-hardening audit diff comparing active configuration against pristine CIS Benchmarks',
      'Store baseline state in a tamper-resistant cryptographic vault to detect configuration drift'
    ]
  },
  {
    id: 'ZT-2',
    number: 2,
    title: 'Assume Breach',
    tagline: 'Operate under the premise that adversaries already possess userland access or foothold on adjacent network segments.',
    percentImplemented: 75,
    implemented: [
      'Assumes webcams and microphones can be covertly activated by existing local malware',
      'Assumes open network ports will be targeted by automated lateral movement scripts',
      'Implements least privilege access on directories to minimize post-compromise privilege escalation'
    ],
    notImplemented: [
      'Does not assume the hardening script itself or its PAM module could be subverted in memory',
      'Relies on the host operating system kernel to enforce decisions without out-of-band attestation'
    ],
    recommendations: [
      'Implement code signing and runtime integrity checking for the hardening script binary',
      'Integrate with hardware-rooted trust (TPM 2.0 / Apple Secure Enclave) for cryptographic key storage'
    ]
  },
  {
    id: 'ZT-3',
    number: 3,
    title: 'Defense in Depth (Layered Resilience)',
    tagline: 'Security must not hinge on a single perimeter wall; if one tier falls, secondary controls must prevent total compromise.',
    percentImplemented: 80,
    implemented: [
      'Multi-layered defense across network (firewall), hardware (driver/udev), and filesystem (ACLs)',
      'Dual enforcement of peripheral lockouts at both OS driver level and PAM user authentication gate'
    ],
    notImplemented: [
      'Lacks out-of-band backup telemetry if the primary local enforcement mechanism crashes',
      'Single PAM module acts as unified gatekeeper: compromise of PAM process unlocks all controlled hardware'
    ],
    recommendations: [
      'Decouple PAM permissions: require independent cryptographic tokens for network vs hardware grants',
      'Deploy an independent hardware watchdog process monitoring the status of the primary enforcement daemon'
    ]
  },
  {
    id: 'ZT-4',
    number: 4,
    title: 'Continuous Verification',
    tagline: 'Trust is ephemeral and must be continually re-evaluated against real-time telemetry and state changes.',
    percentImplemented: 62,
    implemented: [
      'Periodic re-auditing of network socket tables and listening ports',
      'Time-bounded temporary grants with automated timeout countdown'
    ],
    notImplemented: [
      'Audit cycle is scheduled (polling every N minutes) rather than event-driven (immediate socket hook)',
      'No automated behavioral revocation if an active process behaves maliciously during an open PAM window'
    ],
    recommendations: [
      'Transition from periodic polling to kernel-level event streaming (eBPF on Linux, ETW on Windows)',
      'Implement process behavioral monitoring: instantly terminate grants if an unapproved binary attaches to an open port'
    ]
  }
];

export const WORKFLOW_USABILITY_ITEMS = [
  {
    id: 'F1',
    workflow: 'Enterprise Video Conferencing (Zoom, Teams, Meet)',
    issue: 'Disabling camera and microphone breaks daily collaboration. Manual PAM requests before every call cause friction and lead users to request total disabling of hardening.',
    impact: 'MEDIUM usability friction leading to security circumvention.',
    mitigation: 'Implement a trusted "Conference Session" preset that enables camera + mic with a single authenticated action, displays an on-screen duration pill, and automatically locks down when the video process terminates.'
  },
  {
    id: 'F2',
    workflow: 'Software Development & Local Debugging',
    issue: 'Closing random high ports breaks local Vite, Webpack, Node, or Docker debugging (ports 3000, 5173, 8000, 9229). Developers become frustrated and add wildcard allow rules.',
    impact: 'HIGH probability of developers creating permanent dangerous firewall exceptions.',
    mitigation: 'Provide an isolated "Developer Mode" profile that binds local development ports exclusively to `127.0.0.1` (loopback only) while strictly denying any binding to `0.0.0.0` or external network adapters.'
  },
  {
    id: 'F3',
    workflow: 'Specialized Hardware (Medical Devices, Scanners, Audio DACs)',
    issue: 'Aggressive camera/mic driver disablement inadvertently disables medical video feeds, document scanners, and pro-audio interfaces that register under the video/audio device tree.',
    impact: 'MEDIUM potential for breaking essential peripheral equipment.',
    mitigation: 'Deploy a granular Hardware Whitelist based on Vendor ID (VID) and Product ID (PID), allowing specialized verified devices while keeping generic webcams disabled.'
  }
];
