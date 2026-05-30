# Dissecting an Undocumented Lua-Wrapped Loader: The BoldTealLayer Campaign

**Author:** TheOneEyedArgus  
**Date:** 2026-05-29  
**Classification:** Public

---

## Executive Summary

In early 2026, while investigating unexplained high memory usage on my Windows 11 system, I discovered a plaintext debug log file (`lua_traceback.log`) left in the `C:\temp` directory. The log detailed the real‑time actions of a previously undocumented malware loader. Despite being actively executed, the threat evaded detection by multiple up‑to‑date antivirus engines, including Microsoft Defender, Malwarebytes, and ESET.

The loader employs a multi‑stage attack chain. It uses a legitimate, digitally signed executable (`active_desktop_launcher.exe`) to side‑load a malicious DLL (`active_desktop_render_x64.dll`). This DLL then loads a Lua scripting engine to execute an obfuscated script that systematically dismantles Windows security mechanisms—patching Event Tracing for Windows, restoring a clean copy of `ntdll.dll` to remove user‑mode hooks, and employing a rare hardware breakpoint to bypass the Antimalware Scan Interface (AMSI). With all defences neutralised, a .NET assembly is injected directly into memory and executed. **Based on this custom evasion chain, this is the most sophisticated malware I have personally analysed, combining a legitimate signed host with an advanced, fileless Lua-driven payload**.

This report provides the first public analysis of this campaign. Unique Indicators of Compromise (IOCs) extracted from the debug log, registry persistence mechanism, and file hashes are presented here for the first time. The core malicious DLL (`active_desktop_render_x64.dll`) has no prior VirusTotal report and zero detections across all major engines, indicating that this threat has flown completely under the radar of the automated threat intelligence ecosystem.

Organisations and individuals should deploy the included YARA rule to detect the loader’s unique debug strings, monitor for the registry key `BoldTealLayer150`, and block communication with the distribution IP `143.92.51.20`.

---

## Methodology and Tools

Before diving into the full report, I want to mention what tools and resources I used during this process. This investigation was conducted manually, with no automated sandbox or formal analysis environment. I relied purely on Windows built-in tools (Task Manager, Registry Editor), Sysinternals utilities (Autoruns), and open-source intelligence platforms (VirusTotal, URLScan, AlienVault OTX, Triage). Throughout much of the process, I used a local AI assistant (an Abliterated DeepSeek) as a thinking partner—to brainstorm search locations, cross-reference technical concepts, and help structure the analysis. Every finding, IOC, and conclusion was independently and thoroughly verified by me. 

---

## 1. Discovery & Initial Triage

On 27 May 2026, I noticed my system—with 16 GB of RAM—was consistently reporting over 70–80% memory usage, even when no demanding applications were running. Windows Task Manager showed no single process using more than 500 MB. This time, instead of dismissing it as just “Windows being weird,” I began a manual search for the missing gigabytes.

I focused on temporary or unusual directories where malware often hides artifacts. In `C:\temp`, I found an unfamiliar file: `lua_traceback.log`. Opening it revealed a verbose, developer‑style debug log that clearly belonged to a live, active piece of malware.

<img width="496" height="478" alt="Screenshot_2026-05-27_Lua Log" src="https://github.com/user-attachments/assets/85356a25-1f69-4268-bbc6-002a0939623b" />

Figure 1 – Snippet of the lua_traceback.log file found in C:\temp, viewed in a simple text editor.

The log contained lines like `anti-emu: passed`, `ETW: patched 2 functions`, and `AMSI-VEH: DR0 armed on AmsiScanBuffer`. I immediately recognised these as anti‑detection and evasion techniques. The final lines showed a .NET assembly being loaded directly into memory—a classic fileless execution technique.

I initially used Microsoft Defender, which detected `active_desktop_launcher.exe` and flagged it as a threat. I then downloaded and ran Malwarebytes, which scooped up many of the `.exe` clones (all within `C:\ProgramData\`). In an effort to be thorough, I ran the ESET Online Scanner, which found one more `.exe`. Confident it was gone, I restarted my computer. When I logged back in, Task Manager showed another instance of the launcher. This time, when I ran Defender, Malwarebytes, and ESET again, none recognised it as a threat.

I disconnected my internet and ran full scans with the whole suite: Microsoft Defender, Malwarebytes, ESET Online Scanner, and also added RogueKiller (Adlice Protect) to the stack. All came back clean. The malware had not only evaded real‑time protection but also scrubbed any trace that scanners could find—despite being back and actively running. The log was my last and only clue.

Armed with the log—and because I’m a relentlessly stubborn nerd—I manually traced the infection. I found a persistence registry entry named `BoldTealLayer150` and located the three files involved in the attack: a legitimate signed executable, a malicious side‑loaded DLL, and a Lua interpreter. The sections below detail each component.

---

## 2. Technical Analysis

### 2.1 The Debug Log: A Blow‑by‑Blow of the Attack

The `lua_traceback.log` is the centrepiece of this analysis. It reads like a developer’s test output, detailing every step of the loader’s operation. Below is a sanitised excerpt with explanatory annotations.

```
=== DBG INIT OK ===           // Debug mode initialised
=== Lua payload START ===     // The malicious Lua script begins execution
anti-emu: passed              // Anti‑sandbox/VM check passed; real machine detected
payload detect: .NET 913408 bytes      // A .NET payload of 913,408 bytes is detected
ETW: patched 2 functions (variant 5)   // Event Tracing for Windows patched to blind security software
unhook: mapped clean ntdll from KnownDlls (2519040 bytes) // A fresh ntdll.dll is loaded from disk
unhook: restored 17/17 functions       // All 17 previously hooked functions are restored to their original code
AMSI-VEH: VEH registered               // A Vectored Exception Handler is set up
AMSI-VEH: DR0 armed on AmsiScanBuffer  // Hardware breakpoint placed on AmsiScanBuffer to bypass AMSI scanning
cleanup: DR0-DR3 cleared, VEH removed  // Cleanup after AMSI bypass is achieved
mutex: acquired (single instance)      // A mutex ensures only one instance runs
persist: reg run set (BoldTealLayer150)// Persistence is set via the Run registry key
launching CLR payload (blocking)...    // The .NET Common Language Runtime is about to be invoked
AMSI-VEH: VEH registered               // The AMSI bypass is set up again (probably before loading .NET)
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000     // .NET runtime binding successful
CLR: Start hr=0x00000000       // .NET runtime started
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes   // Payload is placed into a safe array
CLR: Load_3 vtable[44] hr=0x80131047   // Initial load attempt fails
CLR: Load_3 vtable[45] hr=0x00000000 OK  // Alternative loading method succeeds
CLR: EntryPoint vtable[16] OK   // Entry point found
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E     // First invocation call fails
CLR: retrying Invoke_3 with null args  // Retry with null arguments
```

**What This Reveals:**
- The loader is entirely Lua‑driven, using a standard Lua 5.1 interpreter (`lua51.dll`).
- It systematically dismantles Windows security: first blinding ETW, then unhooking `ntdll`, and finally bypassing AMSI with a hardware breakpoint—a sophisticated and relatively uncommon technique.
- The final payload is a .NET assembly that is never written to disk. It is loaded entirely from memory, making traditional file‑based detection useless.
- The log’s existence and format are unique; searches for these exact strings returned zero results, confirming this is a previously undocumented custom tool.

**An additional note on the log**: beyond the technical details, the existence of this plaintext log in `C:\temp` is a significant operational security lapse by the malware’s developer. For all the loader’s advanced evasion, this debug artifact handed me a detailed, near step‑by‑step playbook of the entire attack. It underscores a timeless lesson for defenders—even highly capable adversaries can make mistakes, and manual inspection of overlooked directories can sometimes uncover threats that automated scanners miss entirely.

### 2.2 Persistence Mechanism

The malware ensures its survival across reboots by using a simple registry Run key. I found it in several locations within the registry.

<img width="1195" height="792" alt="Screenshot_2026-05-27_RegistryLocation" src="https://github.com/user-attachments/assets/4ce79c39-20d7-43a0-8a51-02a2d3d2aa45" text="screenshot" />

Figure 2 – Registry Editor showing one of the persistence locations. I initially found it in `HKCU\...\Run` but I was rather eager to get rid of the lil bugger (to say it without explitive) so I deleted the file before taking a screenshot. The image shows an alternate location.

**Primary Path:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`  
**Value:** `BoldTealLayer150`  
**Data:** `"C:\ProgramData\BoldTealLayer150\active_desktop_launcher.exe"`

I also found another copy of the launcher in `C:\ProgramData\Microsoft Display Manager\active_desktop_launcher.exe`.

Interestingly, while the initial infection scattered multiple copies across oddly‑named temporary directories, the malware’s resurrection behaviour was limited to restoring only a single file to its primary folder (`BoldTealLayer150`). This suggests the persistence logic was hardcoded for a single path, lacking the redundant mechanisms typical of mature malware. Combined with the existence of the debug log, this points to a tool deployed without full operational hardening—perhaps a test/debug build, or an operator lacking the skill to fully weaponise the loader.

### 2.3 The Malicious File Trio

Three files worked in concert to achieve the infection. I safely hashed them without execution.

| File | SHA256 | Role |
| :--- | :--- | :--- |
| `active_desktop_launcher.exe` | `f712c2a8b4abf2e299a2b480020333deb0f43364e9686cda78b1243c62e4830d` | Legitimate, signed KuGou executable used as a host for DLL side‑loading. |
| `active_desktop_render_x64.dll` | `3E45C86A43F2F742BCE4232CCF2228375726983DE80BE3A5CA990584E66382D0` | Malicious DLL that loads the Lua engine and executes the script. No prior VT report exists. |
| `lua51.dll` | `0846af7812733617e900caf8ccccaae65335ff915584a6fa368eb3e8bfd46604` | Standard Lua 5.1 interpreter DLL, used to run the obfuscated script. |

**DLL Side‑Loading:** The signed `active_desktop_launcher.exe` loads `active_desktop_render_x64.dll` upon execution, either via a renamed legitimate dependency or by DLL search‑order hijacking. Because the host is validly signed, some security products may trust the process.

### 2.4 The Evasion Chain

The loader’s evasion sequence is a masterclass in blinding user‑mode security. I reconstructed the chain from the debug log and dynamic sandbox telemetry (from VirusTotal for `lua51.dll`):

1. **Anti‑Emulation Check:** The script first verifies whether or not it's running in a sandbox/VM by checking specific registry keys. If it detects an analysis environment, it exits cleanly, otherwise proceeds.
2. **ETW Patching:** Two functions within `EtW.dll` are patched to prevent security software from receiving event logs about process activity.
3. **ntdll Unhooking:** A pristine copy of `ntdll.dll` is loaded from `KnownDlls`, and 17 functions are restored to their original state. This removes any hooks placed by EDR/AV software.
4. **AMSI Bypass via Hardware Breakpoint:** A Vectored Exception Handler is registered, and a hardware breakpoint (DR0) is set on `AmsiScanBuffer`. When any software calls this function to scan memory for malicious content, a breakpoint exception is triggered. The handler intercepts it and likely returns a “clean” result, effectively disabling AMSI for all processes.
5. **.NET Injection:** With all monitoring blind, the script loads the .NET CLR into the current process, creates a safe array containing the 913,408‑byte payload, and invokes its entry point—entirely without writing the payload to disk.

The MITRE ATT&CK MBC behavior catalog for `lua51.dll` (from automated sandbox runs on VirusTotal) further confirmed these actions: anti‑VM checks, Base64/XOR decoding, process injection, and registry persistence.

### 2.5 The Final Payload

The log shows a .NET assembly of 913,408 bytes is injected and executed. I did not perform a full reverse engineering of the .NET code, but the initial discovery context (the system was flagged as `Trojan:Win32/Zusy!MTB` by Windows Defender *after* I removed the loader) suggests the payload may be a banking Trojan or information stealer. However, I refrain from definitive classification and simply note that the loader is capable of executing *any* .NET‑based payload.

---

## 3. Automated Sandbox & Community Intelligence

I analysed the three files on VirusTotal without uploading them (only hash searches were performed).

- **`active_desktop_launcher.exe`:** Detected by 0/70 engines. Community comments noted it was signed and “suspicious,” but risk was deferred to the companion DLL. A YARA rule from the zbetcheckin tracker flagged the file for containing debug output strings and anti‑debug code.
- **`lua51.dll`:** Detected by 0/70 engines. Behavioural sandboxes produced a rich MBC tree showing VM detection, process injection, registry modification, and obfuscation (Base64/XOR). This perfectly aligned with the log.
- **`active_desktop_render_x64.dll`:** At the time of writing, this file has **no VirusTotal report at all**—the hash returns “Item not found.” This means it has never been uploaded or analysed by any public sandbox. Therefore, the manual analysis in this report is the first public documentation of this component’s role.

<img width="1919" height="1040" alt="Screenshot_2026-05-28_VirusTotalUnseen" src="https://github.com/user-attachments/assets/c8a6e04d-8c3c-496c-bffe-45098cd1d5d3" />
<img width="1918" height="1034" alt="Screenshot_2026-05-28_VirusTotalUnseen2" src="https://github.com/user-attachments/assets/3d222593-2d2b-485c-8eec-f0d2b0bb9586" />

Figure 3 – The empty VirusTotal pages for active_desktop_render_x64.dll

To further validate the novelty of this threat, I searched *extensively* for the malicious DLL’s SHA256 hash, the filename `active_desktop_render_x64.dll`, and the unique string `BoldTealLayer150` across multiple open‑source threat intelligence platforms. None returned any hits:

- **AlienVault OTX:** No pulses or indicators matched.
- **Triage (tria.ge):** No sandbox reports or analyses existed.
- **URLScan.io:** No scans contained the DLL hash or filename.

These empty results, combined with the absent VirusTotal report and the total lack of *any mention* of `BoldTealLayer150` across multiple search engines, confirm that the core malicious component had never been publicly documented or analysed prior to this report.

In contrast, the distribution IP `143.92.51.20` was well‑documented on URLScan. It has been actively serving multiple suspicious executables, especially within the last year, including `RuntimeBroker.exe`, `package.rar`, `installer.exe`, and many other variations. This indicates my infection is part of a wider, multi‑forked campaign using a common delivery server.

---

## 4. Indicators of Compromise (IOCs)

The following IOCs can be used to detect or block this threat. All strings and hashes have been verified as unique to this campaign at the time of publication.

| IOC Type | Value | Notes |
| :-- | :-- | :-- |
| Debug log strings | `=== DBG INIT OK ===`<br/>`ETW: patched 2 functions (variant 5)`<br/>`AMSI-VEH: DR0 armed on AmsiScanBuffer`<br/>`BoldTealLayer150` | Can be detected via YARA or file content scanning. |
| Registry key (primary) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\BoldTealLayer150` | Persistence |
| Registry key (secondary) | `HKEY_USERS\UserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run` | Found on system; actual SID will vary |
| File path (debug artifact) | `C:\Temp\lua_traceback.log` | May be deleted by malware, but present at time of discovery |
| File path (potential original folder) | `%LOCALAPPDATA%\TEMP\BoldTealLayer150\` | Folder containing the signed loader |
| File path (potential secondary copy) | `C:\ProgramData\Microsoft Display Manager\` | Additional copy location |
| SHA256 – signed loader | `f712c2a8b4abf2e299a2b480020333deb0f43364e9686cda78b1243c62e4830d` | `active_desktop_launcher.exe` |
| SHA256 – malicious DLL | `3E45C86A43F2F742BCE4232CCF2228375726983DE80BE3A5CA990584E66382D0` | `active_desktop_render_x64.dll` |
| SHA256 – Lua interpreter | `0846af7812733617e900caf8ccccaae65335ff915584a6fa368eb3e8bfd46604` | `lua51.dll` |
| Network IP | `143.92.51.20` | Distribution server |
| Network URL | `http://143.92.51.20/RuntimeBroker.exe` | Original download URL (from VirusTotal community) |

---

## 5. Detection Guidance & YARA Rule

Organisations should implement the following measures:

- Deploy the YARA rule below to scan files, memory, or logs for the loader’s unique debug strings.
- Monitor registry run keys for unusual names like `BoldTealLayer150`.
- Block outbound traffic to IP `143.92.51.20` and any domain resolving to it.
- Investigate the presence of `lua51.dll` and `active_desktop_render_x64.dll` on systems, especially in non‑standard directories.

**YARA Rule:**

```yara
rule BoldTealLayer150_DebugLog {
    meta:
        description = "Detects the unique debug strings of the Lua-wrapped loader documented in this report"
        author = "TheOneEyedArgus"
        date = "2026-05-29"
        reference = "https://theoneeyedargus.github.io"
    strings:
        $s1 = "=== DBG INIT OK ==="
        $s2 = "ETW: patched 2 functions (variant 5)"
        $s3 = "AMSI-VEH: DR0 armed on AmsiScanBuffer"
        $s4 = "BoldTealLayer150"
    condition:
        any of them
}
```

This rule can be used with standard malware scanning tools like `yara64.exe` or integrated into Loki Scanner.

---

## 6. Conclusion

This investigation uncovered a highly evasive, custom malware loader that had completely bypassed the modern AV/EDR ecosystem. Its use of a legitimate signed binary, a Lua‑based orchestrator, and advanced anti‑detection techniques (ETW patching, ntdll unhooking, hardware breakpoint AMSI bypass) allowed it to operate silently for an unknown period. The accidental inclusion of a verbose debug log provided a rare glimpse into its inner workings.

The fact that the core malicious DLL remains undetected and unanalysed on VirusTotal as of this writing highlights a gap in automated threat intelligence that manual hunting can fill. I hope this report assists other defenders in identifying and neutralizing similar threats.

While not exploiting a zero‑day vulnerability, this malware represents a previously undocumented and fully undetected threat employing advanced, custom evasion techniques. To my knowledge, this is the first public analysis of this specific loader and its unique indicators.

---

## Appendix A: Raw Log Excerpt

Below is the complete, **unedited** contents of the `lua_traceback.log` as found on the infected system. The file contains repeated execution blocks, each beginning with `=== DBG INIT OK ===`, representing multiple attempts by the malware to launch. Variations in the ETW patching variant number and the sequence of evastion steps can be observed across these iterations.

```
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 5)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 4)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 2)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 1)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
ETW: patched 2 functions (variant 1)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 1)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 1)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 3)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 3)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 3)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
ETW: patched 2 functions (variant 1)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 2)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
ETW: patched 2 functions (variant 1)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 2)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
ETW: patched 2 functions (variant 5)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 3)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
ETW: patched 2 functions (variant 1)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 1)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 2)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 3)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
ETW: patched 2 functions (variant 1)
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
ETW: patched 2 functions (variant 2)
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 5)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
ETW: patched 2 functions (variant 3)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
ETW: patched 2 functions (variant 2)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 5)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 3)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
ETW: patched 2 functions (variant 3)
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 3)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 1)
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 2)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 2)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 4)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
ETW: patched 2 functions (variant 1)
cleanup: DR0-DR3 cleared, VEH removed
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
unhook: restored 17/17 functions
mutex: acquired (single instance)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 2)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 2)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
ETW: patched 2 functions (variant 2)
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 5)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
ETW: patched 2 functions (variant 3)
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
ETW: patched 2 functions (variant 1)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
stomp: no code cave found
AMSI-VEH: DR0 armed on AmsiScanBuffer
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 4)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
ETW: patched 2 functions (variant 2)
ETW: patched 2 functions (variant 5)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 4)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 4)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 5)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 5)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
ETW: patched 2 functions (variant 3)
ETW: patched 2 functions (variant 4)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 5)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
ETW: patched 2 functions (variant 4)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
ETW: patched 2 functions (variant 1)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 4)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 1)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 2)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
ETW: patched 2 functions (variant 4)
ETW: patched 2 functions (variant 3)
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 3)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 2)
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
ETW: patched 2 functions (variant 1)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 2)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 4)
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
ETW: patched 2 functions (variant 3)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 4)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 2)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
ETW: patched 2 functions (variant 1)
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 2)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
ETW: patched 2 functions (variant 3)
ETW: patched 2 functions (variant 4)
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 2)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
ETW: patched 2 functions (variant 1)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
ETW: patched 2 functions (variant 2)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 5)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
ETW: patched 2 functions (variant 4)
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
ETW: patched 2 functions (variant 3)
CLR: retrying Invoke_3 with null args
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 1)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 4)
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
ETW: patched 2 functions (variant 5)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 4)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
ETW: patched 2 functions (variant 3)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
ETW: patched 2 functions (variant 5)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 3)
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 3)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
ETW: patched 2 functions (variant 3)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
unhook: mapped clean ntdll from KnownDlls (2519040 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 3)
unhook: mapped clean ntdll from KnownDlls (2514944 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
CLR: Load_3 vtable[45] hr=0x00000000 OK
payload detect: .NET 913408 bytes
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
ETW: patched 2 functions (variant 4)
unhook: mapped clean ntdll from KnownDlls (2514944 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: instance already running, exit
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 2)
unhook: mapped clean ntdll from KnownDlls (2514944 bytes)
unhook: restored 17/17 functions
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 4)
ETW: patched 2 functions (variant 2)
unhook: mapped clean ntdll from KnownDlls (2514944 bytes)
unhook: restored 17/17 functions
unhook: mapped clean ntdll from KnownDlls (2514944 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: reg run set (BoldTealLayer150)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 3)
unhook: mapped clean ntdll from KnownDlls (2514944 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
=== DBG INIT OK ===
=== Lua payload START ===
anti-emu: passed
payload detect: .NET 913408 bytes
ETW: patched 2 functions (variant 3)
unhook: mapped clean ntdll from KnownDlls (2514944 bytes)
unhook: restored 17/17 functions
stomp: no code cave found
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
cleanup: DR0-DR3 cleared, VEH removed
mutex: acquired (single instance)
persist: admin detected, using schtasks
persist: schtasks created (Microsoft Display Manager)
launching CLR payload (blocking)...
AMSI-VEH: VEH registered
AMSI-VEH: DR0 armed on AmsiScanBuffer
CLR: CorBind hr=0x00000000
CLR: Start hr=0x00000000
CLR: GetDefaultDomain hr=0x00000000
CLR: QI _AppDomain hr=0x00000000
CLR: SAFEARRAY created, 913408 bytes
CLR: Load_3 vtable[44] hr=0x80131047
CLR: Load_3 vtable[45] hr=0x00000000 OK
CLR: EntryPoint vtable[16] OK
CLR: args built (empty string[])
CLR: Invoke_3 hr=0x8002000E
CLR: retrying Invoke_3 with null args
```

---

*© 2026 TheOneEyedArgus. Published as public intelligence for the cybersecurity community.*
