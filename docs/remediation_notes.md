\# Remediation Notes — Ubuntu 24.04 STIG Audit



\## Scan Environment

\- Tool: DISA SCAP Compliance Checker (SCC) 5.14.1

\- Benchmark: CAN\_Ubuntu\_24-04\_STIG version 001.004.006

\- System: Ubuntu Server 24.04 LTS (VMware Workstation VM)



\## Before State

\- Score: 26.16% (RED)

\- Pass: 45 | Fail: 127 | Total: 194



\## Remediations Applied



\### V-270666 — SSH confidentiality and integrity

\- Finding: SSH not configured to protect transmitted information

\- Fix: Set Protocol 2, StrictModes yes, PermitRootLogin no in sshd\_config

\- File modified: /etc/ssh/sshd\_config



\### V-270708 — Remote X connections

\- Finding: X11Forwarding not disabled

\- Fix: Set X11Forwarding no in sshd\_config

\- File modified: /etc/ssh/sshd\_config



\### V-270712 — Ctrl-Alt-Delete

\- Finding: Key sequence not disabled

\- Fix: sudo systemctl mask ctrl-alt-del.target

\- Method: systemd service masking



\### V-270714 — PAM null passwords

\- Finding: nullok present in common-auth

\- Fix: Removed nullok from pam\_unix.so line

\- File modified: /etc/pam.d/common-auth



\### V-270717 — Automatic SSH login

\- Finding: PermitUserEnvironment not disabled

\- Fix: Set PermitUserEnvironment no in sshd\_config

\- File modified: /etc/ssh/sshd\_config



\## Deferred Items (POA\&M)



\### V-270744 — FIPS cryptography

\- Reason: Requires kernel-level changes, risk of system instability in lab environment



\### V-270736 — PKI-based authentication mapping

\- Reason: Requires PKI infrastructure not present in this environment



\### V-270675 — Single-user mode authentication

\- Reason: GRUB configuration changes outside scope of this audit phase



\## After State

\- Score: 27.91% (RED)

\- Pass: 48 | Fail: 124 | Total: 194

\- Confirmed remediations: 3 automated checks resolved

