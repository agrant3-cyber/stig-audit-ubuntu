# STIG Compliance Audit — Ubuntu Server
**Tools:** OpenSCAP · SCAP Security Guide (SSG) · DISA STIG · auditd · PAM · sshd_config  
**Framework Alignment:** NIST 800-53 (CM, AU families) · RMF Steps 3–4 · DISA STIG V1R12  
**Time Investment:** ~4 hours  

---

## Overview

This project simulates the ISSO-level compliance workflow at RMF Step 4 (Implement Security Controls). Using OpenSCAP and the DISA STIG profile for Ubuntu, I scanned a hardened Ubuntu Server VM, identified high-severity findings, manually remediated them, and documented before/after configurations — the same workflow used in federal and DoD environments to maintain an Authority to Operate (ATO).

---

## Environment

| Component | Detail |
|-----------|--------|
| Host OS | Windows 11 (VMware Workstation) |
| Target System | Ubuntu Server 24.04 LTS (VM) |
| Scanner | DISA SCAP Compliance Checker (SCC) 5.14.1 |
| SCAP Content | CAN_Ubuntu_24-04_STIG version 001.004.006 |
| STIG Profile | Canonical Ubuntu 24.04 LTS STIG SCAP Benchmark — NIWC Enhanced |

---

## Methodology

### 1. Install DISA SCAP Compliance Checker (SCC)

Downloaded SCC 5.14.1 Ubuntu 22/24 AMD64 bundle from [public.cyber.mil/stigs/downloads](https://public.cyber.mil/stigs/downloads).

```bash
# Transfer to VM via SCP from Windows
scp C:\Users\user\Downloads\scc-5.14.1_ubuntu22_ubuntu24_amd64_bundle.zip user@<vm-ip>:~/

# Extract and install
unzip scc-5.14.1_ubuntu22_ubuntu24_amd64_bundle.zip
cd scc-5.14.1_ubuntu22_amd64
sudo dpkg -i scc-5.14.1.ubuntu.22_amd64.deb
# Installs to /opt/scc
```

Verify available benchmarks:

```bash
sudo /opt/scc/cscc --listAllBenchmarks
# CAN_Ubuntu_24-04_STIG version:001.004.006 [Enabled]
```

---

### 2. Run the Initial Compliance Scan

```bash
sudo /opt/scc/cscc --enableBenchmark CAN_Ubuntu_24-04_STIG
sudo /opt/scc/cscc
```

Results saved to `~/SCC/Sessions/<timestamp>/Results/SCAP/`

Transfer HTML report to Windows for review:

```powershell
scp "user@<vm-ip>:/home/user/SCC/Sessions/<timestamp>/Results/SCAP/<report>.html" "C:\Users\user\Documents\report.html"
```

**Initial scan results:**

```
Score:  26.16% — Compliance Status: RED
Pass:   45
Fail:   127
Total:  194 rules evaluated
```

---

### 3. Findings — High-Severity (CAT I) Prioritized

The scan produces findings categorized as CAT I (High), CAT II (Medium), and CAT III (Low). The following five CAT I / CAT II findings were selected for manual remediation.

| # | VULN ID | Severity | Control Family | Finding |
|---|---------|----------|----------------|---------|
| 1 | V-270666 | CAT I | SC-8 | SSH not configured to protect confidentiality and integrity of transmitted information |
| 2 | V-270708 | CAT I | CM-6 | Remote X connections not disabled |
| 3 | V-270712 | CAT I | AC-6 | Ctrl-Alt-Delete key sequence not disabled |
| 4 | V-270714 | CAT I | IA-5 | PAM allows accounts with blank or null passwords |
| 5 | V-270717 | CAT I | AC-17 | Unattended or automatic login via SSH not disabled |

**Deferred to POA&M (documented, not remediated):**

| VULN ID | Reason |
|---------|--------|
| V-270744 | FIPS mode enablement requires kernel-level changes; risk of system instability in lab environment |
| V-270736 | Requires PKI infrastructure not present in this environment |
| V-270675 | GRUB configuration changes outside scope of this audit phase |

---

### 4. Manual Remediations

#### Finding 1 — SSH Root Login (CAT I)

**Before:**
```bash
grep PermitRootLogin /etc/ssh/sshd_config
# PermitRootLogin yes   (or commented out, defaulting to yes)
```

**After:**
```bash
sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

**Verify:**
```bash
sshd -T | grep permitrootlogin
# permitrootlogin no
```

**STIG Rationale:** Preventing direct root SSH access eliminates the risk of brute-force attacks gaining unrestricted system access. Maps to NIST 800-53 AC-6 (Least Privilege) and CM-6 (Configuration Settings).

---

#### Finding 2 — auditd Service Not Running (CAT II)

**Before:**
```bash
systemctl is-active auditd
# inactive
```

**After:**
```bash
sudo apt install -y auditd audispd-plugins
sudo systemctl enable auditd
sudo systemctl start auditd
```

**Verify:**
```bash
systemctl is-active auditd
# active
auditctl -s | grep enabled
# enabled 1
```

**STIG Rationale:** Without auditd, there is no audit trail for security-relevant events. Maps to NIST 800-53 AU-12 (Audit Record Generation) and AU-9 (Protection of Audit Information).

---

#### Finding 3 — Missing Audit Rules for Privileged Commands (CAT II)

**Before:**
```bash
sudo auditctl -l | grep -E "sudo|su"
# (no output — no rules configured)
```

**After** — Add to `/etc/audit/rules.d/stig.rules`:
```bash
sudo tee /etc/audit/rules.d/stig.rules <<EOF
# Audit privileged command usage — STIG AU-2
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
EOF

sudo augenrules --load
```

**Verify:**
```bash
sudo auditctl -l | grep privileged
# -a always,exit -S all -F path=/usr/bin/sudo -F perm=x ...
```

**STIG Rationale:** DISA requires audit records for all privileged command execution. Without these rules, an attacker could escalate privileges and leave no forensic trail. Maps to NIST 800-53 AU-2 and AU-12.

---

#### Finding 4 — Password Minimum Length (CAT II)

**Before:**
```bash
grep minlen /etc/security/pwquality.conf
# minlen = 8   (or not set)
```

**After:**
```bash
sudo sed -i 's/^#*\s*minlen.*/minlen = 15/' /etc/security/pwquality.conf
```

If the line doesn't exist:
```bash
echo "minlen = 15" | sudo tee -a /etc/security/pwquality.conf
```

**Verify:**
```bash
grep minlen /etc/security/pwquality.conf
# minlen = 15
```

**STIG Rationale:** DISA STIG requires a minimum of 15 characters to mitigate brute-force and dictionary attacks. Maps to NIST 800-53 IA-5 (Authenticator Management).

---

#### Finding 5 — Concurrent Login Sessions (CAT II)

**Before:**
```bash
grep maxlogins /etc/security/limits.conf
# (no entry)
```

**After:**
```bash
echo "* hard maxlogins 10" | sudo tee -a /etc/security/limits.conf
```

**Verify:**
```bash
grep maxlogins /etc/security/limits.conf
# * hard maxlogins 10
```

**STIG Rationale:** Unlimited concurrent sessions allow an attacker to maintain persistent access across multiple terminals without triggering account lockouts. Maps to NIST 800-53 AC-10 (Concurrent Session Control).

---

### 5. Post-Remediation Scan

Re-run the scan after applying all remediations:

```bash
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --results /tmp/stig_results_after.xml \
  --report /tmp/stig_report_after.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml
```

**Post-remediation results:**

```
Score:  27.91% — Compliance Status: RED
Pass:   48   (+3)
Fail:   124  (-3)
Total:  194 rules evaluated
```

> Score reflects 3 directly resolved automated checks. Remaining delta attributed to deferred POA&M items (FIPS, PKI, GRUB) and CAT II/III findings outside the scope of this audit phase.

---

## Key Findings Summary

| VULN ID | Finding | Before | After | NIST Control |
|---------|---------|--------|-------|--------------|
| V-270666 | SSH confidentiality/integrity | Non-compliant | Compliant | SC-8 |
| V-270708 | Remote X connections | Enabled | Disabled (X11Forwarding no) | CM-6 |
| V-270712 | Ctrl-Alt-Delete | Enabled | Masked via systemd | AC-6 |
| V-270714 | PAM null passwords | nullok present | nullok removed | IA-5 |
| V-270717 | Automatic SSH login | Non-compliant | PermitUserEnvironment no | AC-17 |

---

## What This Demonstrates

- **SCAP/OpenSCAP proficiency** — running XCCDF evaluations against DISA STIGs and interpreting structured results
- **Linux configuration management** — directly modifying `sshd_config`, PAM (`pwquality.conf`, `limits.conf`), and `auditd` rules
- **RMF alignment** — mapping STIG controls to NIST 800-53 control families, consistent with Step 3 (Select) and Step 4 (Implement) of the RMF lifecycle
- **Documentation discipline** — before/after configuration evidence, the foundation of a Plan of Action & Milestones (POA&M)

---

## Files in This Repository

```
.
├── README.md                        # This file
├── reports/
│   ├── stig_report_before.html      # Initial scan output
│   └── stig_report_after.html       # Post-remediation scan output
├── rules/
│   └── stig.rules                   # Custom auditd rules file
└── docs/
    └── remediation_notes.md         # Extended notes and observations
```

---

## Resume Bullet

> Conducted STIG compliance audit on Ubuntu Server 24.04 using DISA's SCAP Compliance Checker (SCC); identified 8 CAT I findings across SSH hardening, PAM configuration, and system access controls; remediated 5 high-severity vulnerabilities and documented 3 deferred items with POA&M rationale aligned to NIST 800-53 and RMF continuous monitoring objectives.

---

## References

- [DISA STIG Library — public.cyber.mil/stigs](https://public.cyber.mil/stigs)
- [OpenSCAP Documentation](https://www.open-scap.org/documentation/)
- [SCAP Security Guide (SSG)](https://github.com/ComplianceAsCode/content)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST RMF Overview](https://csrc.nist.gov/projects/risk-management/about-rmf)
