# AD Weak Policies Discovery Scripts

A small collection of PowerShell scripts for finding, investigating, and gathering
evidence on weak or legacy security settings in Active Directory environments —
things like SMBv1, missing SMB signing, NTLMv1, and NetBIOS — plus two full
privilege-and-permissions auditors that turn "who has access to what" into a
severity-rated, risk-explained report. The goal is to help administrators and
security professionals see where insecure configurations or excessive privilege
are still in use, so remediation can be prioritized and proven.

Each script runs from a different vantage point. Read the per-script notes below
before running anything. Every check below carries a **severity** (Critical / High
/ Medium / Low / Info, plus **Secure** for a positive/protective finding) and a
one-line **risk** explaining what an attacker actually gets out of it.

## Scripts

- [`get-server-SMBv1-usage.ps1`](#get-server-smbv1-usageps1--is-smbv1-actually-being-used) — is SMBv1 actually being used?
- [`get-weak-domain-policies.ps1`](#get-weak-domain-policiesps1--sweep-every-server-in-the-domain) — sweep every server in the domain
- [`AD-Scan-Admin-on-DC.ps1`](#ad-scan-admin-on-dcps1--gpo-evidence--audit-dashboard) — GPO evidence + audit dashboard (admin, from a DC)
- [`AD-Scan-on-domainjoined-pc.ps1`](#ad-scan-on-domainjoined-pcps1--what-can-i-actually-do-selfaccount-privilege-report) — "what can I actually do?" self/account privilege report (any user, any PC)

---

### `get-server-SMBv1-usage.ps1` — Is SMBv1 actually being used?

Run this **directly on the server you want to investigate**. It reports the local
SMBv1 configuration and, more importantly, whether SMBv1 has actually been used
recently — so you can tell a dormant-but-enabled protocol apart from one that
still has live clients.

It reports:
- OS name, version, and computer name
- SMBv1 feature (`FS-SMB1`) install state
- SMB server configuration (`EnableSMB1Protocol`, `EnableSMB2Protocol`, `AuditSmb1Access`)
- Shared folders (`net share`)
- The last 20 SMBv1 audit events (event ID 3000)
- A count of SMBv1 events over the last 30 days, with a pass/warn verdict
- Active SMB sessions (client computer and user)

| Check | Severity | Risk |
|---|---|---|
| SMBv1 feature installed and/or `EnableSMB1Protocol` enabled | High | SMBv1 has no protection against relay/downgrade attacks and is missing decades of protocol-level security fixes (it is the protocol EternalBlue/WannaCry exploited); any host that still speaks it is a soft target. |
| SMBv1 events seen in the last 30 days (live clients, not just enabled) | High | A protocol that is enabled **and actively used** cannot be disabled without breaking something — this is what turns "insecure setting" into a prioritized, provable remediation task instead of a guess. |
| SMBv1 enabled but zero recent audit events | Info | Likely a safe, low-risk removal candidate — dormant but enabled still counts as attack surface if it's ever reachable. |

**Requirements**
- Run in an elevated PowerShell session on the target server
- SMBv1 access auditing should be enabled (`Set-SmbServerConfiguration -AuditSmb1Access $true`)
  for the event-based checks to return meaningful data

---

### `get-weak-domain-policies.ps1` — Sweep every server in the domain

Run this from a **domain-joined workstation or management system**. It discovers
every server in the domain via LDAP and, over WinRM, collects a one-row-per-server
summary of common weak settings.

Results are printed as a table. Servers that can't be reached are still listed,
with the error captured in the `Status` column.

| Check | Severity | Risk |
|---|---|---|
| SMBv1 enabled (`EnableSMB1Protocol`) | High | Same protocol-level exposure as above — no downgrade/relay protection and known-exploited vulnerabilities. |
| SMB signing not required (`RequireSecuritySignature = 0`) | High | Without signing, SMB traffic can be tampered with or relayed (NTLM relay attacks), letting an attacker on the network path authenticate as the victim to a third system. |
| NTLMv1 allowed (`LmCompatibilityLevel` < 3) | High | NTLMv1 uses a weak challenge/response scheme that is practically breakable, and it doesn't stop relay attacks the way Kerberos or NTLMv2-with-signing does. |
| NetBIOS enabled and TCP/139 actually listening | Medium | NetBIOS name resolution can be spoofed on the local network (NBT-NS poisoning) to capture credentials from misdirected authentication attempts. |
| Server unreachable | Info | Recorded as an evidence gap so a connectivity failure is never silently mistaken for "no weak settings found." |

**Requirements**
- Domain Admin privileges (as noted at the top of the script)
- PowerShell Remoting (WinRM) enabled and reachable on the target servers
- Network connectivity to the target servers

---

### `AD-Scan-Admin-on-DC.ps1` — GPO evidence + audit dashboard

The heavy lifter. Run this from a **domain controller or a management system with
the `ActiveDirectory` and `GroupPolicy` modules, elevated**. It exports audit-grade
evidence about how weak settings are (or aren't) mitigated through Group Policy,
inventories privileged access domain-wide, and runs ~27 severity-rated security
checks across every user and computer account — all combined into one interactive
HTML dashboard (`AUDIT-DASHBOARD.html`).

Privileged groups are located by well-known SID/RID rather than by display name, so
the script works across domains with mixed-language systems.

**Requirements**
- Windows PowerShell 5.1+ (`#requires -Version 5.1`)
- The `ActiveDirectory` and `GroupPolicy` modules
- An elevated session; Domain Admins-level read access is typically needed to
  enumerate fine-grained password policies

**Common parameters** (all optional):

| Parameter | Default | Purpose |
|---|---|---|
| `-OutputPath` | `.\GPO-Security-Evidence-<timestamp>` | Where evidence is written |
| `-DomainController` | auto | Target a specific DC |
| `-ResolveGroupMembership` | `$true` | Resolve security-filtering group members (`:$false` to skip) |
| `-MaxGroupMembersToDisplay` | `50` | Members embedded per group in the dashboard (full list still goes to CSV) |
| `-InheritanceQueryDelayMs` / `-InheritanceQueryRetryCount` | `250` / `2` | Throttle & retry `Get-GPInheritance` in large domains |
| `-MaxGroupNestingDepth` | `10` | Depth limit for recursive group resolution |
| `-OldPasswordThresholdDays` | `180` | Age past which a password is flagged as old |
| `-InactiveAccountThresholdDays` | `90` | Days of no logon past which an account is flagged as inactive |
| `-MaxAccountRowsToDisplay` | `200` | Rows embedded per check in the dashboard (full list still goes to CSV) |

**Examples**

```powershell
# Default run in the current directory
.\AD-Scan-Admin-on-DC.ps1

# Custom output folder and explicit DC
.\AD-Scan-Admin-on-DC.ps1 -OutputPath C:\AuditEvidence\GPO -DomainController DC01.contoso.com

# Skip (potentially slow) group membership resolution
.\AD-Scan-Admin-on-DC.ps1 -ResolveGroupMembership:$false
```

> **Note:** The dashboard surfaces *configured* settings, structural scope, and
> security filtering — it does **not** compute final effective (resultant) policy.
> For computer-specific proof, supplement it with `gpresult.exe /h GPResult.html`
> or `Get-GPResultantSetOfPolicy`.

#### Checks performed

**GPO policy findings** — read directly from `GptTmpl.inf` in SYSVOL via
language-independent registry paths, for every GPO in the domain:

| Setting | Insecure | Partial | Secure |
|---|---|---|---|
| SMB server/client signing required (`RequireSecuritySignature`) | Not required (`0`) — **High** | *(no partial state)* | Required (`1`) — **Secure**: signing stops in-transit tampering and NTLM-relay reuse of the session. |
| LAN Manager authentication level (`LmCompatibilityLevel`, NTLMv1) | `0`–`2`: LM/NTLMv1 sent and accepted — **High**: crackable, replayable hashes on the wire. | `3`–`4`: outbound NTLMv1 stopped, but the system may still *accept* inbound NTLMv1 — **Medium**. | `5`: LM and NTLMv1 refused both ways — **Secure**. |

**Password policy assessment** — default domain policy plus every fine-grained
password policy (PSO), each setting scored against modern guidance:

| Setting | Flagged when | Risk |
|---|---|---|
| Minimum password length | < 14 characters (High if < 8) | Short passwords are within reach of modern offline/online cracking, especially once a hash is obtained via Kerberoasting or a dump. |
| Complexity required | Disabled | Removes the last barrier against trivially guessable passwords. |
| Password history | < 24 remembered | Lets users cycle straight back to a previously (possibly already-breached) password. |
| Account lockout threshold | `0` (no lockout) | No lockout means unlimited online password-guessing attempts against every account. |
| Reversible encryption | Enabled | Stores the password in a form equivalent to plaintext on the domain controller. |

**Privileged access & Protected Users evidence** — recursive membership (including
nested groups, with the nesting path recorded) for Domain Admins, Enterprise
Admins, Schema Admins, built-in Administrators, Account/Server/Backup/Print
Operators, Group Policy Creator Owners, Key Admins/Enterprise Key Admins, and
DnsAdmins, cross-referenced against Protected Users membership.

| Finding | Severity | Risk |
|---|---|---|
| Large / stale privileged-group membership | High | Every extra member of a group like Domain Admins is another account that, if phished or cracked, hands an attacker control of the environment. |
| Privileged account not in Protected Users | Medium | Misses Protected Users' hardening (no NTLM, no delegation, no cached credentials, no weak Kerberos crypto) that would otherwise blunt several common attack paths. |
| Privileged group could not be resolved | Info (evidence gap) | Recorded explicitly rather than silently treated as "empty" — a gap in evidence is not proof of absence. |

**Users tab — one CSV + one severity-rated check each:**

| Check | Severity | Risk |
|---|---|---|
| Unconstrained delegation (users) | Critical | A compromised account can collect the Kerberos TGTs of everyone who authenticates to it — including Domain Admins — and replay them to impersonate those users anywhere; one of the fastest routes to full domain compromise. |
| Kerberoastable accounts (SPN set) | High | Any authenticated domain user can request a service ticket for the account and crack its password hash offline, with no lockout and nothing that looks like a failed login. |
| Service accounts (SPN set) | High | Service accounts commonly carry old, weak, human-chosen passwords and more privilege than needed — the prime Kerberoasting target, and a privileged one that's cracked gives broad, persistent access. |
| AS-REP roastable accounts (no pre-auth) | High | Anyone — even with zero credentials — can request AS-REP data for the account and crack its password offline. |
| Privileged accounts (core admin groups) | High | Every extra member is another account that, if compromised, hands over control of the environment. |
| Accounts with SIDHistory | High | Can silently grant access (including administrative access) that doesn't show up in normal group membership — a known stealthy persistence technique. |
| DES encryption allowed (users) | High | DES keys are broken trivially with modern hardware, exposing any Kerberos ticket protected with it. |
| Constrained delegation (users) | High | Lets the account impersonate other users against a specific service list; protocol transition widens the abuse window further. |
| Accounts without AES | Medium | Falls back to RC4, which is exactly what makes Kerberoasting practical against the account. |
| Protected accounts (`AdminCount = 1`) but no current privileged membership | Medium | Usually means leftover hardened permissions and broken ACL inheritance, and can hide the fact the account once had (or quietly still has) privileged access. |
| Password never expires | Medium | An unlimited window for the password to be guessed, cracked, or reused after a breach. |
| Old passwords (> `-OldPasswordThresholdDays`) | Medium | The longer a password is unchanged, the more time an attacker has to crack it offline or reuse a leaked copy. |
| Inactive accounts (> `-InactiveAccountThresholdDays`) | Medium | Unused-but-enabled accounts are an easy, quiet target — nobody is watching for their misuse. |
| Sensitive / cannot-be-delegated flag | Info | A positive control — the risk is what's *missing*: any privileged account **not** on this list (and not in Protected Users) can still be impersonated via delegation. |
| Protected Users members | Info | A positive control — the risk is coverage: privileged accounts **not** in this group miss its protections. |
| Disabled accounts | Low | Low risk while disabled, but clutter the directory and could be re-enabled to provide a legitimate-looking foothold. |

**Computers tab — one CSV + one severity-rated check each:**

| Check | Severity | Risk |
|---|---|---|
| Unconstrained delegation (computers, non-DC) | Critical | A compromised server can harvest the Kerberos TGTs of everyone who has connected to it — including Domain Admins — and replay them to take over the domain. |
| Resource-based constrained delegation (RBCD) configured | High | Whoever can write this attribute can grant themselves the ability to impersonate any user, including admins, against that host — a common lateral-movement/privesc technique. |
| Constrained delegation (computers) | High | A compromised server can act as other users against the listed services; protocol transition widens the abuse window. |
| Kerberos delegation overview (users & computers combined) | High | A single combined view of every delegation-capable account — collectively some of the highest-value targets in the domain. |
| DES encryption allowed (computers) | High | DES keys are trivially broken, exposing any Kerberos traffic protected with them. |
| Computers with SIDHistory | High | Can grant hidden, inherited access outside normal group membership. |
| Computers without LAPS | High | Without LAPS, the same local Administrator password is usually reused fleet-wide — recovering it from one machine unlocks all of them. |
| Domain controllers on a legacy/end-of-life OS | High (else Info) | No longer receives security fixes, leaving known, unpatched vulnerabilities on the single most critical systems in the environment. |
| Computers without AES | Medium | Falls back to weaker RC4, which Microsoft is actively phasing out. |
| Inactive computers (> `-InactiveAccountThresholdDays`) | Medium | Stale computer objects can be taken over or re-joined by an attacker to blend in with legitimate systems. |
| Disabled computers | Low | Low risk while disabled, but could be re-enabled for a legitimate-looking foothold. |

---

### `AD-Scan-on-domainjoined-pc.ps1` — "What can I actually do?" self/account privilege report

Run this from **any domain-joined workstation or member server, as any
authenticated domain user** — it does not require local admin or Domain Admin
rights, though some sections return more when run elevated. It is entirely
**read-only**: it never changes group membership, permissions, or account
settings. Where it fits relative to the other two scripts: those sweep
servers/GPOs from an admin vantage point; this one answers "what can *this one
account* actually do, here and in the domain?" from an ordinary user's vantage
point, and separates what's *normal* for a standard account from what's *higher
than it should be*.

**Credentials:** run it and you'll be prompted once for domain credentials; press
Cancel or leave the username blank to scan your current, already-logged-on identity
instead (no password used in that case). Pass `-Credential` to scan a specific
account non-interactively, or `-NoCredentialPrompt` to always use the current
session without any prompt. A supplied password is only ever held in memory for
the life of the script.

Anything the scan could not read (access denied, secedit needing elevation, an
unreachable domain controller) is recorded as an explicit evidence gap on its own
dashboard tab rather than silently skipped.

**Common parameters** (all optional):

| Parameter | Default | Purpose |
|---|---|---|
| `-Credential` | prompt | Domain account to scan; Cancel/blank = current identity |
| `-NoCredentialPrompt` | off | Skip the prompt, always use the current identity |
| `-OutputPath` | `C:\temp\Privilege-Scan-<timestamp>` | Where evidence is written |
| `-DomainController` | auto | Target a specific DC |
| `-ScanOuAcls` | off | Also sweep every OU's ACL (slower) |
| `-MaxOusToScanAcls` / `-MaxGposToScanAcls` | `300` / `500` | Caps for the OU/GPO ACL sweeps |

**Examples**

```powershell
# Prompt for credentials (Cancel/blank = scan the current logon)
.\AD-Scan-on-domainjoined-pc.ps1

# Non-interactive, current identity only
.\AD-Scan-on-domainjoined-pc.ps1 -NoCredentialPrompt

# Scan a specific account and sweep every OU's ACL too
.\AD-Scan-on-domainjoined-pc.ps1 -Credential (Get-Credential) -ScanOuAcls
```

#### Checks performed

##### Local machine — User Rights Assignment / token privileges

Every right the scanned identity is granted (directly or via a local **or**
domain group, matched by SID against the local security policy) plus, for the
session actually running the script, which are *currently enabled* in its live
token. Membership is compared against the "normal baseline" noted for each right.

**Critical**

| Right | Risk |
|---|---|
| `SeDebugPrivilege` | Opens a handle to (almost) any process, including LSASS — trivially leads to credential theft and code injection into SYSTEM processes. Expected only for admins/EDR tooling. |
| `SeTcbPrivilege` | "Act as part of the operating system" — can create tokens for any user without authenticating; effectively full system control. |
| `SeCreateTokenPrivilege` | Can fabricate an arbitrary access token (any user, group, or privilege) — a direct path to becoming any account. |
| `SeLoadDriverPrivilege` | Can load a kernel-mode driver — a classic route to kernel code execution, disabling security tooling, or exploiting a vulnerable signed driver. |
| `SeRestorePrivilege` | Can overwrite any file/registry value ignoring ACLs — a well-known local privesc and persistence primitive (e.g. replacing a service binary). |
| `SeBackupPrivilege` | Can read any file ignoring ACLs, including SAM/SYSTEM/NTDS.dit — enables full offline credential extraction. |
| `SeEnableDelegationPrivilege` | Can configure unconstrained/constrained delegation on other accounts — a domain-compromise primitive normally reserved for domain controllers. |
| `SeCreatePermanentPrivilege` | Can create permanent (non-removable) kernel objects — essentially never legitimate for a non-SYSTEM account. |

**High**

| Right | Risk |
|---|---|
| `SeTakeOwnershipPrivilege` | Can take ownership of any securable object, then grant itself full control — equivalent to full control everywhere. |
| `SeSecurityPrivilege` | Can view and clear the Security event log and change audit policy — lets an attacker read sensitive audit data or erase evidence. |
| `SeRelabelPrivilege` | Can change an object's Mandatory Integrity Control label, potentially bypassing integrity-based protections. |
| `SeSyncAgentPrivilege` | Required for directory-replication reads; combined with matching AD replication rights this enables DCSync-style hash extraction. |
| `SeTrustedCredManAccessPrivilege` | Allows reading other users' stored Credential Manager secrets. |
| `SeDelegateSessionUserImpersonatePrivilege` | Can impersonate other logged-on session users on this system. |
| `SeImpersonatePrivilege` | The well-known enabler of "Potato"-family local privesc (PrintSpoofer, RoguePotato, etc.), turning a service-context foothold into SYSTEM. |
| `SeAssignPrimaryTokenPrivilege` | Combined with impersonation rights, enables the same Potato-style privesc chains. |
| `SeSystemEnvironmentPrivilege` | Can alter UEFI/firmware variables, with potential impact on boot security configuration. |

**Medium**

| Right | Risk |
|---|---|
| `SeManageVolumePrivilege` | Raw, low-level disk/volume access that can bypass normal file-ACL semantics. |
| `SeMachineAccountPrivilege` | Can join new computer accounts to the domain — abusable for relay/coercion or RBCD attacks against those new accounts. |
| `SeCreateGlobalPrivilege` | Can create objects in the global namespace shared by all sessions — relevant to certain RDP/session-isolation attacks. |
| `SeCreateSymbolicLinkPrivilege` | Symbolic-link creation has been used as a building block in several local-privesc/file-redirection chains. |
| `SeSystemtimePrivilege` | Can shift the system clock, disrupting Kerberos (time-sensitive) or interfering with forensic log correlation. |
| `SeLockMemoryPrivilege` | Pins process memory so it can't be paged out; abnormal outside specific server workloads. |
| `SeRemoteInteractiveLogonRight` | Governs Remote Desktop logon — meaningful network-facing attack surface if unexpected. |

**Low / Info**

| Right | Risk |
|---|---|
| `SeRemoteShutdownPrivilege`, `SeShutdownPrivilege`, `SeIncreaseBasePriorityPrivilege`, `SeIncreaseQuotaPrivilege`, `SeProfileSingleProcessPrivilege`, `SeSystemProfilePrivilege`, `SeCreatePagefilePrivilege`, `SeAuditPrivilege`, `SeRemoveComputerPrivilege` | Availability/minor-information-disclosure impact only; expected on standard admin/service identities. |
| `SeUndockPrivilege`, `SeTimeZonePrivilege`, `SeIncreaseWorkingSetPrivilege`, `SeChangeNotifyPrivilege`, `SeInteractiveLogonRight`, `SeNetworkLogonRight`, `SeBatchLogonRight`, `SeServiceLogonRight` | No meaningful risk — granted to standard users/service accounts by default; this is the expected baseline. |

**Secure (protective)**

| Right | Risk |
|---|---|
| `SeDenyInteractiveLogonRight`, `SeDenyNetworkLogonRight`, `SeDenyRemoteInteractiveLogonRight`, `SeDenyBatchLogonRight`, `SeDenyServiceLogonRight` | No risk — these explicitly *block* a logon type for the account, a hardening control. |

##### Local & domain group membership (well-known SID/RID catalog)

The same SID-suffix catalog is used both for local BUILTIN groups and for matching
the account's domain group memberships (via the `tokenGroups` attribute) against
domain-relative RIDs — so it works identically whether the group lives in the
local SAM or in Active Directory.

**Critical**

| Group | Risk |
|---|---|
| Administrators (local) | Full local administrative control: install software/drivers, read any file, modify any account, disable security tooling. |
| Backup Operators | Can back up/restore any file ignoring ACLs and log on locally — functionally equivalent to full admin control. |
| Domain Admins | Full administrative control over the entire domain. |
| Enterprise Admins | Full administrative control over every domain in the forest. |
| Schema Admins | Can modify the AD schema forest-wide — a mistake or malicious change affects every domain in the forest. |

**High**

| Group | Risk |
|---|---|
| Account Operators | Can create/modify/delete most non-admin accounts and reset their passwords — a common lateral-movement stepping stone. |
| Server Operators | Can log on locally to domain controllers and manage services there — a path to full DC (and domain) compromise. |
| Print Operators | Can load print drivers on domain controllers — a known route to SYSTEM code execution on a DC. |
| Incoming Forest Trust Builders | Can create one-way incoming forest trusts, affecting cross-forest authentication trust boundaries. |
| Hyper-V Administrators | Full control over every VM hosted on the machine, including their credentials/data. |
| Group Policy Creator Owners | Can create new GPOs, which — once linked — can push settings (including scripts) to every affected computer/user. |
| Key Admins / Enterprise Key Admins | Can manage `msDS-KeyCredentialLink`, enabling "Shadow Credentials" account takeover without knowing the password. |
| DnsAdmins (name-based) | Historically allowed loading an arbitrary DLL into the DNS service (SYSTEM) on domain controllers. |
| Organization Management / Exchange Windows Permissions (name-based) | Broad Exchange rights; historically a path to `WriteDacl` on the domain object in unpatched deployments. |

**Medium**

| Group | Risk |
|---|---|
| Power Users, Replicator | Legacy groups with historically near-administrative power; unusual membership worth confirming. |
| Network Configuration Operators | Can modify TCP/IP configuration (including DNS servers) — abusable to redirect/intercept traffic. |
| Remote Desktop Users, Remote Management Users | Meaningful network-facing attack surface (RDP / WinRM) if unexpected for the role. |
| Distributed COM Users | Can launch/activate DCOM objects remotely — relevant to several lateral-movement/coercion techniques. |
| Cryptographic Operators, Certificate Service DCOM Access | Access to sensitive cryptographic/certificate operations. |
| Cert Publishers, RAS and IAS Servers, Storage Replica Administrators, Device Owners | Elevated but role-specific rights; unusual for a normal user account. |

**Low / Info**

| Group | Risk |
|---|---|
| Guests | Should normally be empty; low individual risk but worth a sanity check. |
| Performance Monitor/Log Users, Event Log Readers, Access Control Assistance Operators | Read/monitoring access — minor information-disclosure potential only. |
| Users, IIS_IUSRS, Domain Users, Domain Computers, Windows Authorization Access Group, Terminal Server License Servers, Domain Controllers, Enterprise RODCs | Expected baseline for the corresponding standard/service/computer identity. |

**Secure (protective)**

| Group | Risk |
|---|---|
| Protected Users | Not a privilege — restricts the account to Kerberos-only, no NTLM/DES, no delegation, non-cacheable credentials, shorter ticket lifetimes. A positive finding. |

##### Account configuration (UAC flags, Kerberos, delegation)

| Check | Severity | Risk |
|---|---|---|
| `ENCRYPTED_TEXT_PWD_ALLOWED` (reversible encryption) | Critical | Password is stored in a form equivalent to plaintext on the domain controller. |
| `TRUSTED_FOR_DELEGATION` (unconstrained delegation) | Critical | Any service this account authenticates to can capture and replay its full Kerberos TGT to impersonate it anywhere in the domain. |
| `PASSWD_NOTREQD` | High | Windows will accept a blank password for this account. |
| `USE_DES_KEY_ONLY` | High | Restricted to the DES cipher — weak, legacy crypto. |
| `DONT_REQUIRE_PREAUTH` (AS-REP roastable) | High | An offline-crackable hash can be requested with no credentials at all. |
| `TRUSTED_TO_AUTH_FOR_DELEGATION` (protocol transition) | High | Can trigger delegation even without an initial Kerberos ticket from the impersonated user, widening the abuse window. |
| Service Principal Name(s) set (Kerberoastable) | High (privileged account) / Medium | Any authenticated user can request a ticket and crack the password offline. |
| Constrained delegation configured | High (protocol transition) / Medium | Can obtain tickets to the listed services on behalf of other users. |
| Stale `adminCount = 1` with no current privileged membership | Medium | SDProp doesn't auto-clear this flag; can leave a stale, non-inheriting permissive ACL on an account that should no longer be privileged. |
| `DONT_EXPIRE_PASSWORD` | Low | Normal for a service account; worth reviewing on a standard interactive user. |
| `NOT_DELEGATED`, `SMARTCARD_REQUIRED` | Secure | Protective controls — reported as positive findings. |

##### AD object permissions (ACLs) — domain root, AdminSDHolder, every GPO, own objects

Every right the identity holds (directly or via group membership) is classified
by what it actually grants. Scanned by default: domain root, AdminSDHolder, the
account's own user object, its own computer object, and every existing Group
Policy Object (edit rights). `-ScanOuAcls` extends the same checks to every OU.

| Right found | Severity | Risk |
|---|---|---|
| `GenericAll` (full control) | Critical | Complete control over the object: read/modify everything, change permissions, take ownership. |
| Directory replication rights (**DCSync** pair) | Critical | Can replicate directory data from a DC, including password hashes for every account in the domain — full domain compromise via a single non-interactive read. |
| `WriteDacl` (modify permissions) | Critical | Can grant itself any right on the object at any time, regardless of what's granted today. |
| `WriteOwner` (take ownership) | Critical | An object's owner can always grant themselves any permission on it, even with no explicit ACE. |
| All extended rights (`ObjectType` = empty GUID) | Critical | Includes DCSync-equivalent and password-reset rights in one grant. |
| Ownership of the object | High | Same practical effect as `WriteOwner` — owner can (re)grant any right at will. |
| `GenericWrite` | High | Can modify most attributes; on a computer object this can configure Resource-Based Constrained Delegation to impersonate any user, including Domain Admins. |
| User-Force-Change-Password (extended right) | High | Can reset the account's password without knowing the current one. |
| GPO edit rights (`Write`/`GenericWrite`/`GenericAll` on an existing GPO) | High | If the GPO is linked to any OU, this can push settings — including a startup/logon script — to every computer/user in scope. |
| Enable Per-User Reversibly Encrypted Password (extended right) | High | Can flip the "store password using reversible encryption" bit on in-scope accounts. |
| Update Password Not Required Bit (extended right) | High | Can flip the "password not required" flag, after which Windows accepts a blank password for that account. |
| Delete / delete subtree | High | A destructive capability, even though the scan itself never deletes anything. |
| Unexpire Password (extended right) | Medium | Can clear the "password expired" state, bypassing an administrator-forced password change. |
| A specific, unrecognized extended right or attribute `WriteProperty` | Medium | Impact depends on the specific right/attribute (shown as a GUID in evidence); flagged for manual review. |
| Create/delete child objects | Medium | Impact depends on the container — e.g. creating computer/user objects. |
| **Apply Group Policy** (universal default) | *Suppressed — not reported* | Required for GPOs to function at all; every authenticated user has it on every GPO by design. |
| **Change Password** (extended right) | Info (baseline) | Standard default, typically granted broadly; only usable when the current password is already known. |
| **Write `description` attribute** | Info (baseline) | Standard default; limited to a cosmetic free-text field. |
| Nothing dangerous found on any scanned object | Secure | Reported explicitly as a positive finding. |

The last three rows are recognized, schema-verified Windows defaults (not
guessed) so they're reported as expected baseline instead of drowning real
findings in noise — everything else above is flagged for review.

---

## Use cases

- Active Directory security assessments and hardening projects
- Attack surface reduction and legacy protocol discovery
- Privilege and permissions review — "does this account/role have more access than it should?"
- Compliance and audit preparation
- Validating that mitigations are actually in place — and in scope

## Disclaimer

Use these scripts only in environments where you have explicit authorization to
perform security assessments and administrative reviews. Test any remediation in a
non-production environment before rolling changes out to production.

## Contributing

Contributions, improvements, and suggestions are welcome. Feel free to open an
issue or submit a pull request to improve detection coverage and reporting.
