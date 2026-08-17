# AD Weak Policies Discovery Scripts

A small collection of PowerShell scripts for finding, investigating, and gathering
evidence on weak or legacy security settings in Active Directory environments —
things like SMBv1, missing SMB signing, NTLMv1, and NetBIOS. The goal is to help
administrators and security professionals see where insecure configurations are
still in use (and still being *actively* used), so remediation can be prioritized
and proven.

Each script runs from a different vantage point. Read the per-script notes below
before running anything.

## Scripts

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

**Requirements**
- Run in an elevated PowerShell session on the target server
- SMBv1 access auditing should be enabled (`Set-SmbServerConfiguration -AuditSmb1Access $true`)
  for the event-based checks to return meaningful data

### `get-weak-domain-policies.ps1` — Sweep every server in the domain

Run this from a **domain-joined workstation or management system**. It discovers
every server in the domain via LDAP and, over WinRM, collects a one-row-per-server
summary of common weak settings.

For each reachable server it records:
- Reachability status (Connected / error)
- IPv4 address, Windows version, OS version and build
- SMBv1 enabled
- SMB signing required (`RequireSecuritySignature`)
- NTLMv1 allowed, inferred from `LmCompatibilityLevel`
- NetBIOS configuration (Enabled / Disabled / DHCP) and whether TCP/139 is actually listening

Results are printed as a table. Servers that can't be reached are still listed,
with the error captured in the `Status` column.

**Requirements**
- Domain Admin privileges (as noted at the top of the script)
- PowerShell Remoting (WinRM) enabled and reachable on the target servers
- Network connectivity to the target servers

### `AD-Scan-Admin-on-DC.ps1` — GPO evidence + audit dashboard

The heavy lifter. Run this from a **domain controller or a management system with
the `ActiveDirectory` and `GroupPolicy` modules**. It exports audit-grade evidence
about how weak settings are (or aren't) mitigated through Group Policy, and builds
a single-file interactive HTML dashboard to trace findings by GPO or by OU/domain.

It focuses on:
- SMB signing enforcement and NTLMv1 prevention, read from `GptTmpl.inf` in SYSVOL
  using **language-independent** registry paths (not localized policy display names)
- GPO links, structural scope, security filtering (with resolved group membership),
  WMI filtering, and Group Policy inheritance
- Domain overview and a full domain controller inventory
- Recursive privileged group membership, including nested groups and the nesting path
- A Protected Users × administrative groups matrix
- The default domain password policy and any fine-grained password policies (PSOs)

Privileged groups are located by well-known SID/RID rather than by display name, so
the script works across domains with mixed-language systems.

**Outputs** (into a timestamped folder by default):
- `AUDIT-DASHBOARD.html` — interactive single-file dashboard (overview, policies,
  scope, privileged access, and password policy tabs; hover tooltips show group members)
- CSV summaries and per-GPO HTML/XML reports
- Raw `GptTmpl.inf` evidence, GPO link and inherited-scope data, security/WMI filtering data
- SHA-256 hashes for every evidence file, a PowerShell transcript, and a human-readable summary

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

### `AD-Scan-on-domainjoined-pc.ps1` — "What can I actually do?" self/account privilege report

Run this from **any domain-joined workstation or member server, as any authenticated
domain user** — it does not require local admin or Domain Admin rights, though some
sections return more when run elevated. It is entirely **read-only**: it never
changes group membership, permissions, or account settings. Where it fits relative
to the other two scripts: those sweep servers/GPOs from an admin vantage point; this
one answers "what can *this one account* actually do, here and in the domain?" from
an ordinary user's vantage point.

It builds a single-file interactive HTML dashboard that separates what's *normal*
for a standard account from what's *higher than it should be*, with a plain-English
risk explanation and a remediation for every finding — including a set of positive
("secure") findings when nothing unusual is found.

**Credentials:** run it and you'll be prompted once for domain credentials; press
Cancel or leave the username blank to scan your current, already-logged-on identity
instead (no password used in that case). Pass `-Credential` to scan a specific
account non-interactively, or `-NoCredentialPrompt` to always use the current
session without any prompt. A supplied password is only ever held in memory for
the life of the script.

It covers:
- **Local machine** — group membership (matched by SID, so nested domain-group-in-
  local-group membership is caught even without logging on as the account), the
  full local Administrators membership for context, the local User Rights
  Assignment policy (via `secedit`, mapped to the account's SID set), and, for the
  account actually running the session, its live/currently-enabled token
  privileges (via a small P/Invoke helper — language-independent, unlike parsing
  `whoami /priv`)
- **Domain group membership** — every privileged group the account belongs to,
  resolved through nested groups by Active Directory itself (the constructed
  `tokenGroups` attribute), matched against a catalog of well-known privileged
  group SIDs/RIDs plus a few commonly-privileged named groups (DnsAdmins, Exchange
  groups)
- **Account configuration** — UAC flags (password never expires, reversible
  encryption, delegation, pre-authentication), a stale/orphaned `adminCount`
  check, Service Principal Names (Kerberoastable), and constrained-delegation
  targets
- **AD object permissions (ACLs)** — dangerous rights (GenericAll/GenericWrite/
  WriteDacl/WriteOwner, the two DCSync replication rights, password-reset rights,
  and a handful of other specific extended rights) the account holds, directly or
  via group membership, on the domain root, AdminSDHolder, every existing Group
  Policy Object (edit rights), and its own user/computer objects. A handful of
  universal Windows defaults (Apply Group Policy, Change Password, writing the
  `description` attribute) are recognized and reported as expected baseline
  instead of noise. Pass `-ScanOuAcls` to additionally sweep every OU in the
  domain for the same rights (slower; capped by `-MaxOusToScanAcls`)

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

## Use cases

- Active Directory security assessments and hardening projects
- Attack surface reduction and legacy protocol discovery
- Compliance and audit preparation
- Validating that mitigations are actually in place — and in scope

## Disclaimer

Use these scripts only in environments where you have explicit authorization to
perform security assessments and administrative reviews. Test any remediation in a
non-production environment before rolling changes out to production.

## Contributing

Contributions, improvements, and suggestions are welcome. Feel free to open an
issue or submit a pull request to improve detection coverage and reporting.
