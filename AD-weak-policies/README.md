# AD Weak Policies Discovery Scripts

This repository contains a collection of PowerShell scripts designed to identify, investigate, and triage the usage of weak or legacy security policies within Active Directory environments. The goal is to help administrators and security professionals understand where insecure configurations are still in use, so they can prioritize mitigation efforts and reduce their attack surface.

## Overview

Not all scripts are intended to be executed from the same location. Depending on the type of policy being investigated, scripts may need to be run on target systems, management workstations, or specific infrastructure servers.

### Endpoint-Based Discovery

Some scripts should be executed directly on the system you want to investigate. These scripts collect local configuration information and determine whether weak protocols or settings are actively in use.

**Example:**
- `Get-Server-SMBv1-Usage.ps1`

### Remote Domain Discovery

Other scripts are designed to query and assess configurations across multiple systems or within Active Directory. These scripts should be executed from a workstation or management system that has network connectivity to the target systems and the required permissions.

**Example:**
- `Get-Weak-Domain-Policies.ps1`

**Requirements:**
- Appropriate Active Directory permissions
- PowerShell remoting access (where applicable)
- Network connectivity to the target systems

### Domain Controller-Based Analysis

Some scripts require access to domain-specific information and should be executed on a Domain Controller or a system with equivalent access to Active Directory and Group Policy data.

**Example:**
- `Get-GPO-Evidence-Weak-Policy-Mitigation.ps1`

These scripts help identify which Group Policy Objects are responsible for applying weak configurations and provide evidence to support remediation planning.

## Use Cases

- Active Directory security assessments
- Attack surface reduction initiatives
- Legacy protocol discovery
- Security hardening projects
- Compliance and audit preparation
- Validation of mitigation efforts

## Disclaimer

These scripts are intended for use in environments where you have explicit authorization to perform security assessments and administrative reviews. Always test remediation actions in a non-production environment before deploying changes to production systems.

## Contributing

Contributions, improvements, and suggestions are welcome. Feel free to submit pull requests or open issues to improve detection coverage and reporting capabilities.