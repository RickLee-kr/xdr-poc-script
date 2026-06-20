# MASTER WBS

Version: 1.2

---

# COMPLETED

## Core Platform

- Runner
- Plugin Loader
- Scenario Framework
- Event Store
- Validation Engine
- Reporting Engine

## Protocol Framework

- DNS
- HTTP
- SSH
- SMB
- LDAP
- Kerberos

## Scenario Library

- dns_tunnel
- dga
- http_followup
- ssh_failure
- sql_injection
- smb_login_failure
- port_sweep
- ldap_enumeration
- kerberos_failure

## Execution Provider Contracts

- Local Provider
- JSP Contract
- PHP Contract
- ASPX Contract

---

# IN PROGRESS

## Remote Execution

- Webshell Contract
- Transport Layer
- Runtime Layer
- Remote Event Collection
- EventSyncBridge

## Webshell Attack Chain Alignment

- Initial Compromise Host Model
- Webshell Host Target Mapping
- Webshell Host Discovery Origin
- Webshell Host HTTP Follow-up Targeting
- Webshell Host SQL Injection Targeting
- Foothold-Based Remote Scenario Execution
- Attack Chain Planning Consistency
- Local Provider Compatibility Validation
- Webshell Provider Compatibility Validation

## Discovery-First Execution Model Alignment

- Discovery-First Scenario Planning
- Live Host Discovery Integration
- Service Discovery Integration
- Service-Specific Follow-up Selection
- HTTP Follow-up Selection From HTTP Discovery
- SQL Injection Selection From HTTP Discovery
- SSH Failure Selection From SSH Discovery
- LDAP Enumeration Selection From LDAP Discovery
- SMB Login Failure Selection From SMB Discovery
- Kerberos Failure Selection From Kerberos Discovery
- DNS Tunnel Selection From DNS Discovery
- DGA Selection From DNS Discovery
- Discovery-To-Follow-up Planning Consistency
- Bash PoC Execution Order Compatibility Validation

## Local and Webshell Provider Behavioral Parity

- Provider-Independent Scenario Planning
- Provider-Independent Target Selection
- Provider-Independent Service Discovery
- Provider-Independent Follow-up Selection
- Provider-Independent Scenario Ordering
- Local Provider Execution Validation
- Webshell Provider Execution Validation
- Local vs Webshell Plan Parity Validation
- Local vs Webshell Execution Parity Validation

---

# REMAINING P1

## Real JSP Command Execution

Execute DSP scenario commands through JSP webshell endpoints.

The webshell host is a command execution surface only.

Do not deploy DSP runtime components.

## Real PHP Command Execution

Execute DSP scenario commands through PHP webshell endpoints.

The webshell host is a command execution surface only.

Do not deploy DSP runtime components.

## Real ASPX Command Execution

Execute DSP scenario commands through ASPX webshell endpoints.

The webshell host is a command execution surface only.

Do not deploy DSP runtime components.

## Webshell Command Dispatch

Execute approved scenario commands through the configured webshell endpoint.

Examples:

- discovery commands
- protocol commands
- follow-up commands
- host behavior commands

The execution mechanism must be command-based.

## Remote Discovery Execution

Execute discovery operations from the webshell execution context.

Examples:

- host discovery
- service discovery
- capability discovery

Discovery must originate from the webshell host.

## Remote Follow-up Execution

Execute follow-up scenarios from the webshell execution context.

Examples:

- HTTP Follow-up
- SQL Injection
- SSH Failure
- DNS Tunnel
- DGA
- LDAP Enumeration
- SMB Login Failure
- Kerberos Failure
- Port Sweep

Traffic origin must be the webshell host.

## Remote Detection Artifact Generation

Generate only scenario-specific detection artifacts when required.

Allowed examples:

- EICAR test file
- temporary test script
- temporary command output file
- temporary evidence file

Forbidden examples:

- manifest.json
- run_scenario.py
- remote_discovery.py
- DSP package files
- DSP runtime deployment
- scenario runner deployment
- planner deployment

## Remote Event Collection

Collect scenario execution events produced through webshell-dispatched commands.

Remote event collection must not require DSP runtime deployment on the webshell host.

## Evidence Export

- JSON Export
- Markdown Export

## Manual Verification Package

- Checklist
- Investigation Notes
- Evidence Templates

---

# CURRENT RELEASE SCOPE

Release 1.0 ends when:

1. Remote command execution works
2. Remote discovery execution works
3. Remote follow-up execution works
4. Remote events are collected
5. Evidence packages are exported
6. Manual verification workflow is usable

Nothing beyond this is required.

---

# FROZEN

Never Add:

- stdout parsing
- stderr parsing
- grep validation
- attack success inference
- detection success inference
- automatic alert validation
- AI correlation
- risk scoring
- confidence scoring

---

# DEFERRED

Do Not Implement:

- Correlation Expansion
- Validation Expansion
- Orchestration Expansion
- RunManager Expansion
- AI Analysis
- Detection Scoring
- SOAR Integration
- Alert Correlation

These items are outside Release 1.0.

---

# HOST BEHAVIOR SIMULATION SCENARIOS

The following scenario library extensions are approved for host-based detection validation traffic generation.

These scenarios generate observable operating system activity, endpoint telemetry, execution events, and evidence.

These scenarios do not determine:

- attack success
- detection success
- alert generation
- case generation

## Scenario Library Extension

- eicar_test_file
- webshell_recon
- linux_recon_burst
- encoded_shell_execution
- credential_store_access
- persistence_simulation
- service_manipulation
- suspicious_admin_tool_usage

## Planned Scenario Definitions

### eicar_test_file

Generate EICAR test file lifecycle activity.

Examples:

- file creation
- file access
- file read
- file deletion

### webshell_recon

Generate post-compromise reconnaissance activity from a webshell execution context.

Examples:

- whoami
- id
- hostname
- uname
- network discovery

### linux_recon_burst

Generate rapid host and environment enumeration activity.

Examples:

- identity discovery
- operating system discovery
- network discovery
- account discovery

### encoded_shell_execution

Generate encoded command execution patterns.

Examples:

- base64 encoded command execution
- encoded shell invocation

### credential_store_access

Generate credential-related access attempts.

Examples:

- account database access attempts
- credential store enumeration attempts

### persistence_simulation

Generate temporary persistence-related activity.

Examples:

- cron simulation
- startup persistence simulation
- scheduled execution simulation

### service_manipulation

Generate service-management activity.

Examples:

- service enumeration
- service inspection
- temporary service actions

### suspicious_admin_tool_usage

Generate administrative-tool activity commonly monitored by endpoint security platforms.

Examples:

- curl
- wget
- nc
- ncat
- socat
- openssl client utilities

## Future Validation Coverage

The purpose of these scenarios is to support validation of:

- EDR visibility
- XDR visibility
- AV visibility
- NGAV visibility
- Endpoint telemetry collection
- Security monitoring workflows

Evidence generation remains subject to the existing DSP evidence workflow.
