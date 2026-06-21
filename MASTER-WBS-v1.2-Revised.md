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
- rare_protocol_activity

## Execution Provider Contracts

- Local Provider
- JSP Contract
- PHP Contract
- ASPX Contract

---

# IN PROGRESS

## Webshell Command Execution Model

- Command-Only Execution
- Discovery-First Webshell Execution
- Webshell-Origin Traffic Generation
- Runtime Deployment Prevention
- Runner Deployment Prevention
- Command Dispatch Validation
- JSP Validation
- PHP Validation
- ASPX Validation

## Webshell Attack Chain Alignment

- Initial Compromise Host Model
- Webshell Host Target Mapping
- Webshell Host HTTP Follow-up Targeting
- Webshell Host SQL Injection Targeting
- Webshell Host Host Behavior Check (Phase 1 required)
- Foothold-Based Remote Scenario Execution
- Attack Chain Planning Consistency
- Local Provider Compatibility Validation
- Webshell Provider Compatibility Validation

## Discovery-First Execution Model Alignment

- Discovery-First Scenario Planning
- Live Host Discovery Integration
- Service Discovery Integration
- Service-Specific Follow-up Selection

### Service Discovery Follow-up Mapping

HTTP Discovery
- HTTP Follow-up Selection From HTTP Discovery
- SQL Injection Selection From HTTP Discovery

SSH Discovery
- SSH Failure Selection From SSH Discovery

LDAP Discovery
- LDAP Enumeration Selection From LDAP Discovery

SMB Discovery
- SMB Login Failure Selection From SMB Discovery

Kerberos Discovery
- Kerberos Failure Selection From Kerberos Discovery

Live Host Discovery
- DNS Tunnel Selection From Live Host Discovery
- Rare Protocol Activity Selection From Live Host Discovery
- Port Sweep Selection From Live Host Discovery

DNS Discovery
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

## Real JSP Execution

Implement actual JSP execution.

## Real PHP Execution

Implement actual PHP execution.

## Real ASPX Execution

Implement actual ASPX execution.

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

1. Discovery-first execution works
2. Local Provider works
3. Webshell Provider works
4. Evidence packages are exported
5. Manual verification workflow is usable

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

# WEBSHELL EXECUTION RULES

The Webshell Host is a command execution surface only.

Never Deploy:

- DSP Runtime
- Scenario Runner
- Planner Components
- manifest.json
- run_scenario.py
- remote_discovery.py
- DSP Package Files

Execution must remain command-based.

---

# HOST BEHAVIOR SIMULATION SCENARIOS

## Scenario Library Extension

- eicar_test_file *(in `host_behavior_check`)*
- ~~webshell_recon~~ — **superseded by `host_behavior_check`** (whoami, id, hostname, uname, network discovery)
- linux_recon_burst
- encoded_shell_execution *(partial in `host_behavior_check`)*
- credential_store_access *(in `host_behavior_check`)*
- persistence_simulation *(in `host_behavior_check`)*
- service_manipulation
- suspicious_admin_tool_usage

## Validation Goal

Generate:

- Endpoint Telemetry
- EDR Visibility
- XDR Visibility
- AV Visibility
- NGAV Visibility
- Security Monitoring Evidence

Never infer:

- attack success
- detection success
- alert generation
- case generation

Evidence generation remains subject to the DSP evidence workflow.
