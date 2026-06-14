# MASTER WBS

Version: 1.1

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
- Artifact Transfer
- Event Bundle Transfer
- EventSyncBridge

## Webshell Attack Chain Alignment

- Initial Compromise Host Model
- Webshell Host Target Mapping
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

## Real JSP Execution

Implement actual JSP execution.

## Real PHP Execution

Implement actual PHP execution.

## Real ASPX Execution

Implement actual ASPX execution.

## Remote Command Execution

Execute commands remotely.

## Remote Artifact Upload

Upload artifacts.

## Remote Bundle Download

Download event bundles.

## Remote Scenario Runner

Execute scenarios remotely.

## Remote Event Collection

Collect remote events.

## Evidence Export

JSON Export

Markdown Export

## Manual Verification Package

Checklist

Investigation Notes

Evidence Templates

---

# CURRENT RELEASE SCOPE

Release 1.0 ends when:

1. Remote execution works
2. Event bundles are collected
3. Evidence packages are exported
4. Manual verification workflow is usable

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
