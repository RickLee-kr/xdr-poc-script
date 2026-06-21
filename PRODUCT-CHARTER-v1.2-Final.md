
# PRODUCT CHARTER

Version: 1.2 Final

---

# Product Name

Detection Scenario Platform (DSP)

---

# Mission

Provide a reproducible, discovery-driven, provider-independent platform for generating security detection validation traffic, execution evidence, and observable telemetry.

DSP exists to generate activity.

DSP does not determine outcomes.

---

# Product Identity

DSP is:

- Traffic Generator
- Detection Validation Platform
- Scenario Runner
- Event Collector
- Evidence Generator
- Manual Verification Platform

DSP is not:

- SIEM
- XDR
- SOAR
- EDR
- Detection Engine
- Correlation Engine
- Threat Hunting Platform
- Governance Platform
- AI Analysis Platform

---

# Core Principles

## Discovery First

All scenario execution begins with discovery.

No scenario may assume targets.

No scenario may bypass discovery.

Discovery determines follow-up activity.

## Event Store First

Event Store is the only source of truth.

No alternate truth source is allowed.

## Evidence First

DSP generates evidence.

DSP does not generate conclusions.

## Provider Independence

Scenario planning must be provider-independent.

Execution location may change.

Scenario behavior must not change.

---

# Validation Philosophy

Validation means:

Evidence Exists

Validation does not mean:

- attack succeeded
- compromise succeeded
- detection succeeded
- alert created
- case created

---

# Success Criteria

Success = Traffic Generated

Success != Attack Successful

Success != Detection Successful

Success != Alert Generated

Success != Case Generated

---

# Supported Providers

## Local Provider

Traffic originates from the DSP host.

## Webshell Provider

Traffic originates from the configured webshell host.

Supported webshell types:

- JSP
- PHP
- ASPX

---

# Discovery-First Execution Model

Execution sequence:

1. Target Network Discovery
2. Live Host Discovery
3. Service Discovery
4. Follow-up Selection
5. Scenario Execution
6. Evidence Generation

Discovery determines execution scope.

No hardcoded targets are allowed.

No synthetic targets are allowed.

No discovery bypass is allowed.

---

# Follow-up Selection Model

## HTTP Discovery

Follow-up scenarios:

- HTTP Follow-up
- SQL Injection

## SSH Discovery

Follow-up scenarios:

- SSH Failure

## LDAP Discovery

Follow-up scenarios:

- LDAP Enumeration

## SMB Discovery

Follow-up scenarios:

- SMB Login Failure

## Kerberos Discovery

Follow-up scenarios:

- Kerberos Failure

## Live Host Discovery

Follow-up scenarios:

- DNS Tunnel
- Rare Protocol Activity
- Port Sweep

Important:

DNS Tunnel is selected from discovered live hosts.

DNS Tunnel is not dependent on DNS service discovery.

## DNS Discovery

Follow-up scenarios:

- DGA

DGA requires discovered DNS services.

---

# Webshell Attack Chain Model

DSP models a post-compromise attack chain.

## Phase 1

Attack the webshell host.

**Required scenarios** (webshell provider):

- URL Scan
- HTTP Follow-up
- SQL Injection
- SSH Failure (login failure attempts against the webshell host)
- **Host Behavior Check** (`host_behavior_check`) — mandatory endpoint telemetry on the webshell compromise host; includes **webshell reconnaissance** (whoami, id, hostname, uname, network discovery); runs after HTTP/SQLi and before internal recon
- **Non-standard port HTTP burst** — executed from the webshell host against itself (non-standard ports on the webshell server)

All Phase 1 activities target the webshell host itself. `host_behavior_check` is not optional for webshell attack-chain runs.

**Superseded scenario names:** *Webshell Reconnaissance* is not a separate scenario — it is covered by `host_behavior_check`.

## Phase 2

Assume foothold acquisition.

DSP does not determine compromise success.

The webshell endpoint is an execution mechanism only.

## Phase 3

Launch attack traffic from the webshell host against the target network (`target_net`).

Execution sequence:

1. **Target network discovery (TCP)** — prefetch from the webshell host; open ports on `FAST_SAFE_DISCOVERY_PORTS` populate `alive_hosts` and service buckets.
2. **Port Sweep** — horizontal port scan traffic against discovered live hosts (detection artifact; does not replan services).
3. **Service follow-ups** — HTTP Follow-up, SQL Injection, SSH/LDAP/SMB/Kerberos failures, DGA (skipped when no `dns_hosts`), Rare Protocol Activity; targets come from step 1 service buckets only.
4. **DNS Tunnel** — last; queries originate toward discovered live hosts.

Examples (step 3 unless noted):

- Port Sweep
- DNS Tunnel
- DGA
- SSH Failure
- SMB Login Failure
- LDAP Enumeration
- Kerberos Failure
- Rare Protocol Activity

The webshell host becomes the origin of attack traffic toward `target_net`.

DSP does not infer:

- attack success
- detection success
- alert generation
- case generation

---

# Local and Webshell Provider Consistency

The following must remain identical:

- Discovery Logic
- Service Discovery Logic
- Target Selection Logic
- Follow-up Selection Logic
- Scenario Ordering
- Scenario Behavior

Only traffic origin changes.

Local Provider:

Traffic originates from DSP.

Webshell Provider:

Traffic originates from the webshell host.

Planning must remain identical.

---

# Webshell Execution Rules

The webshell host is a command execution surface only.

DSP must never deploy:

- DSP Runtime
- Scenario Runner
- Planner Components
- manifest.json
- run_scenario.py
- remote_discovery.py
- DSP Package Files

Execution must remain command-based.

Discovery must remain command-based.

Follow-up activity must remain command-based.

---

# Evidence Workflow

Scenario
↓
Execution
↓
Event Store
↓
Evidence Package
↓
Human Verification

No automatic decision layer exists.

---

# Host Behavior Simulation

**Required** Phase 1 scenario (`host_behavior_check`) for webshell attack-chain runs. DSP generates endpoint telemetry on the webshell compromise host.

Examples (delivered by `host_behavior_check` unless noted as future extension):

- EICAR Test File
- Host / webshell reconnaissance (whoami, id, hostname, uname, ip addr, ip route, /etc/passwd)
- Linux Recon Burst *(future extension)*
- Encoded Shell Execution *(partial — base64 decode in `host_behavior_check`)*
- Credential Store Access Simulation
- Persistence Simulation
- Service Manipulation Simulation *(future extension)*
- Suspicious Administrative Tool Usage *(future extension)*

*Webshell Reconnaissance* is not a standalone scenario; recon commands above run inside `host_behavior_check`.

Purpose:

Generate observable endpoint activity.

Not:

- malware deployment
- attack success
- detection success

---

# EICAR Test File

DSP may:

- create
- access
- read
- remove

the industry-standard EICAR file.

DSP does not deploy malware.

---

# Future Scope Boundary

DSP Release 1.0 ends when:

- Discovery-first execution works
- Local Provider works
- Webshell Provider works
- Evidence export works
- Manual verification works

DSP Release 1.0 does not include:

- AI Correlation
- Risk Scoring
- Detection Scoring
- Alert Correlation
- SOAR Integration
- Automated Case Validation

---

# Frozen Rules

Never Add:

- stdout parsing as source of truth
- stderr parsing as source of truth
- grep validation
- attack success inference
- detection success inference
- automatic alert validation
- automatic case validation
- AI correlation
- confidence scoring
- risk scoring

---

# Final Principle

DSP generates activity.

DSP generates evidence.

Humans determine outcomes.
