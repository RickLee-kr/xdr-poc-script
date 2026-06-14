# PRODUCT CHARTER

Version: 1.1

---

# Product Name

Detection Scenario Platform (DSP)

---

# Mission

Provide a reproducible and extensible platform
for generating detection scenario traffic.

---

# What DSP Is

DSP is:

- Traffic Generator
- Scenario Runner
- Event Collector
- Evidence Generator

---

# What DSP Is NOT

DSP is NOT:

- SIEM
- XDR
- SOAR
- EDR
- Detection Engine
- Correlation Engine
- AI Analysis Platform
- Threat Hunting Platform
- Governance Platform

---

# Primary Goals

1. Generate scenario traffic

2. Collect execution events

3. Store events

4. Export evidence

5. Support manual verification

---

# Validation Philosophy

Validation means:

Evidence Exists

Validation does NOT mean:

- attack succeeded
- detection succeeded

---

# Reporting Philosophy

Reporting provides:

- Evidence Summary
- Investigation Notes
- Manual Verification Support

Reporting never determines success or failure.

---

# Event Store

Event Store is the only source of truth.

No alternate truth source is allowed.

---

# Success Criteria

Success = Traffic Generated

Success != Detection Triggered

Success != Alert Created

Success != Case Created

Success != Attack Successful

---

# Supported Execution Models

Local Provider

Webshell Provider

- JSP
- PHP
- ASPX

---

# Webshell Attack Chain Model

When the Webshell Provider is used, DSP models a post-compromise attack chain.

The Webshell Host has four roles:

- Initial Compromise Target
- Webshell Execution Host
- Attack Foothold
- Internal Attack Origin

Attack chain flow:

Phase 1

Attack the Webshell Host.

Examples:

- HTTP Follow-up
- SQL Injection
- URL Scan style HTTP probing

These activities are directed at the host that provides the webshell endpoint.

Phase 2

Assume foothold acquisition.

DSP does not determine whether compromise actually succeeded.

DSP uses the configured webshell endpoint only as an execution mechanism.

Phase 3

Launch internal attack scenarios from the Webshell Host.

Examples:

- Port Sweep
- DNS Tunnel
- DGA
- SSH Failure
- SMB Login Failure
- LDAP Enumeration
- Kerberos Failure

The Webshell Host acts as the origin of internal attack traffic.

This model exists only to simulate realistic attack paths.

It does not imply:

- attack success
- detection success
- alert generation
- case generation


---

# Scenario Execution Model

DSP follows a Discovery-First execution model.

The execution sequence is:

1. Target Network Discovery

2. Live Host Discovery

3. Service Discovery

4. Service-Specific Follow-up Activity

Examples:

HTTP Service

- URL Scan style HTTP probing
- HTTP Follow-up
- SQL Injection

SSH Service

- SSH Failure

LDAP Service

- LDAP Enumeration

SMB Service

- SMB Login Failure

Kerberos Service

- Kerberos Failure

DNS Service

- DNS Tunnel
- DGA

The purpose of discovery is to determine which follow-up scenarios are applicable to each discovered service.

Follow-up activities are selected based on discovered services.

---

# Local Provider and Webshell Provider Consistency

The attack chain, scenario ordering, discovery logic, service selection logic, and follow-up behavior must be identical between:

- Local Provider
- Webshell Provider

The only difference is the execution location.

Local Provider:

Traffic is generated from the local DSP host.

Webshell Provider:

Traffic is generated through the configured webshell execution host.

Execution location may differ.

Scenario behavior must not differ.

Target selection must not differ.

Service discovery logic must not differ.

Follow-up selection logic must not differ.

Webshell Provider changes where traffic originates.

It does not change how scenarios are planned.


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
