# MASTER PROMPT — SECUREFLOW DEVSECOPS SECURITY PLATFORM

## 1. ROLE

Act as a senior product designer, UI/UX architect, and frontend engineer designing a production-grade enterprise cybersecurity platform.

Create a complete web application called **SecureFlow**.

SecureFlow is a **DevSecOps security orchestration and security-gate platform** that helps developers and security teams scan applications, analyze vulnerabilities, enforce security policies, and control whether software is allowed to proceed through CI/CD toward deployment.

The design must look like a **real enterprise cybersecurity/SaaS product**, not a college-project dashboard.

The interface should be technically sophisticated, clean, minimal, professional, responsive, and highly usable.

---

# 2. CORE PRODUCT IDEA

The user should be able to:

1. Create/manage projects.
2. Upload an authorized project as a ZIP file.
3. Connect a GitHub repository.
4. Configure a CI/CD security pipeline.
5. Start security scans.
6. Run multiple security gates.
7. View vulnerabilities and findings.
8. Calculate an overall security/risk score.
9. Apply security policies.
10. Automatically decide:
   - PASS
   - WARN
   - BLOCK
11. View deployment status.
12. View security reports.
13. View audit logs.
14. Track security posture over time.

The central concept of the product is:

**Detect → Analyze → Normalize → Evaluate → Gate → Deploy**

---

# 3. IMPORTANT PRODUCT ARCHITECTURE

The frontend is ONLY the control panel/UI.

Do NOT pretend the browser itself performs security scanning.

The future architecture is:

Frontend
↓
Backend API
↓
Scan Orchestrator
↓
Security Tools / CI/CD / Docker / GitHub
↓
Result Normalization
↓
Risk Engine
↓
Security Policy
↓
PASS / WARN / BLOCK
↓
Deployment Decision
↓
Dashboard / Reports / Audit Logs

The UI should clearly represent this architecture.

---

# 4. TECHNOLOGY CONTEXT

The overall project will eventually use:

Frontend:
- Modern web frontend
- Responsive UI
- Component-based architecture

Backend:
- Backend API
- Authentication
- Project management
- Scan orchestration
- Result processing
- Policy engine

Source Control:
- GitHub
- GitHub API
- GitHub Actions

Containerization:
- Docker
- Containerized scanner environments
- Container image scanning

Security tools may include:

- Gitleaks — secret scanning
- Semgrep / CodeQL — SAST
- OWASP Dependency-Check / similar — SCA
- Checkov — IaC security
- Trivy — container/image security
- OWASP ZAP — DAST

The UI must treat these as separate security engines.

---

# 5. DESIGN LANGUAGE

Use a premium cybersecurity/SOC aesthetic.

Primary visual direction:

- Dark theme by default
- Near-black background
- Dark navy/charcoal panels
- Subtle borders
- High contrast typography
- Green/teal for secure/pass states
- Amber/yellow for warnings
- Red for critical/blocking states
- Blue for informational/running states

Avoid:
- Excessive gradients
- Huge glowing effects
- Gaming-style UI
- Excessive neon
- Generic admin-dashboard appearance
- Excessive rounded cards
- Unnecessary decorative graphics

The product should feel similar to a serious enterprise security platform.

Use:
- Inter or similar professional sans-serif
- Compact typography
- Clear hierarchy
- Data-dense but readable layouts
- Small status badges
- Security-oriented icons
- Consistent spacing
- Professional tables

---

# 6. GLOBAL LAYOUT

Create a permanent application shell.

LEFT SIDEBAR:

Logo:
SecureFlow

Subtitle:
DevSecOps Security Platform

Navigation:

Dashboard
Projects
Repositories
Scans
Findings
Reports
Security Policy
Deployments
Audit Logs

Bottom section:

Platform status:
● Platform Online

Current user:
Nitesh
Security Analyst

MAIN AREA:

Top navigation/header containing:

- Breadcrumb
- Page title
- Global search
- Notifications
- User/profile menu
- "+ New Scan" button

---

# 7. DASHBOARD

Create the main security dashboard.

Header:

SECURITY OVERVIEW

"Good morning, Nitesh."

Subtitle:

"Here’s what is happening across your protected applications."

Top actions:

- Export Snapshot
- + Start Scan

## KPI CARDS

Create four cards:

Projects
12

Total Scans
48

Open Findings
23

Blocked Releases
7

Each card should optionally show trend information.

Example:

↑ 14% vs last month

---

# 8. SECURITY POSTURE

Create a section:

Security Posture

Display:

- Risk score
- Critical findings
- High findings
- Medium findings
- Low findings
- Security gate success rate

Create a professional risk visualization.

Example:

CURRENT RELEASE RISK

82 / 100

HIGH RISK

Use a circular risk indicator.

---

# 9. RISK TREND

Create a chart:

Risk Score Trend

Time range:
7 days / 30 days / 90 days

The graph should show decreasing/increasing risk over time.

Add tooltip behavior.

---

# 10. SECURITY GATES

Create a major dashboard section called:

Security Gates

Display individual gate cards/rows.

Gates:

1. Secret Scanning
Tool:
Gitleaks

2. Static Application Security Testing
Tool:
Semgrep / CodeQL

3. Software Composition Analysis
Tool:
OWASP Dependency-Check

4. Infrastructure as Code Security
Tool:
Checkov

5. Container Security
Tool:
Trivy

6. Dynamic Application Security Testing
Tool:
OWASP ZAP

Each gate should display:

- Tool
- Status
- Number of findings
- Duration
- Last execution
- Severity summary

Statuses:

PASS
WARN
BLOCK
RUNNING
FAILED

---

# 11. RELEASE DECISION

Create a prominent component:

RELEASE DECISION

Example:

BLOCK

Reason:

1 Critical vulnerability
2 High vulnerabilities

Policy:

Default Release Policy

Required action:

Remediation required before production deployment.

Buttons:

- View Findings
- Re-run Pipeline

---

# 12. RECENT SCANS

Create a professional table.

Columns:

Scan ID
Project
Source
Branch
Commit
Status
Risk
Started
Duration
Actions

Example:

SCN-1024
SecureShop
GitHub
main
8ad4e21
BLOCKED
82
2 min ago
4m 32s

Actions:

View
Re-run

---

# 13. PROJECTS PAGE

Create a dedicated Projects page.

Header:

Projects

Subtitle:

"Manage applications, targets, repositories and security posture."

Button:

+ New Project

Each project should show:

- Project name
- Repository
- Technology
- Last scan
- Risk score
- Open findings
- Deployment status
- Security status

Example projects:

SecureShop
IoT Gateway API
Payments Service
Inventory API
Lab Web App

---

# 14. PROJECT DETAIL PAGE

When a project is opened, show:

Project name

Repository

Branch

Latest commit

Technology

Owner

Environment

Risk score

Open findings

Last scan

Deployment status

Tabs:

Overview
Scans
Findings
Pipeline
Deployments
Reports
Settings

---

# 15. NEW PROJECT FLOW

Create a polished multi-step modal/page.

Step 1:
Project Information

Fields:

Project Name
Description
Technology
Environment

Step 2:
Source

Options:

Upload ZIP
GitHub Repository
Authorized Application URL

Step 3:
Security Configuration

Select:

Secret scanning
SAST
SCA
IaC
Container scanning
DAST

Step 4:
Security Policy

Select:

Default Release Policy
Strict Production Policy
Development Policy

Step 5:
Review

Show configuration summary.

Button:

Create Project

---

# 16. REPOSITORIES PAGE

Create:

Repositories

Show GitHub integration status.

Example:

GitHub Connected

Connected account

Repositories:

nitesh/secureshop
nitesh/iot-gateway
nitesh/payments-service

Each row:

Repository
Branch
Last Commit
Workflow
Last Scan
Status
Actions

Buttons:

Connect GitHub
Run Workflow
Configure

---

# 17. GITHUB INTEGRATION

Create a GitHub connection interface.

Explain:

"SecureFlow can connect to GitHub to trigger security checks from CI/CD workflows."

Show architecture visually:

GitHub Repository
↓
GitHub Actions
↓
SecureFlow Security Gates
↓
Security Policy
↓
PASS / WARN / BLOCK

Show events:

Push
Pull Request
Manual
Scheduled

Do not expose real secrets/tokens in UI.

Use secure placeholders.

---

# 18. CI/CD PIPELINE PAGE

Create a visual pipeline.

Pipeline stages:

1. Checkout
2. Build
3. Unit Tests
4. Secret Scan
5. SAST
6. SCA
7. IaC Scan
8. Docker Build
9. Container Scan
10. Deploy to Staging
11. DAST
12. Risk Evaluation
13. Security Gate
14. Production Deployment

Represent the pipeline visually as connected stages.

Each stage must show:

- Status
- Duration
- Tool
- Logs
- Findings

---

# 19. PIPELINE DETAIL

Clicking a stage should open a detail panel.

Example:

SCA

Status:
FAILED

Tool:
OWASP Dependency-Check

Duration:
38 seconds

Findings:
1 Critical
2 High

Show:

- Dependency
- Version
- Vulnerability
- CVE
- CVSS
- Recommendation

Button:

View Findings

---

# 20. SCANS PAGE

Create:

Scans

Filters:

- Project
- Status
- Scanner
- Severity
- Date

Search scans.

Table:

Scan ID
Project
Source
Commit
Status
Risk
Findings
Duration
Date

Buttons:

View
Re-run
Delete

---

# 21. SCAN CREATION MODAL

Create a polished "New Security Scan" modal.

Title:

Start a Security Scan

Source choices:

UPLOAD PROJECT

GITHUB REPOSITORY

AUTHORIZED LIVE APPLICATION

For ZIP:

Project ZIP
Browse

For GitHub:

Repository URL
Branch
Workflow

For live application:

Authorized Target URL

Show an authorization warning:

"Only scan applications you own or are explicitly authorized to test."

Then:

Environment
Policy

Show:

GATE PLAN

Gitleaks
SAST
SCA
IaC
Trivy
ZAP

Button:

Start Security Scan

---

# 22. SCAN EXECUTION SCREEN

When a scan is running, show:

SCAN IN PROGRESS

Project:
SecureShop

Commit:
8ad4e21

Environment:
Staging

Create a vertical or horizontal execution timeline.

Example:

✓ Checkout
✓ Build
✓ Unit Tests
✓ Secret Scan
● SAST
○ SCA
○ IaC
○ Container Scan
○ DAST
○ Risk Evaluation
○ Security Gate

Show:

Current stage
Elapsed time
Estimated progress

---

# 23. FINDINGS PAGE

Create a vulnerability management interface.

Top statistics:

Critical
1

High
3

Medium
5

Low
14

Informational
8

Create filters:

Severity
Scanner
Project
Status
CVE
Date

Search findings.

Table columns:

Finding ID
Title
Severity
Scanner
Project
CVE
CVSS
Status
Detected
Actions

---

# 24. FINDING DETAIL

Clicking a finding should open a detailed security finding page.

Example:

Potential SQL Injection

Severity:
HIGH

CVSS:
8.7

Scanner:
SAST

Project:
SecureShop

Location:

UserController.java:84

Show:

Description
Impact
Evidence
Affected Code
CVE/CWE if applicable
Remediation
References
Detection history

Buttons:

Mark Resolved
Ignore
Create Exception
Re-scan

---

# 25. SECURITY POLICY PAGE

Create a professional policy-as-code style interface.

Title:

Security Policy

Show policy:

Default Release Policy

Rules:

Critical findings → BLOCK

High findings → BLOCK

Medium findings → WARN

Low findings → ALLOW

Secrets detected → BLOCK

Scanner failure → BLOCK

Show editable controls.

Example table:

Condition
Severity
Action

Allow actions:

BLOCK
WARN
ALLOW

Add:

Save Policy
Reset Policy
Clone Policy

---

# 26. RISK ENGINE PAGE

Create a dedicated risk evaluation visualization.

Explain:

"The risk engine aggregates normalized security findings and evaluates them against organizational policy."

Show factors:

Severity
CVSS
Exploitability
Asset Criticality
Exposure
Finding Count
Scanner Confidence

Create a scoring visualization.

Example:

Overall Risk:
82

Critical:
+35

High:
+25

Exposure:
+12

Asset Criticality:
+10

Then:

Final Decision:
BLOCK

---

# 27. DEPLOYMENTS PAGE

Create:

Deployments

Show:

Application
Version
Environment
Commit
Pipeline
Risk
Security Decision
Deployment Status

Example:

SecureShop
v1.8.4
Production
8ad4e21
SCN-1024
82
BLOCK
Blocked

---

# 28. DEPLOYMENT DETAIL

Show:

Deployment Overview

Release:
SecureShop v1.8.4

Environment:
Production

Deployment status:

BLOCKED

Security gates:

Build — PASS
Secrets — PASS
SAST — FAIL
SCA — FAIL
Container — PASS
DAST — PASS

Final decision:

BLOCK

Reason:

Critical vulnerability violates production policy.

Button:

Re-run Security Pipeline

Do not provide a "Deploy Anyway" action without an explicit approval/override workflow.

---

# 29. REPORTS PAGE

Create:

Security Reports

Report cards:

Security Scan Report
Release Security Report
Compliance Report
Executive Security Summary
Pipeline Audit Report

Each report should show:

Project
Scan
Generated date
Risk
Decision

Actions:

View
Download
Generate

---

# 30. REPORT DETAIL

Create a professional report layout.

Include:

Executive Summary

Project information

Scan information

Security posture

Security gates

Findings summary

Critical findings

High findings

Risk score

Policy decision

Deployment decision

Remediation recommendations

Audit trail

Use charts and tables.

---

# 31. AUDIT LOGS

Create:

Audit Logs

Every important system action should appear here.

Examples:

GitHub repository connected
Security scan started
SAST completed
Critical vulnerability detected
Policy updated
Deployment blocked
Report generated
Finding marked resolved

Columns:

Timestamp
User
Action
Project
Resource
Result

Add filters.

---

# 32. NOTIFICATIONS

Create a notification center.

Examples:

Critical vulnerability detected
Production deployment blocked
Scan completed
GitHub workflow failed
Security policy updated

Severity-based notification styles.

---

# 33. GLOBAL SEARCH

Create a global search experience.

Search across:

Projects
Repositories
Scans
Findings
Reports
Deployments

Use keyboard shortcut:

Ctrl + K

---

# 34. RESPONSIVE DESIGN

The entire application must work on:

Desktop
Laptop
Tablet
Mobile

Desktop:

Persistent sidebar.

Tablet:

Collapsible sidebar.

Mobile:

Bottom navigation or collapsible menu.

Tables should become responsive cards on mobile.

Do not allow horizontal overflow wherever possible.

---

# 35. EMPTY STATES

Every page must have a professional empty state.

Examples:

"No projects yet."

"No security findings."

"No scans found."

"No repositories connected."

Include helpful CTA buttons.

---

# 36. LOADING STATES

Use skeleton loaders for:

Dashboard cards
Tables
Charts
Finding details
Project details

Do not freeze the interface.

---

# 37. ERROR STATES

Create professional error states.

Examples:

Scanner unavailable
GitHub connection failed
Invalid repository
Scan timeout
Docker build failed
Security tool failed
Backend unavailable

Show:

What happened
Why it happened
What the user can do

Actions:

Retry
View Logs
Contact Administrator

---

# 38. SECURITY UX

The product itself is security-focused.

Include:

- Session timeout indication
- Secure authentication UI
- Role-based access concept
- API token masking
- No plaintext secrets
- Confirmation before destructive operations
- Audit logging
- Permission indicators

Never display actual secrets.

---

# 39. ROLE-BASED UI

Support conceptual roles:

Admin
Security Analyst
Developer
Viewer

Example permissions:

Admin:
Everything

Security Analyst:
Findings
Scans
Policies
Reports

Developer:
Projects
Scans
Findings
Repositories

Viewer:
Dashboard
Reports
Findings

Show role information in user profile.

---

# 40. IMPORTANT INTERACTIONS

The prototype should feel functional.

Implement UI interactions for:

- Sidebar navigation
- Search
- Filtering
- Sorting
- Opening scan details
- Opening findings
- Opening projects
- New scan modal
- Source selection
- Upload field
- GitHub connection flow
- Pipeline stage expansion
- Policy editing
- Notification panel
- Report generation
- Re-running scans
- Deployment status
- Responsive sidebar

Use realistic mock data.

---

# 41. SCAN WORKFLOW

The UI must visually communicate this exact workflow:

USER
↓
Select Project
↓
Select Source
↓
Upload ZIP / GitHub / Authorized URL
↓
Configure Environment
↓
Select Security Policy
↓
Start Scan
↓
Backend Scan Orchestrator
↓
Security Tools
↓
Normalize Results
↓
Risk Engine
↓
Security Policy
↓
PASS / WARN / BLOCK
↓
Deployment Decision
↓
Report + Audit Log

---

# 42. DOCKER VISUALIZATION

Include Docker in the architecture.

Show:

Application Source
↓
Docker Build
↓
Container Image
↓
Trivy Scan
↓
Security Result

Explain in UI that Docker is used by the backend/CI infrastructure rather than requiring the user to manually keep Docker Desktop open.

Do NOT imply that the browser directly controls Docker.

---

# 43. GITHUB VISUALIZATION

Show:

GitHub Repository
↓
GitHub Actions
↓
CI/CD Pipeline
↓
SecureFlow Security Gates
↓
Risk Engine
↓
PASS / WARN / BLOCK
↓
Deployment

The frontend should display GitHub workflow status and results.

---

# 44. SECURITY GATE LOGIC

Clearly visualize:

IF no blocking findings
→ PASS

IF warning findings exist
→ WARN

IF critical/blocking findings exist
→ BLOCK

Example:

Critical CVE detected
+
Production policy = BLOCK critical
=
BLOCK RELEASE

---

# 45. DESIGN DETAILS

Use:

- 8–14px border radius
- 1px subtle borders
- Dense tables
- Compact cards
- Clear status colors
- Consistent icons
- Tooltips
- Hover states
- Focus states
- Accessible contrast

Avoid excessive whitespace.

The application should feel information-dense like a professional security operations platform.

---

# 46. SAMPLE DATA

Use realistic sample projects:

SecureShop
IoT Gateway API
Payments Service
Inventory API
Customer Portal

Sample scan:

SCN-1024

Project:
SecureShop

Source:
GitHub

Branch:
main

Commit:
8ad4e21

Risk:
82

Status:
BLOCKED

Findings:

1 Critical
2 High
4 Medium
8 Low

---

# 47. VISUAL HIERARCHY

Most important information:

1. Release decision
2. Risk score
3. Critical/high findings
4. Security gate status
5. Pipeline status
6. Deployment status
7. Detailed findings

The user should immediately understand:

"Is my application safe to deploy?"

---

# 48. PRIMARY USER JOURNEY

Design the product around this journey:

User logs in
↓
Dashboard
↓
Create Project
↓
Connect GitHub
↓
Configure Pipeline
↓
Push code
↓
CI/CD starts
↓
Security gates execute
↓
Findings are collected
↓
Risk score generated
↓
Security policy evaluated
↓
PASS / WARN / BLOCK
↓
Deployment proceeds or stops
↓
Report generated
↓
Audit log recorded

---

# 49. FINAL DESIGN REQUIREMENT

Generate ALL major screens required for a complete product.

At minimum create:

1. Login
2. Dashboard
3. Projects
4. Project Detail
5. Repositories
6. GitHub Connection
7. Pipeline
8. Scans
9. Scan Detail
10. New Scan
11. Scan Running
12. Findings
13. Finding Detail
14. Security Policy
15. Risk Engine
16. Deployments
17. Deployment Detail
18. Reports
19. Report Detail
20. Audit Logs
21. Notifications
22. User/Profile
23. Settings
24. Error States
25. Empty States

---

# 50. FINAL PRODUCT FEEL

The final website should communicate:

"Enterprise DevSecOps Security Control Center"

It should look capable of being used by:

- Software developers
- DevOps engineers
- Security engineers
- Security analysts
- DevSecOps teams
- Engineering managers

It should NOT look like:

- A simple vulnerability scanner
- A basic student dashboard
- A generic CRUD application
- A landing page
- A toy cybersecurity website

The primary goal is to create a **complete, professional, security-first DevSecOps platform interface** whose frontend can later be connected to a real backend API, GitHub, GitHub Actions, Docker, security scanners, database, risk engine, and deployment infrastructure.

Make the UI coherent across all screens, maintain the same design system, use realistic cybersecurity data, and make every important interaction visually understandable.