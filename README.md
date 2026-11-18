# SentraX Security Hub

Build a professional cybersecurity SaaS platform called "SentraX".

Brand:

SentraX is an AI-powered cybersecurity risk assessment platform that helps small businesses discover security weaknesses, understand their cyber risk, and improve their protection.

Main goal:

Create a functional MVP that looks like a real cybersecurity startup product.

The application must be built with clean scalable architecture so the code can later be exported and self-hosted.

Design:

- Premium cybersecurity enterprise style

- Dark modern interface

- Professional SOC (Security Operations Center) inspired dashboard

- Responsive design for desktop and mobile

- Smooth animations but keep performance fast

Create these pages:

1. Landing Page

Hero:

Title:

"See Your Cyber Risk Before Attackers Do"

Subtitle:

"SentraX helps businesses analyze their security posture, identify risks, and receive actionable security recommendations."

Buttons:

- Start Security Assessment

- Explore Dashboard

Sections:

- How SentraX Works

- Features

- Why Businesses Need Cybersecurity

- Security Score Explanation

- Pricing section placeholder

- About SentraX

2. Authentication

Create:

- Register

- Login

- Forgot Password

Use Supabase authentication.

3. User Dashboard

Create a professional security dashboard.

Include:

Security Score:

Example:

85/100

Risk Level:

Low / Medium / High

Dashboard cards:

- Total Scans

- Vulnerabilities Found

- Security Improvements

- Recent Activity

Buttons:

- New Assessment

- View Reports

4. Security Assessment System

Create a page where users can submit:

- Company Name

- Website URL

Create a scanning workflow interface:

Steps:

- Website Analysis

- SSL/TLS Check

- Security Headers Check

- Technology Detection

- Risk Evaluation

For the MVP, generate realistic demo findings.

Example findings:

- Missing security headers

- Weak configuration

- Outdated technology detection

- SSL issues

5. Security Reports

Create professional cybersecurity reports.

Report structure:

- Executive Summary

- Security Score

- Risk Rating

- Findings

- Impact Explanation

- Recommendations

Allow:

- View Report

- Download Report button placeholder

6. User Profile

Include:

- Account information

- Company details

- Security preferences

7. Database

Use Supabase.

Create database structure:

Users:

- id

- name

- email

- created_at

Companies:

- id

- user_id

- company_name

- website

Assessments:

- id

- company_id

- security_score

- risk_level

- created_at

Findings:

- id

- assessment_id

- title

- severity

- description

- recommendation

Reports:

- id

- assessment_id

- content

- created_at

Important:

Make the app architecture ready for future integrations:

- OWASP ZAP

- Nmap

- AI security analysis

- Automated vulnerability scanning

- Threat intelligence APIs

Do not create only a landing page.

Create a real SaaS MVP with working navigation, authentication structure, dashboard, database connection, and clean reusable components.

The final code should be organized and easy to export for self-hosting later.

This project was built with [Lovable](https://lovable.dev).

**Live app**: https://sentrax.lovable.app

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/e4c442d1-23b0-4642-8620-1052a3cbccb5).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
