# VerySecureWebsite - Security Lab Application

An intentionally vulnerable web application for learning application security testing.

## Quick Links

[Enter Security Labs](/labs)

## About

This application contains intentionally vulnerable endpoints to teach security concepts:

- **BOLA/IDOR** - Broken Object Level Authorization
- **BFLA** - Broken Function Level Authorization  
- **XSS** - Cross Site Scripting

> **Note**: The vulnerable endpoints remain intentionally vulnerable for educational purposes.
> Secure versions are available under `/secure/` paths for safe testing.

## Security Research

The application demonstrates common web application security vulnerabilities:

- **Authorization flaws** allowing unauthorized data access
- **Injection vulnerabilities** including XSS attacks
- **Missing access controls** exposing sensitive functionality
- **Improper session management** and authentication issues

## Educational Purpose

This is a local security lab application designed for:

- Learning about common vulnerability types
- Understanding exploitation techniques
- Practicing secure coding practices
- Conducting security assessments

## Getting Started

1. Visit the `/labs` page to start a lab
2. Complete each lab to understand vulnerability mechanics
3. Review the documentation for each vulnerability type
4. Practice fixing the vulnerabilities in secure versions

## Security Testing

Run the maintained isolated verifier tests:

```powershell
python -m pytest tests -v
```

The broader legacy modules are retained for their existing BOLA/BFLA and authentication coverage. `test_bola_bfla.py` drops and recreates the configured tables in its module setup, so run it only in a disposable project/database copy:

```powershell
python -m pytest test_bola_bfla.py test_validate.py -v
```

For the current browser-based learner workflows and exact manual steps, see [docs/LAB_SOLVING_AUDIT.md](docs/LAB_SOLVING_AUDIT.md). The optional Selenium script `xss_browser_test.py` uses port 8000 and requires Chrome/ChromeDriver; use an unused port and a disposable database when running it.
