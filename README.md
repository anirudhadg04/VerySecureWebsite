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

For comprehensive testing, use:

```bash
# Authentication and authorization tests
python -m pytest test_validate.py -v

# BOLA/IDOR and BFLA validation
python -m pytest test_bola_bfla.py -v

# XSS browser validation
python xss_browser_test.py
```
