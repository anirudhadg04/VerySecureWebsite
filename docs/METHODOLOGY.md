# VerySecureWebsite - Methodology Documentation

> **Historical methodology baseline:** The examples and counts below record an earlier validation phase. For current learner workflows and results, see [LAB_SOLVING_AUDIT.md](LAB_SOLVING_AUDIT.md) and [LAB_DISCOVERABILITY_AUDIT.md](LAB_DISCOVERABILITY_AUDIT.md).

## Testing Approach

This document describes the methodology used to validate security findings in the VerySecureWebsite application.

## Validation Categories

### Confirmed through Code Review

Findings supported by source code inspection but not independently reproduced through automated testing.

**Criteria**:
- Source code contains the vulnerability pattern
- Code review confirms the weakness exists
- No automated test executed to verify the behavior

**Examples from this project**:
- VUL-003 (XSS): Lab design confirmed through code review of `app/templates/xss_lab.html` and `app/main.py:461-469`

### Reproduced Manually

Findings independently reproduced through manual testing with separate authenticated sessions.

**Criteria**:
- Test executed with two different user sessions (e.g., Alice and Bob)
- Unauthorized access demonstrated
- Evidence captured from test output

**Examples from this project**:
- VUL-001 (BOLA/IDOR): Alice reads/modifies/deletes Bob's records
- VUL-002 (BFLA): Alice accesses admin endpoints

### Verified through Automated Tests

Findings confirmed by the automated test suite (`test_bola_bfla.py`).

**Criteria**:
- Test passes with pytest
- Test output captured and documented
- Test evidence included in finding report

**Examples from this project**:
- VUL-001: 4/4 BOLA tests pass
- VUL-002: 2/2 BFLA tests pass

### Not Yet Validated (at the time of this report)

Findings that have not been fully tested due to environment limitations or incomplete implementation.

**Criteria**:
- Test not executed or incomplete
- Environment limitations prevent full validation
- Implementation not complete

**Examples from this project**:
- VUL-003 (XSS): Browser-based payload execution not possible in this environment
- Lab completion mechanism: Server startup issues prevented full integration testing
- Session management edge cases: Not yet tested

## Test Environment

### Technology Stack

- **Backend**: Python 3.14.7, FastAPI 0.141.1
- **Database**: SQLite with SQLAlchemy 2.1.2 ORM
- **Testing**: pytest 9.1.1, FastAPI TestClient
- **Password Hashing**: bcrypt 5.0.0

### Test Data

All tests use synthetic data only:

| User | Role | Password |
|------|------|----------|
| alice | user | alice123 |
| bob | user | bob123 |
| admin | admin | admin123 |

| Record ID | Title | Owner |
|-----------|-------|-------|
| 1 | Alice's Medical Record | alice |
| 2 | Alice's Financial Report | alice |
| 3 | Bob's Medical Record | bob |
| 4 | Bob's Financial Report | bob |

### Test Execution

Tests are executed using the FastAPI TestClient, which does not require a running server:

```bash
python -m pytest test_bola_bfla.py -v
```

**Test Results**: 8 passed, 1 warning (StarletteDeprecationWarning about httpx)

## Validation Limitations

### Known Limitations

1. **No browser-based testing**: XSS payload execution cannot be verified in this environment
2. **No running server tests**: All tests use FastAPI TestClient; integration with a running server not performed
3. **Single connection scenario**: Tests do not simulate concurrent users or race conditions
4. **PowerShell environment issues**: Server startup in PowerShell environment had connection issues; tests used TestClient instead
5. **Limited scope**: Only 3 vulnerability classes tested (BOLA, BFLA, XSS design); other categories not yet validated

### What Tests Do Not Establish

- A passing test does not prove the entire vulnerability class is fully tested
- A passing test does not prove a real-world security assessment is complete
- A passing test does not prove the application is secure in production
- A passing test only establishes what its assertions actually test

## Security Principles

### BOLA/IDOR (VUL-001)

**Concept**: Broken Object Level Authorization occurs when an application does not properly verify that the authenticated user has permission to access a specific object (record, file, resource).

**Application Logic**: The `/records/{record_id}` endpoint retrieves a record by ID without checking if the current user owns that record.

**Weakness**: The SQL query `db.query(Record).filter(Record.id == record_id).first()` retrieves any record regardless of owner.

**Tester Recognition**: Any authenticated user can access another user's records by changing the record ID in the URL.

**Validation**: Alice (user) accesses Bob's record (ID 3) → returns Bob's data → BOLA confirmed.

**Prevention**: Add ownership check: `filter(Record.id == record_id, Record.owner_id == current_user.id)`.

**Common Mistakes**:
- Assuming authentication is sufficient authorization
- Not checking resource ownership on every request
- Relying on client-side access controls

### BFLA (VUL-002)

**Concept**: Broken Function Level Authorization occurs when an application does not properly enforce role-based access controls on functions or endpoints.

**Application Logic**: The `/admin/users` and `/admin/debug` endpoints return sensitive data to any authenticated user, regardless of role.

**Weakness**: No `current_user.role == "admin"` check before returning admin data.

**Tester Recognition**: Regular user accesses `/admin/users` → returns all users including admin → BFLA confirmed.

**Validation**: Alice (user) accesses `/admin/users` → returns all 3 users → BFLA confirmed.

**Prevention**: Add role check: `if current_user.role != "admin": raise HTTPException(status_code=403)`.

**Common Mistakes**:
- Assuming all authenticated users have the same privileges
- Not enforcing role checks on admin endpoints
- Relying on URL obscurity for security

## Related Vulnerability Classes

- **CWE-639**: Authorization Bypass Through User-Controlled Key (BOLA/IDOR)
- **CWE-863**: Incorrect Authorization (BFLA)
- **CWE-79**: Cross-Site Scripting (XSS)
- **CWE-89**: SQL Injection
- **CWE-78**: OS Command Injection
- **CWE-22**: Path Traversal
- **CWE-521**: Weak Password Requirements

## Interview Questions

For each finding, the following questions should be answerable:

### VUL-001 (BOLA/IDOR)

1. What is BOLA/IDOR and how does it differ from authentication bypass?
2. Why is ownership validation necessary on every resource access?
3. How would you test for BOLA in a REST API?
4. What is the difference between horizontal and vertical privilege escalation?
5. How does the `owner_id` foreign key relate to the authorization check?

### VUL-002 (BFLA)

1. What is BFLA and how does it differ from BOLA?
2. Why should admin endpoints require role-based access control?
3. How would you test for BFLA in a web application?
4. What is the difference between authentication and authorization?
5. How does the `role` field on the User model enable BFLA?

## Methodology Limitations

This methodology is designed for a local security research lab, not a production security assessment. Key limitations:

- No external target testing
- No automated vulnerability scanning
- No production environment validation
- No real user data involved
- All findings are based on synthetic test data

## References

- OWASP Top 10 2021: A01 - Broken Access Control
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-863: Incorrect Authorization
- CWE-79: Cross-Site Scripting
- PortSwigger Web Security Academy (learning platform inspiration)

---
*This methodology is part of the VerySecureWebsite security research lab. All data is synthetic and isolated to the local development environment.*