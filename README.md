# SecureAuth: AI-Powered Multi-Factor Authentication

SecureAuth is a conceptual Multi-Factor Authentication (MFA) application that leverages machine learning and risk-based authentication (RBA) to dynamically adapt security friction based on user behavior.

## Machine Learning Engine

The core of SecureAuth is a Risk-Based Authentication engine powered by a Scikit-Learn `DecisionTreeClassifier`. The model evaluates eight distinct behavioral features in real-time to generate a risk score (Low, Medium, or High) for every login attempt.

The behavioral features analyzed include:
*   Consecutive failed password attempts
*   Short time intervals between login attempts (indicating automated scripts)
*   Unrecognized device fingerprints
*   Login attempts at historically unusual hours
*   Incorrect password submissions
*   Exhaustion of OTP resend limits
*   Login attempts from unusual geographical locations
*   Usage of anonymous IP addresses (VPNs or Proxies)

The model is trained on synthetically generated logs to establish baseline thresholds for legitimate versus anomalous authentication behavior.

## Security Mitigations & Dynamic Flow

Rather than enforcing a static MFA policy for every login, SecureAuth applies friction dynamically based on the ML engine's risk assessment.

*   **Low Risk (Frictionless Login):** Users with correct credentials logging in from recognized devices under normal conditions bypass the OTP requirement entirely, streamlining the user experience.
*   **Medium Risk (Step-Up Authentication):** When an anomaly is detected (such as an unknown device, an unusual location, or an anonymous IP), the login flow is interrupted. The user receives a specific inline warning and must successfully verify an OTP to proceed.
*   **High Risk (Temporal Lockout):** If the system detects overt malicious behavior, such as a brute-force attack (5+ failed logins) or a combination of severe anomalies, the account is temporarily blocked for 60 seconds.
*   **Passwordless Fallback:** If a user fails their password 3 consecutive times, the system gracefully degrades to a passwordless OTP-only fallback, allowing legitimate users who forgot their password to recover access securely.
*   **Automated Bot Protection:** After 2 failed attempts, a reCAPTCHA challenge is dynamically injected into the login form to mitigate automated credential stuffing.
*   **Rate Limiting:** Users are strictly limited to a maximum of 2 OTP resend requests. Exceeding this limit triggers an immediate High Risk lockout.

## Test Users

The application is pre-configured with the following test accounts:

**User 1**
*   Username: `stud1`
*   Password: `stud123`
*   Known Device: `device-01`

**User 2**
*   Username: `stud2`
*   Password: `stud234` (or `123` depending on local setup)
*   Known Device: `device-02`
