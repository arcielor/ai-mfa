# Test Cases Sorted by Risk

This document organizes the AI/ML-Enhanced MFA System test cases by their associated risk level. It reflects the latest Dynamic Risk-Based Authentication workflows.

## 🔴 High Risk

| Test ID | Test Category | Objective / Description | Test Steps | Expected Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **TC-4.2** | AI/ML Risk Scoring | Rate limiting block on brute-force (High Risk) | 1. Submit wrong passwords 5 times consecutively. | The 5th attempt triggers a **🔴 HIGH RISK** block, rendering the `/blocked` template showing a 60-second lock-out timer. |
| **TC-4.8** | Rate Limiting | OTP Resend Limit Block | 1. Reach the `/otp` page. <br>2. Let the timer expire and click **Resend OTP** twice. <br>3. Attempt to click it a third time. | The user's risk level is escalated to **🔴 HIGH RISK**, and they are locked out for 60 seconds with a block page. |

## 🟡 Medium Risk (Triggers OTP Challenge)

| Test ID | Test Category | Objective / Description | Test Steps | Expected Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **TC-4.1** | AI/ML Risk Scoring | Unknown device anomaly | 1. Enter correct credentials. <br>2. Enter a custom Device ID (e.g., `unknown-laptop`). <br>3. Click **Authenticate**. | The login pauses with an inline error: `Unusual behaviour detected. [Send OTP]`. Clicking the button triggers an OTP challenge (🟡 Medium Risk). |
| **TC-4.3** | AI/ML Risk Scoring | Geolocation / Impossible Travel | 1. Use the "Spoof IP" demo tool. <br>2. Enter a foreign IP address (e.g. `1.1.1.1` for Australia). <br>3. Click **Authenticate** with correct credentials. | The login pauses with an inline error: `Unusual behaviour detected. [Send OTP]`. Clicking the button triggers an OTP challenge (🟡 Medium Risk). |
| **TC-4.4** | AI/ML Risk Scoring | Anonymous IP / VPN / Proxy | 1. Use the "Spoof IP" demo tool. <br>2. Enter a known Tor Exit Node IP (e.g. `185.220.101.1`). <br>3. Click **Authenticate** with correct credentials. | The login pauses with an inline error: `Unusual behaviour detected. [Send OTP]`. Clicking the button triggers an OTP challenge (🟡 Medium Risk). |
| **TC-4.5** | AI/ML Risk Scoring | Unusual Login Hour | 1. Use the "Spoof Time" demo tool. <br>2. Change the hour to `3` (3:00 AM). <br>3. Click **Authenticate** with correct credentials. | The login pauses with an inline error: `Unusual behaviour detected. [Send OTP]`. Clicking the button triggers an OTP challenge (🟡 Medium Risk). |
| **TC-4.7** | Passwordless Fallback | 3 Failed Attempts Trigger | 1. Enter the *wrong* password 3 times. | The inline error appends `[Login with OTP]`. Clicking it bypasses the password requirement and forces a Medium Risk OTP verification. |

## 🟢 Low / Standard Risk (Bypasses OTP)

| Test ID | Test Category | Objective / Description | Test Steps | Expected Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **TC-1.2** | Hashed Password | Rejection of incorrect password | 1. Enter incorrect password. <br>2. Click **Authenticate**. | Page reloads displaying the error: `Invalid credentials. Risk: LOW \| Attempt 1/5`. |
| **TC-4.6** | Dynamic MFA | OTP Bypass on Safe Login | 1. Leave spoofing tools at defaults. <br>2. Use a known Device ID and the correct password. <br>3. Click **Authenticate**. | User entirely bypasses the `/otp` screen and is immediately redirected to `/success` due to a 🟢 Low Risk score. |
| **TC-2.1** | Google reCAPTCHA | reCAPTCHA widget display trigger | 1. Perform 3 consecutive failed login attempts. | On the 3rd failed attempt, the **Google reCAPTCHA checkbox widget** renders right above the "Authenticate" button. |
| **TC-2.2** | Google reCAPTCHA | Block submission without checking checkbox | 1. With reCAPTCHA visible, click **Authenticate** *without* checking the box. | Submission is blocked, showing a warning: `Please complete the reCAPTCHA verification.` |
| **TC-3.1** | OTP & Countdown | OTP verification success | 1. Reach the `/otp` page (via a Medium Risk scenario). <br>2. Copy the OTP into the field. <br>3. Click **Verify OTP**. | Redirection to the Success page displaying: `Authentication Successful`. |
| **TC-3.2** | OTP & Countdown | OTP countdown timer ticks down | 1. Reach the `/otp` page. <br>2. Observe the timer widget. | The clock counts down correctly from 15 seconds. |
| **TC-3.3** | OTP & Countdown | OTP expiration behavior | 1. On the `/otp` page, wait for 15 seconds. | The timer hits `00:00`, displays `Expired` in red, disables inputs, masks the Demo OTP to `******`, and reveals the "Resend OTP" button. |
| **TC-5.1** | Auditing & Logs | Client tracking capture | 1. Navigate to `/logs`. | The logged entry shows the exact IP address, device, threat indicators (consolidated into a dynamic `Flags` column), risk level, and action taken. |
