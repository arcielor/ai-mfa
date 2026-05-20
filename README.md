# AI/ML-Enhanced Multi-Factor Authentication (MFA)

This repository contains a secure authentication prototype that integrates **Machine Learning (ML) behavioral scoring** with **Multi-Factor Authentication (MFA)** to detect and mitigate password guessing attacks in real-time.

---

## 🧠 What ML is Used?

The system uses a **Decision Tree Classifier** (implemented via `scikit-learn` in [ml_engine.py](file:///d:/UNIMAS/UNI%20SEM%208/CS/vercel/ml_engine.py)) to evaluate login threats.

### 📊 Input Features
The ML engine evaluates **5 behavioral features** for every login attempt:
1. **`failed_attempts`**: The number of consecutive failed login attempts for the username.
2. **`short_interval`** (Binary: `0` or `1`): Detects if the login attempt occurred within 5 seconds of the previous attempt (indicates automated scripting).
3. **`unknown_device`** (Binary: `0` or `1`): Detects if the provided `device_id` does not match the user's pre-registered `known_device` in `users.json`.
4. **`unusual_hour`** (Binary: `0` or `1`): Detects if the login attempt is happening during off-peak/night hours (between 12 AM and 5 AM).
5. **`password_match`** (Binary: `0` or `1`): Detects whether the entered password is correct.

### 🛡️ Threat & Mitigation Response
Based on the threat features, the ML model classifies the login attempt into one of three risk levels:
*   **🟢 LOW RISK**: The user proceeds to standard MFA (OTP) verification immediately.
*   **🟡 MEDIUM RISK**: The system enforces a **3-second delay** (to slow down automated dictionary attacks) before presenting the MFA prompt.
*   **🔴 HIGH RISK**: The attempt is immediately blocked, and the account is locked for **60 seconds** to mitigate active attacks.

---

## 🔑 What MFA is Used?

The Multi-Factor Authentication layer uses a dynamic **One-Time Password (OTP)** mechanism:
*   **Generation**: The system generates a random 6-digit numeric code on successful password verification (shown on the MFA screen for demo purposes).
*   **Expiry**: The OTP is valid for **300 seconds** (5 minutes). Once verified, the session is authenticated.
*   **Verification**: Implemented dynamically in [app.py](file:///d:/UNIMAS/UNI%20SEM%208/CS/vercel/app.py) via `/otp`.

---

## 🧪 Test Accounts (`users.json`)

You can test the system manually using these credentials:
*   **User 1**: `stud1` / Password: `stud123` / Known Device: `device-01`
*   **User 2**: `stud2` / Password: `stud234` / Known Device: `device-02`

*Tip: Type a different Device ID (e.g. `device-xyz`) to trigger the "Unknown Device" anomaly and observe the elevated ML risk assessment.*
