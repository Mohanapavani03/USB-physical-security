# USB-physical-security
Implemented a secure authentication system with SHA-256 password hashing to protect user credentials from plain-text exposure.

Designed a JSON-based user database with admin approval workflow to ensure controlled access.

Integrated temporary password generation and email delivery for new user onboarding and recovery.

Enforced role-based access control, allowing only authorized administrators to modify USB security settings.

External (need to install with pip):

pywin32 → To work with Windows Registry & system-level APIs

pip install pywin32


wmi → For detecting USB devices (via Windows Management Instrumentation)

pip install wmi


opencv-python → For webcam recording (intruder detection)

pip install opencv-python
