# Cross Domain Login
# Cross Domain Login is a WordPress plugin that enables seamless single sign-on (SSO) across multiple domains. It allows users to log in once on one domain and automatically authenticate on other configured domains without needing to re-enter credentials.

# Features
Cross-Domain Authentication: Automatically logs users into multiple domains using secure token-based redirects.
Configurable Domains: Admins can specify up to five domains in the settings for cross-domain login.
Secure Token Handling: Uses SHA-256 hashed tokens with a 5-minute expiration for safe authentication.
HTTPS Support: Ensures redirects occur over secure connections for enhanced security.
Admin-Friendly Settings: Simple interface in WordPress admin to manage domains with validation for unique and valid entries.
Debug Logging: Detailed logs (when WP_DEBUG is enabled) for troubleshooting and monitoring.
Lightweight and Efficient: Minimal performance impact with clean, modern PHP code.

Ensure all domains use HTTPS for secure token transmission.
Server logs should be secured to prevent token exposure.
For support, contact the author at vladyslav10111@gmail.com.
