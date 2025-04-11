# Security Policy

## Supported Versions

This project adheres to a continuous deployment model, and security updates are applied to the latest release. We recommend always using the most recent version.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < latest| :x:                |

## Reporting a Vulnerability

The security of our Azure Sentinel Enterprise deployment is a top priority. If you discover a security vulnerability, please follow these steps:

1. **Do Not** disclose the vulnerability publicly until it has been addressed.
2. Submit the vulnerability report to our security team by emailing [security@yourcompany.com](mailto:security@yourcompany.com).
3. Include detailed information about the vulnerability:
   - Description of the issue
   - Steps to reproduce
   - Potential impact
   - Any suggested mitigations if known

### What to Expect
- Acknowledgment of your report within 48 hours
- Assessment of the vulnerability by our team
- Regular updates on the progress towards resolution
- Credit for responsible disclosure (if desired)

## Security Best Practices

When implementing this Sentinel architecture, please follow these security recommendations:

1. Use managed identities for Azure resources whenever possible
2. Implement least-privilege RBAC roles for all stakeholders
3. Secure all storage accounts with appropriate network controls
4. Enable Customer-Managed Keys for encryption
5. Use Private Link for all service connections
6. Review security configurations and access regularly
7. Implement Microsoft Defender for Cloud with enhanced security features

Thank you for helping keep our Azure Sentinel implementations secure!
