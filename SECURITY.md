# Security Policy

## Supported Versions

Currently, the following versions of macFIRE are supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :x:                |

## Security Considerations

macFIRE is a forensic acquisition tool designed to handle potentially sensitive data. Please consider the following security aspects when using this tool:

1. **Root/Administrative Access**: The tool requires root privileges to collect many artifacts. Always run it with the minimum necessary privileges for your specific task.

2. **Data Sensitivity**: Data collected by macFIRE may contain sensitive information. Ensure proper handling of all collected artifacts according to your organization's data protection policies.

3. **Chain of Custody**: When using macFIRE for formal investigations, maintain appropriate chain of custody procedures beyond what the tool automatically documents.

4. **Local Operation**: All processing occurs locally on the machine running macFIRE. No data is transmitted to external servers.

5. **Output Security**: Secure all output directories containing forensic artifacts and reports, as they may contain sensitive system and user information.

## Reporting a Vulnerability

We take the security of macFIRE seriously. If you believe you've found a security vulnerability, please follow these steps:

1. **Do Not Disclose Publicly**: Please do not disclose the vulnerability publicly until it has been addressed.

2. **Create a Security Advisory**: Report the vulnerability through GitHub's Security Advisory feature or directly to the maintainers at riyan.pratama@security-life.org (replace with your actual security contact).

3. **Include Details**: Provide as much information as possible, including:
   - A clear description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact
   - Suggested fixes (if any)

4. **Response Time**: We aim to acknowledge receipt of vulnerability reports within 48 hours and will provide an estimated timeline for a fix based on severity.

5. **Recognition**: We're happy to acknowledge your contribution in our release notes if desired.

## Security Best Practices When Using macFIRE

1. **Verify Downloads**: Always verify the integrity of macFIRE downloads by checking the provided SHA-256 hashes.

2. **Keep Updated**: Use the latest version of macFIRE to benefit from security patches and improvements.

3. **Isolated Environment**: When possible, run macFIRE on isolated networks, especially when processing potentially compromised systems.

4. **Review Output**: Always review the generated reports and logs for sensitive information before sharing them.

5. **Secure Storage**: Store disk images and artifact collections securely, preferably encrypted when at rest.

6. **User Access Control**: Limit access to macFIRE outputs to authorized personnel only.

## Dependency Security

macFIRE relies primarily on Python standard libraries and native macOS commands, minimizing external dependencies. However:

1. We regularly review and update any dependencies that may be added in the future.

2. We use GitHub's Dependabot to monitor for security issues in dependencies.

3. We recommend using virtual environments when running macFIRE to isolate dependencies.

## Secure Development Practices

The macFIRE development team follows these security practices:

1. Code reviews for all changes
2. Regular security audits of the codebase
3. Testing in various environments before release
4. Verification of all external commands executed by the tool
5. Proper error handling to prevent information leakage

## Attribution

When security vulnerabilities are fixed, we will provide credit to the reporter (if desired) in the release notes and/or commit messages.

## Changes to This Policy

This security policy may be updated from time to time. When significant changes are made, we will update the version number and date below.

Version: 1.0  
Last Updated: April 1, 2025
