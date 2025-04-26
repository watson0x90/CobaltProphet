# COBALT PROPHET

![Azure](https://img.shields.io/badge/Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![Version](https://img.shields.io/badge/Version-1.0.0-blue)
![License](https://img.shields.io/badge/License-MIT-green)

COBALT PROPHET is a comprehensive PowerShell-based tool for Azure cloud environment enumeration and reconnaissance, designed specifically for red team operations and security assessments.

## Overview

COBALT PROPHET enables security professionals to efficiently gather intelligence about Azure environments using only Azure Management API endpoints. The tool maps accessible resources, identifies permissions, discovers security weaknesses, and generates detailed reports to support informed security assessments.  

**NOTE**: It is important to note that this will enumerate and provide information back for the TOKEN provided. 

![COBALT PROPHET](imgs/image.png)

## Features

### Core Enumeration Capabilities

- **Subscription Discovery**: Identifies accessible Azure subscriptions
- **Resource Mapping**: Enumerates resource groups and resources
- **Identity Analysis**: Discovers managed identities and permission configurations
- **High-Value Target Identification**: Locates key vaults, storage accounts, VMs, and more

### Advanced Security Assessment

- **Permission Testing**: Identifies privilege escalation paths and excessive permissions
- **Security Misconfiguration Detection**: Discovers exposed storage accounts and weak access controls
- **Network Security Analysis**: Maps NSGs and public IP addresses
- **Secret Management Evaluation**: Tests access to storage account keys and connection strings

### Comprehensive Reporting

- **CSV Data Export**: All findings are exported to structured CSV files
- **Interactive HTML Reports**: Generates rich, interactive reports with search and filtering
- **Markdown Reports**: Creates lightweight reports for quick review and sharing
- **Security Findings Summary**: Highlights high-value findings and potential security issues

## Installation

### Prerequisites

- PowerShell 5.1 or higher
- Azure subscription access (token required)
- Optional: MSAL.PS module for token acquisition

### Installation Steps

```powershell
# Clone the repository
git clone https://github.com/watson0x90/cobalt-prophet.git
cd cobalt-prophet

# Import the module
Import-Module .\CobaltProphet.ps1
```

## Usage

### Basic Usage

```powershell
# Get a token (requires MSAL.PS module)
$token = Get-AzureToken
Start-AzureEnumeration -Token $token

# Run basic enumeration with token in JWT Format
Start-AzureEnumeration -Token "eyJ0eX..."
```

### Advanced Usage

```powershell
# Comprehensive enumeration with HTML report only
Start-AzureEnumeration -Token $token -Comprehensive -ReportFormat "HTML"

# Targeted enumeration with custom output directory
Start-AzureEnumeration -Token $token -OutputDirectory "C:\AzureAudit" -ReportFormat "Both"

# Quick data collection without report generation, output csv only
Start-AzureEnumeration -Token $token -ReportFormat "None"
```

### Individual Function Usage

COBALT PROPHET provides modular functions that can be used individually:

```powershell
# Get all storage accounts in a subscription
$storageAccounts = Get-AzureStorageAccounts -Token $token -SubscriptionID "your-subscription-id"

# Check for storage accounts with anonymous access
$publicStorage = Get-AzureStorageAccountsWithAnonymousAccess -Token $token -SubscriptionID "your-subscription-id"

# Test permissions on a specific resource
$permissions = Test-AzureResourceActions -Token $token -ResourceID "/subscriptions/your-subscription-id/resourceGroups/your-rg/providers/Microsoft.KeyVault/vaults/your-keyvault"
```

## Function Reference

| Function | Description |
|----------|-------------|
| `Start-AzureEnumeration` | Main function to perform comprehensive enumeration |
| `Get-AzureSubscriptionID` | Discovers accessible Azure subscriptions |
| `Get-AzureResourceList` | Lists all resources in a subscription |
| `Get-AzureResourceGroups` | Lists all resource groups in a subscription |
| `Get-AzureVirtualMachines` | Enumerates virtual machines |
| `Get-AzureKeyVaults` | Enumerates key vaults |
| `Get-AzureStorageAccounts` | Enumerates storage accounts |
| `Get-AzureStorageAccountsWithAnonymousAccess` | Identifies public storage accounts |
| `Test-AzureResourceActions` | Tests permissions on Azure resources |
| `Get-AzureResourcePermissions` | Gets permissions for a specific resource |
| `Get-AzureNetworkSecurityGroups` | Lists network security groups |
| `Get-AzurePublicIPAddresses` | Lists public IP addresses |
| `New-AzureEnumerationMarkdownReport` | Generates markdown reports |
| `New-AzureEnumerationHtmlReport` | Generates HTML reports |

## Report Examples

### HTML Report

The HTML report provides interactive features:
- Global search functionality
- Table filtering
- Color-coded security findings
- Full-detail views of large datasets
- Mobile-friendly responsive design

### Markdown Report

The markdown report offers:
- Lightweight format viewable in any text editor
- Table of contents for easy navigation
- Summarized findings for quick review
- Links to detailed data reports

## Use Cases

- **Security Assessments**: Evaluate Azure environments for security weaknesses
- **Red Team Operations**: Map attack surfaces and identify privilege escalation paths
- **Penetration Testing**: Discover potential entry points and security misconfigurations
- **Security Compliance**: Audit Azure environments against security best practices
- **Security Posture Evaluation**: Assess the overall security posture of Azure deployments

## Operational Security Considerations

COBALT PROPHET is designed with operational security in mind:
- Minimal API calls to reduce detection footprint
- Option for lightweight markdown reports to avoid browser activity
- Structured output for easy integration with other tools
- Avoids unnecessary or potentially detectable operations

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

COBALT PROPHET is intended for authorized security testing and assessment only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before conducting security assessments.
---

