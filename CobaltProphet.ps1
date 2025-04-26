<#
.SYNOPSIS
COBALT PROPHET - Azure Cloud Enumeration Tool

.DESCRIPTION
A comprehensive PowerShell module for Azure environment enumeration during red team operations.
This tool uses Azure REST APIs to enumerate resources, permissions, configurations, and potential security weaknesses.
Focused exclusively on management.azure.com endpoints.

.NOTES
Author: Ryan Watson (watson0x90)
Version: 1.0.0
Requires: PowerShell 5.1 or higher
#>

# Base Azure Functions
function Get-SubscriptionID {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token
    )
    $URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    try {
        $subs = (Invoke-RestMethod @RequestParams).value
        Write-Host "[+] Found $($subs.Count) accessible subscriptions" -ForegroundColor Green
        return $subs
    }
    catch {
        Write-Error "[-] Failed to retrieve subscriptions. Error: $_"
        return $null
    }
}

function Get-AzureResourceList {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/resources?api-version=2020-10-01"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    try {
        $resources = (Invoke-RestMethod @RequestParams).value
        Write-Host "[+] Found $($resources.Count) resources in subscription $SubscriptionID" -ForegroundColor Green
        return $resources
    }
    catch {
        Write-Error "[-] Failed to retrieve resources in subscription $SubscriptionID. Error: $_"
        return $null
    }
}

function Get-AzureResourcePermissions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceID
    )
    $URI = "https://management.azure.com/$ResourceID/providers/Microsoft.Authorization/permissions?api-version=2015-07-01"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    try {
        $permissions = (Invoke-RestMethod @RequestParams).value
        Write-Host "[+] Successfully retrieved permissions for resource $ResourceID" -ForegroundColor Green
        return $permissions
    }
    catch {
        Write-Warning "[-] Failed to retrieve permissions for resource $ResourceID. Error: $_"
        return $null
    }
}

function Get-AzureRoleAssignments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceID
    )
    $URI = "https://management.azure.com/$ResourceID/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    try {
        $roleAssignments = (Invoke-RestMethod @RequestParams).value
        Write-Host "[+] Found $($roleAssignments.Count) role assignments for resource $ResourceID" -ForegroundColor Green
        return $roleAssignments
    }
    catch {
        Write-Warning "[-] Failed to retrieve role assignments for resource $ResourceID. Error: $_"
        return $null
    }
}

function Get-AzureResourceGroups {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/resourcegroups?api-version=2021-04-01"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    try {
        $resourceGroups = (Invoke-RestMethod @RequestParams).value
        Write-Host "[+] Found $($resourceGroups.Count) resource groups in subscription $SubscriptionID" -ForegroundColor Green
        return $resourceGroups
    }
    catch {
        Write-Error "[-] Failed to retrieve resource groups in subscription $SubscriptionID. Error: $_"
        return $null
    }
}

function Get-AzureResourceDetails {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceID
    )
    $URI = "https://management.azure.com/$ResourceID/?api-version=2021-04-01"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    try {
        $resourceDetails = Invoke-RestMethod @RequestParams
        Write-Host "[+] Successfully retrieved details for resource $ResourceID" -ForegroundColor Green
        return $resourceDetails
    }
    catch {
        Write-Warning "[-] Failed to retrieve details for resource $ResourceID. Error: $_"
        return $null
    }
}

# Storage Account Functions
function Get-AzureStorageAccounts {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    try {
        $storageAccounts = (Invoke-RestMethod @RequestParams).value
        Write-Host "[+] Found $($storageAccounts.Count) storage accounts in subscription $SubscriptionID" -ForegroundColor Green
        return $storageAccounts
    }
    catch {
        Write-Warning "[-] Failed to retrieve storage accounts in subscription $SubscriptionID. Error: $_"
        return $null
    }
}

function Get-AzureStorageAccountsWithAnonymousAccess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    
    try {
        $storageAccounts = (Invoke-RestMethod @RequestParams).value
        
        $vulnerableAccounts = @()
        
        foreach ($account in $storageAccounts) {
            $accountName = $account.name
            $accountURI = "https://management.azure.com" + $account.id + "/blobServices/default?api-version=2023-01-01"
            
            $blobParams = @{
                Method  = 'GET'
                Uri     = $accountURI
                Headers = @{
                    'Authorization' = "Bearer $Token"
                }
            }
            
            try {
                $blobProperties = Invoke-RestMethod @blobParams
                
                if ($blobProperties.allowBlobPublicAccess -eq $true) {
                    Write-Host "[!] Found storage account with public access: $accountName" -ForegroundColor Yellow
                    $vulnerableAccounts += $account
                }
            }
            catch {
                Write-Verbose "Could not check blob properties for account $accountName. Error: $_"
            }
        }
        
        Write-Host "[+] Found $($vulnerableAccounts.Count) storage accounts with anonymous access" -ForegroundColor Green
        return $vulnerableAccounts
    }
    catch {
        Write-Error "[-] Failed to check storage accounts for anonymous access. Error: $_"
        return $null
    }
}

# Storage Account Key Functions
function Get-AzureStorageAccountKeys {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountID
    )
    
    $URI = "https://management.azure.com$StorageAccountID/listKeys?api-version=2023-01-01"
    $RequestParams = @{
        Method  = 'POST'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
            'Content-Type'  = 'application/json'
        }
        Body    = '{}'
    }
    
    try {
        $keys = Invoke-RestMethod @RequestParams
        Write-Host "[+] Successfully retrieved keys for storage account $StorageAccountID" -ForegroundColor Green
        Write-Host "[!] Storage account keys are highly sensitive! Handle with care." -ForegroundColor Yellow
        return $keys
    }
    catch {
        Write-Warning "[-] Failed to retrieve keys for storage account $StorageAccountID. Error: $_"
        return $null
    }
}

# Compute Functions
function Get-AzureVirtualMachines {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    try {
        $vms = (Invoke-RestMethod @RequestParams).value
        Write-Host "[+] Found $($vms.Count) virtual machines in subscription $SubscriptionID" -ForegroundColor Green
        return $vms
    }
    catch {
        Write-Warning "[-] Failed to retrieve virtual machines in subscription $SubscriptionID. Error: $_"
        return $null
    }
}

# VM Network Interfaces
function Get-AzureVirtualMachineNetworkInterfaces {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$VirtualMachineID
    )
    
    try {
        $vmDetails = Get-AzureResourceDetails -Token $Token -ResourceID $VirtualMachineID
        $networkInterfaces = @()
        
        if ($vmDetails.properties.networkProfile.networkInterfaces) {
            foreach ($interface in $vmDetails.properties.networkProfile.networkInterfaces) {
                $interfaceId = $interface.id
                $interfaceDetails = Get-AzureResourceDetails -Token $Token -ResourceID $interfaceId
                $networkInterfaces += $interfaceDetails
            }
            
            Write-Host "[+] Found $($networkInterfaces.Count) network interfaces for VM $VirtualMachineID" -ForegroundColor Green
            return $networkInterfaces
        }
        else {
            Write-Warning "[-] No network interfaces found for VM $VirtualMachineID"
            return $null
        }
    }
    catch {
        Write-Warning "[-] Failed to retrieve network interfaces for VM $VirtualMachineID. Error: $_"
        return $null
    }
}

# Key Vault Functions
function Get-AzureKeyVaults {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/providers/Microsoft.KeyVault/vaults?api-version=2023-02-01"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    try {
        $keyVaults = (Invoke-RestMethod @RequestParams).value
        Write-Host "[+] Found $($keyVaults.Count) key vaults in subscription $SubscriptionID" -ForegroundColor Green
        return $keyVaults
    }
    catch {
        Write-Warning "[-] Failed to retrieve key vaults in subscription $SubscriptionID. Error: $_"
        return $null
    }
}

function Get-AzureKeyVaultAccessPolicies {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$KeyVaultID
    )
    
    $URI = "https://management.azure.com/$KeyVaultID?api-version=2022-07-01"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    
    try {
        $keyVault = Invoke-RestMethod @RequestParams
        $accessPolicies = $keyVault.properties.accessPolicies
        Write-Host "[+] Found $($accessPolicies.Count) access policies for Key Vault $KeyVaultID" -ForegroundColor Green
        return $accessPolicies
    }
    catch {
        Write-Warning "[-] Failed to retrieve Key Vault access policies. Error: $_"
        return $null
    }
}

# Permission Functions
function Get-AzureSubscriptionPermissions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/providers/Microsoft.Authorization/permissions?api-version=2018-01-01-preview"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    
    try {
        $permissions = (Invoke-RestMethod @RequestParams).value
        Write-Host "[+] Successfully retrieved permissions for subscription $SubscriptionID" -ForegroundColor Green
        return $permissions
    }
    catch {
        Write-Warning "[-] Failed to retrieve permissions for subscription $SubscriptionID. Error: $_"
        return $null
    }
}

# Function to enumerate permissions for a resource
function Get-AzureResourceRoleAssignments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceID
    )
    
    $URI = "https://management.azure.com/$ResourceID/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    
    try {
        $roleAssignments = (Invoke-RestMethod @RequestParams).value
        Write-Host "[+] Found $($roleAssignments.Count) role assignments for resource $ResourceID" -ForegroundColor Green
        
        # Extract principal IDs for later reference
        $principalIds = @()
        foreach ($role in $roleAssignments) {
            $principalIds += $role.properties.principalId
        }
        
        return @{
            RoleAssignments = $roleAssignments
            PrincipalIds    = $principalIds
        }
    }
    catch {
        Write-Warning "[-] Failed to retrieve role assignments for resource $ResourceID. Error: $_"
        return $null
    }
}

# Function to check what actions are allowed for the current identity
function Test-AzureResourceActions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceID
    )
    
    # Common actions to test for
    $actionsToTest = @(
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Compute/virtualMachines/write",
        "Microsoft.Compute/virtualMachines/start/action",
        "Microsoft.Compute/virtualMachines/restart/action",
        "Microsoft.Compute/virtualMachines/runCommand/action",
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Storage/storageAccounts/write",
        "Microsoft.Storage/storageAccounts/listKeys/action",
        "Microsoft.KeyVault/vaults/read",
        "Microsoft.KeyVault/vaults/write",
        "Microsoft.KeyVault/vaults/secrets/read",
        "Microsoft.KeyVault/vaults/keys/read",
        "Microsoft.Web/sites/read",
        "Microsoft.Web/sites/write",
        "Microsoft.Web/sites/config/read",
        "Microsoft.Web/sites/config/write",
        "Microsoft.Authorization/roleAssignments/write"
    )
    
    $results = @()
    
    foreach ($action in $actionsToTest) {
        $URI = "https://management.azure.com/$ResourceID/providers/Microsoft.Authorization/permissions?api-version=2015-07-01"
        $RequestParams = @{
            Method  = 'GET'
            Uri     = $URI
            Headers = @{
                'Authorization' = "Bearer $Token"
            }
        }
        
        try {
            $permissions = (Invoke-RestMethod @RequestParams).value
            $actionAllowed = $false
            
            foreach ($permission in $permissions) {
                if ($permission.actions -contains $action -or $permission.actions -contains "*") {
                    $actionAllowed = $true
                    break
                }
            }
            
            $results += [PSCustomObject]@{
                ResourceID = $ResourceID
                Action     = $action
                Allowed    = $actionAllowed
            }
        }
        catch {
            Write-Verbose "Could not test action $action on resource $ResourceID. Error: $_"
        }
    }
    
    return $results
}

# Identity Functions
function Get-AzureManagedIdentities {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    
    try {
        $identities = (Invoke-RestMethod @RequestParams).value
        Write-Host "[+] Found $($identities.Count) user-assigned managed identities in subscription $SubscriptionID" -ForegroundColor Green
        return $identities
    }
    catch {
        Write-Warning "[-] Failed to retrieve managed identities. Error: $_"
        return $null
    }
}

# Web App Functions
function Get-AzureFunctionApps {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/providers/Microsoft.Web/sites?api-version=2022-03-01"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    
    try {
        $sites = (Invoke-RestMethod @RequestParams).value
        $functionApps = $sites | Where-Object { $_.kind -match "functionapp" }
        Write-Host "[+] Found $($functionApps.Count) Function Apps in subscription $SubscriptionID" -ForegroundColor Green
        return $functionApps
    }
    catch {
        Write-Warning "[-] Failed to retrieve Function Apps. Error: $_"
        return $null
    }
}

function Get-AzureAppServiceConnectionStrings {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$AppServiceID
    )
    
    $URI = "https://management.azure.com/$AppServiceID/config/connectionstrings/list?api-version=2022-03-01"
    $RequestParams = @{
        Method  = 'POST'  # Note this is POST even though it's a read operation
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
            'Content-Type'  = 'application/json'
        }
        Body    = '{}'  # Empty body required
    }
    
    try {
        $connectionStrings = (Invoke-RestMethod @RequestParams).properties
        if ($connectionStrings -and $connectionStrings.PSObject.Properties.Count -gt 0) {
            Write-Host "[+] Found $($connectionStrings.PSObject.Properties.Count) connection strings for App Service $AppServiceID" -ForegroundColor Green
            Write-Host "[!] Connection strings may contain sensitive information" -ForegroundColor Yellow
        }
        else {
            Write-Host "[+] No connection strings found for App Service $AppServiceID" -ForegroundColor Green
        }
        return $connectionStrings
    }
    catch {
        Write-Warning "[-] Failed to retrieve App Service connection strings. Error: $_"
        return $null
    }
}

# Function to get app settings (may contain secrets)
function Get-AzureAppServiceSettings {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$AppServiceID
    )
    
    $URI = "https://management.azure.com/$AppServiceID/config/appsettings/list?api-version=2022-03-01"
    $RequestParams = @{
        Method  = 'POST'  # Note this is POST even though it's a read operation
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
            'Content-Type'  = 'application/json'
        }
        Body    = '{}'  # Empty body required
    }
    
    try {
        $appSettings = (Invoke-RestMethod @RequestParams).properties
        if ($appSettings -and $appSettings.PSObject.Properties.Count -gt 0) {
            Write-Host "[+] Found $($appSettings.PSObject.Properties.Count) app settings for App Service $AppServiceID" -ForegroundColor Green
            Write-Host "[!] App settings may contain sensitive information" -ForegroundColor Yellow
        }
        else {
            Write-Host "[+] No app settings found for App Service $AppServiceID" -ForegroundColor Green
        }
        return $appSettings
    }
    catch {
        Write-Warning "[-] Failed to retrieve App Service settings. Error: $_"
        return $null
    }
}

# Automation Functions
function Get-AzureAutomationAccounts {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/providers/Microsoft.Automation/automationAccounts?api-version=2022-08-08"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    
    try {
        $automationAccounts = (Invoke-RestMethod @RequestParams).value
        Write-Host "[+] Found $($automationAccounts.Count) automation accounts in subscription $SubscriptionID" -ForegroundColor Green
        return $automationAccounts
    }
    catch {
        Write-Warning "[-] Failed to retrieve automation accounts. Error: $_"
        return $null
    }
}

function Get-AzureRunbookContent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$RunbookID
    )
    
    $URI = "https://management.azure.com/$RunbookID/content?api-version=2022-08-08"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    
    try {
        $content = Invoke-RestMethod @RequestParams
        Write-Host "[+] Successfully retrieved runbook content for $RunbookID" -ForegroundColor Green
        Write-Host "[!] Runbook content may contain credentials or other sensitive information" -ForegroundColor Yellow
        return $content
    }
    catch {
        Write-Warning "[-] Failed to retrieve runbook content. Error: $_"
        return $null
    }
}

# Resource Search Function
function Find-AzureResourcesByType {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceType,
        
        [Parameter(Mandatory = $false)]
        [string]$SubscriptionID
    )
    
    try {
        # If no subscription is provided, get all accessible subscriptions
        if (-not $SubscriptionID) {
            $subscriptions = (Get-SubscriptionID -Token $Token)
        }
        else {
            $subscriptions = @(@{subscriptionId = $SubscriptionID })
        }
        
        $allResources = @()
        
        foreach ($sub in $subscriptions) {
            $subId = $sub.subscriptionId
            
            $URI = "https://management.azure.com/subscriptions/$subId/providers/$ResourceType?api-version=2021-04-01"
            $RequestParams = @{
                Method  = 'GET'
                Uri     = $URI
                Headers = @{
                    'Authorization' = "Bearer $Token"
                }
            }
            
            try {
                $resources = (Invoke-RestMethod @RequestParams).value
                foreach ($resource in $resources) {
                    $resource | Add-Member -NotePropertyName "SubscriptionId" -NotePropertyValue $subId -Force
                    $allResources += $resource
                }
                Write-Host "[+] Found $($resources.Count) resources of type $ResourceType in subscription $subId" -ForegroundColor Green
            }
            catch {
                Write-Warning "[-] Failed to get resources in subscription $subId. Error: $_"
            }
        }
        
        Write-Host "[+] Found a total of $($allResources.Count) resources of type $ResourceType across all subscriptions" -ForegroundColor Green
        return $allResources
    }
    catch {
        Write-Error "[-] Failed to find resources by type. Error: $_"
        return $null
    }
}

# Export Function
function Export-AzureResultsToCSV {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Data,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $false)]
        [switch]$Append
    )
    
    try {
        if ($Data -is [System.Collections.IEnumerable] -and $Data -isnot [string]) {
            $Data | Export-Csv -Path $FilePath -NoTypeInformation -Append:$Append
            Write-Host "[+] Data successfully exported to $FilePath" -ForegroundColor Green
        }
        else {
            # Convert single object to array
            @($Data) | Export-Csv -Path $FilePath -NoTypeInformation -Append:$Append
            Write-Host "[+] Data successfully exported to $FilePath" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "[-] Failed to export data to CSV. Error: $_"
    }
}

# Function to check for NSG rules
function Get-AzureNetworkSecurityGroups {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-02-01"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    
    try {
        $nsgs = (Invoke-RestMethod @RequestParams).value
        Write-Host "[+] Found $($nsgs.Count) Network Security Groups in subscription $SubscriptionID" -ForegroundColor Green
        return $nsgs
    }
    catch {
        Write-Warning "[-] Failed to retrieve Network Security Groups in subscription $SubscriptionID. Error: $_"
        return $null
    }
}

# Function to get public IP addresses
function Get-AzurePublicIPAddresses {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/providers/Microsoft.Network/publicIPAddresses?api-version=2023-02-01"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    
    try {
        $publicIPs = (Invoke-RestMethod @RequestParams).value
        Write-Host "[+] Found $($publicIPs.Count) Public IP Addresses in subscription $SubscriptionID" -ForegroundColor Green
        return $publicIPs
    }
    catch {
        Write-Warning "[-] Failed to retrieve Public IP Addresses in subscription $SubscriptionID. Error: $_"
        return $null
    }
}

# Function to get VM run commands - these can be used for privilege escalation
function Get-AzureVMRunCommands {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$VMResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/resourceGroups/$VMResourceGroupName/providers/Microsoft.Compute/virtualMachines/$VMName/runCommands?api-version=2023-03-01"
    $RequestParams = @{
        Method  = 'GET'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    
    try {
        $runCommands = (Invoke-RestMethod @RequestParams).value
        Write-Host "[+] Found $($runCommands.Count) Run Commands for VM $VMName" -ForegroundColor Green
        return $runCommands
    }
    catch {
        Write-Warning "[-] Failed to retrieve Run Commands for VM $VMName. Error: $_"
        return $null
    }
}

# Function to execute VM run command - can be used for privilege escalation
function Invoke-AzureVMRunCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        
        [Parameter(Mandatory = $true)]
        [string]$VMResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID,
        
        [Parameter(Mandatory = $true)]
        [string]$CommandId,
        
        [Parameter(Mandatory = $true)]
        [string]$ScriptToRun
    )
    
    $URI = "https://management.azure.com/subscriptions/$SubscriptionID/resourceGroups/$VMResourceGroupName/providers/Microsoft.Compute/virtualMachines/$VMName/runCommand?api-version=2023-03-01"
    
    $body = @{
        commandId = $CommandId
        script    = @($ScriptToRun)
    } | ConvertTo-Json
    
    $RequestParams = @{
        Method  = 'POST'
        Uri     = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
            'Content-Type'  = 'application/json'
        }
        Body    = $body
    }
    
    try {
        Write-Host "[!] WARNING: Executing command on VM $VMName. This is a high-risk operation!" -ForegroundColor Yellow
        $result = Invoke-RestMethod @RequestParams
        Write-Host "[+] Command execution initiated on VM $VMName. Operation ID: $($result.name)" -ForegroundColor Green
        return $result
    }
    catch {
        Write-Error "[-] Failed to execute command on VM $VMName. Error: $_"
        return $null
    }
}

# Function to convert CSV to Markdown report
function ConvertTo-MarkdownReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [string]$Title,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRows = 0  # 0 means all rows
    )
    
    try {
        # If no output path is specified, create one based on the CSV path
        if (-not $OutputPath) {
            $OutputPath = [System.IO.Path]::ChangeExtension($CsvPath, ".md")
        }
        
        # If no title is specified, create one based on the CSV filename
        if (-not $Title) {
            $csvFilename = [System.IO.Path]::GetFileNameWithoutExtension($CsvPath)
            $Title = "Report: $csvFilename"
        }
        
        # Try to import the CSV
        $data = Import-Csv -Path $CsvPath
        
        # Create the markdown content
        $markdownContent = "# $Title`n`n"
        $markdownContent += "Report generated on $(Get-Date)`n`n"
        
        # If there's no data, note that
        if (-not $data -or $data.Count -eq 0) {
            $markdownContent += "No data found in the CSV file.`n"
            Set-Content -Path $OutputPath -Value $markdownContent
            Write-Host "[+] Empty markdown report saved to $OutputPath" -ForegroundColor Green
            return
        }
        
        # Get the headers
        $headers = $data[0].PSObject.Properties.Name
        
        # Create the table header
        $markdownContent += "| " + ($headers -join " | ") + " |`n"
        $markdownContent += "| " + (($headers | ForEach-Object { "-" * ($_.Length) }) -join " | ") + " |`n"
        
        # Limit rows if needed
        $rowsToProcess = if ($MaxRows -gt 0 -and $data.Count -gt $MaxRows) { $data[0..($MaxRows - 1)] } else { $data }
        
        # Create the table rows
        foreach ($row in $rowsToProcess) {
            $rowValues = @()
            foreach ($header in $headers) {
                # Escape any pipe characters in the cell value
                $cellValue = $row.$header -replace '\|', '\|'
                # Replace any null values with empty string
                if ($null -eq $cellValue) { $cellValue = "" }
                $rowValues += $cellValue
            }
            $markdownContent += "| " + ($rowValues -join " | ") + " |`n"
        }
        
        # If we limited the rows, add a note
        if ($MaxRows -gt 0 -and $data.Count -gt $MaxRows) {
            $markdownContent += "`n_Note: Showing $MaxRows of $($data.Count) total rows._`n"
        }
        
        # Add a summary section
        $markdownContent += "`n## Summary`n`n"
        $markdownContent += "- Total records: $($data.Count)`n"
        $markdownContent += "- Report generated by COBALT PROPHET`n"
        
        # Save the markdown content
        Set-Content -Path $OutputPath -Value $markdownContent
        
        Write-Host "[+] Markdown report saved to $OutputPath" -ForegroundColor Green
        return $OutputPath
    }
    catch {
        Write-Error "[-] Failed to convert CSV to Markdown: $_"
        return $null
    }
}

# Function to generate consolidated markdown report from all CSVs
function New-AzureEnumerationMarkdownReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputDirectory,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRowsPerTable = 10
    )
    
    try {
        # If no output path is specified, create one in the input directory
        if (-not $OutputPath) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $OutputPath = Join-Path -Path $InputDirectory -ChildPath "CobaltProphet_Report_$timestamp.md"
        }
        
        # Create the markdown content
        $markdownContent = "# COBALT PROPHET - Azure Enumeration Report`n`n"
        $markdownContent += "Report generated on $(Get-Date)`n`n"
        
        # Create a table of contents
        $markdownContent += "## Table of Contents`n`n"
        
        # Find all CSV files in the directory and subdirectories
        $csvFiles = Get-ChildItem -Path $InputDirectory -Filter "*.csv" -Recurse
        
        if (-not $csvFiles -or $csvFiles.Count -eq 0) {
            $markdownContent += "No CSV files found in the directory.`n"
            Set-Content -Path $OutputPath -Value $markdownContent
            Write-Host "[+] Empty consolidated report saved to $OutputPath" -ForegroundColor Green
            return
        }
        
        # Group files by directory
        $filesByDirectory = $csvFiles | Group-Object -Property DirectoryName
        
        # Add TOC entries
        foreach ($dirGroup in $filesByDirectory) {
            $dirName = Split-Path -Path $dirGroup.Name -Leaf
            $markdownContent += "- [$dirName](#$($dirName.ToLower() -replace ' ', '-'))`n"
            foreach ($file in $dirGroup.Group) {
                $fileName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                $markdownContent += "  - [$fileName](#$($fileName.ToLower() -replace ' ', '-'))`n"
            }
        }
        
        $markdownContent += "`n## Findings Summary`n`n"
        
        # Add a summary of high-value findings
        $highValueFiles = $csvFiles | Where-Object { $_.Name -match "high_value|public|vulnerable" }
        if ($highValueFiles -and $highValueFiles.Count -gt 0) {
            $markdownContent += "### High-Value Findings`n`n"
            $markdownContent += "The following high-value resources were identified:`n`n"
            
            foreach ($file in $highValueFiles) {
                $data = Import-Csv -Path $file.FullName
                if ($data -and $data.Count -gt 0) {
                    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                    $markdownContent += "- **$fileName**: $($data.Count) findings`n"
                }
            }
        }
        
        # Process each directory group
        foreach ($dirGroup in $filesByDirectory) {
            $dirName = Split-Path -Path $dirGroup.Name -Leaf
            $markdownContent += "`n## $dirName`n`n"
            
            # Process each CSV file in the directory
            foreach ($file in $dirGroup.Group) {
                $data = Import-Csv -Path $file.FullName
                $fileName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                
                $markdownContent += "### $fileName`n`n"
                
                if (-not $data -or $data.Count -eq 0) {
                    $markdownContent += "No data found in this file.`n`n"
                    continue
                }
                
                # Add a quick summary for this file
                $markdownContent += "- Total records: $($data.Count)`n`n"
                
                # Get the headers
                $headers = $data[0].PSObject.Properties.Name
                
                # Create the table header
                $markdownContent += "| " + ($headers -join " | ") + " |`n"
                $markdownContent += "| " + (($headers | ForEach-Object { "-" * ($_.Length) }) -join " | ") + " |`n"
                
                # Limit rows for readability
                $rowsToProcess = if ($MaxRowsPerTable -gt 0 -and $data.Count -gt $MaxRowsPerTable) { 
                    $data[0..($MaxRowsPerTable - 1)] 
                }
                else { 
                    $data 
                }
                
                # Create the table rows
                foreach ($row in $rowsToProcess) {
                    $rowValues = @()
                    foreach ($header in $headers) {
                        # Escape any pipe characters in the cell value
                        $cellValue = $row.$header -replace '\|', '\|'
                        # Replace any null values with empty string
                        if ($null -eq $cellValue) { $cellValue = "" }
                        # Truncate long values
                        if ($cellValue.Length -gt 50) {
                            $cellValue = $cellValue.Substring(0, 47) + "..."
                        }
                        $rowValues += $cellValue
                    }
                    $markdownContent += "| " + ($rowValues -join " | ") + " |`n"
                }
                
                # If we limited the rows, add a note and a link to the full report
                if ($MaxRowsPerTable -gt 0 -and $data.Count -gt $MaxRowsPerTable) {
                    $reportPath = [System.IO.Path]::ChangeExtension($file.FullName, ".md")
                    $relativePath = $reportPath.Replace($InputDirectory, "").TrimStart("\")
                    $markdownContent += "`n_Note: Showing $MaxRowsPerTable of $($data.Count) total rows. " +
                    "See the detailed report for complete data._`n`n"
                    
                    # Generate the detailed report for this CSV
                    ConvertTo-MarkdownReport -CsvPath $file.FullName -Title "Detailed Report: $fileName"
                }
                
                $markdownContent += "`n"
            }
        }
        
        # Add a note about the tool
        $markdownContent += "`n## About`n`n"
        $markdownContent += "This report was generated by COBALT PROPHET, an Azure red team enumeration tool.`n"
        
        # Save the markdown content
        Set-Content -Path $OutputPath -Value $markdownContent
        
        Write-Host "[+] Consolidated markdown report saved to $OutputPath" -ForegroundColor Green
        return $OutputPath
    }
    catch {
        Write-Error "[-] Failed to generate consolidated markdown report: $_"
        return $null
    }
}

# Function to convert CSV to HTML report
function ConvertTo-HtmlReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [string]$Title,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRows = 0  # 0 means all rows
    )
    
    try {
        # If no output path is specified, create one based on the CSV path
        if (-not $OutputPath) {
            $OutputPath = [System.IO.Path]::ChangeExtension($CsvPath, ".html")
        }
        
        # If no title is specified, create one based on the CSV filename
        if (-not $Title) {
            $csvFilename = [System.IO.Path]::GetFileNameWithoutExtension($CsvPath)
            $Title = "Report: $csvFilename"
        }
        
        # Try to import the CSV
        $data = Import-Csv -Path $CsvPath
        
        # Create HTML header and CSS
        $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2 {
            color: #0066cc;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 20px;
        }
        th, td {
            padding: 8px;
            text-align: left;
            border: 1px solid #ddd;
        }
        th {
            background-color: #0066cc;
            color: white;
            position: sticky;
            top: 0;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #ddd;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin-top: 20px;
        }
        .note {
            font-style: italic;
            color: #666;
        }
        .filter-input {
            width: 100%;
            padding: 8px;
            margin-bottom: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .security-warning {
            background-color: #feecec;
            border-left: 4px solid #d9534f;
            padding: 10px 15px;
            margin-bottom: 20px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <h1>$Title</h1>
    <p>Report generated on $(Get-Date)</p>
    <div class="security-warning">
        <strong>Security Notice:</strong> This report may contain sensitive information about your Azure environment. Handle with care.
    </div>
"@
        
        # If there's no data, note that
        if (-not $data -or $data.Count -eq 0) {
            $htmlContent += "<p>No data found in the CSV file.</p>"
            $htmlContent += "</body></html>"
            Set-Content -Path $OutputPath -Value $htmlContent
            Write-Host "[+] Empty HTML report saved to $OutputPath" -ForegroundColor Green
            return
        }
        
        # Add search functionality
        $htmlContent += @"
    <input type="text" id="searchInput" class="filter-input" placeholder="Search table data...">
    <div style="overflow-x: auto;">
        <table id="dataTable">
            <thead>
                <tr>
"@
        
        # Get the headers
        $headers = $data[0].PSObject.Properties.Name
        
        # Add table headers
        foreach ($header in $headers) {
            $htmlContent += "                <th>$header</th>`n"
        }
        
        $htmlContent += "                </tr>`n            </thead>`n            <tbody>`n"
        
        # Limit rows if needed
        $rowsToProcess = if ($MaxRows -gt 0 -and $data.Count -gt $MaxRows) { $data[0..($MaxRows - 1)] } else { $data }
        
        # Add data rows
        foreach ($row in $rowsToProcess) {
            $htmlContent += "                <tr>`n"
            foreach ($header in $headers) {
                $cellValue = $row.$header
                # Replace any null values with empty string
                if ($null -eq $cellValue) { $cellValue = "" }
                # Make special formatting for certain values
                if ($cellValue -eq "True") {
                    $htmlContent += "                    <td style='background-color: #d4edda;'>$cellValue</td>`n"
                }
                elseif ($cellValue -eq "False") {
                    $htmlContent += "                    <td style='background-color: #f8d7da;'>$cellValue</td>`n"
                }
                elseif ($cellValue -match "key|secret|password|token|connection|pwd|credential" -and $cellValue -ne "") {
                    $htmlContent += "                    <td style='background-color: #fff3cd;'>$cellValue</td>`n"
                }
                else {
                    $htmlContent += "                    <td>$cellValue</td>`n"
                }
            }
            $htmlContent += "                </tr>`n"
        }
        
        $htmlContent += "            </tbody>`n        </table>`n    </div>`n"
        
        # If we limited the rows, add a note
        if ($MaxRows -gt 0 -and $data.Count -gt $MaxRows) {
            $htmlContent += "<p class='note'>Note: Showing $MaxRows of $($data.Count) total rows.</p>`n"
        }
        
        # Add a summary section
        $htmlContent += @"
    <div class="summary">
        <h2>Summary</h2>
        <ul>
            <li>Total records: $($data.Count)</li>
            <li>Report generated by COBALT PROPHET</li>
        </ul>
    </div>
"@
        
        # Add JavaScript for search functionality
        $htmlContent += @"
    <script>
        document.getElementById('searchInput').addEventListener('keyup', function() {
            let input = this.value.toLowerCase();
            let table = document.getElementById('dataTable');
            let rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                let visible = false;
                let cells = rows[i].getElementsByTagName('td');
                
                for (let j = 0; j < cells.length; j++) {
                    if (cells[j].textContent.toLowerCase().indexOf(input) > -1) {
                        visible = true;
                        break;
                    }
                }
                
                rows[i].style.display = visible ? '' : 'none';
            }
        });
    </script>
</body>
</html>
"@
        
        # Save the HTML content
        Set-Content -Path $OutputPath -Value $htmlContent
        
        Write-Host "[+] HTML report saved to $OutputPath" -ForegroundColor Green
        return $OutputPath
    }
    catch {
        Write-Error "[-] Failed to convert CSV to HTML: $_"
        return $null
    }
}

# Function to generate consolidated HTML report from all CSVs
function New-AzureEnumerationHtmlReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputDirectory,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRowsPerTable = 15
    )
    
    try {
        # If no output path is specified, create one in the input directory
        if (-not $OutputPath) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $OutputPath = Join-Path -Path $InputDirectory -ChildPath "CobaltProphet_Report_$timestamp.html"
        }
        
        # Create HTML header and CSS
        $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>COBALT PROPHET - Azure Enumeration Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #0066cc;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 20px;
        }
        th, td {
            padding: 8px;
            text-align: left;
            border: 1px solid #ddd;
        }
        th {
            background-color: #0066cc;
            color: white;
            position: sticky;
            top: 0;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #ddd;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin-top: 20px;
        }
        .note {
            font-style: italic;
            color: #666;
        }
        .filter-input {
            width: 100%;
            padding: 8px;
            margin-bottom: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .security-warning {
            background-color: #feecec;
            border-left: 4px solid #d9534f;
            padding: 10px 15px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .toc {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .toc ul {
            list-style-type: none;
            padding-left: 20px;
        }
        .toc > ul {
            padding-left: 0;
        }
        .section {
            margin-bottom: 30px;
            border-bottom: 1px solid #eee;
            padding-bottom: 20px;
        }
        .high-value {
            background-color: #fff3cd;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
            border-left: 4px solid #ffc107;
        }
        .highlight-true {
            background-color: #d4edda;
        }
        .highlight-false {
            background-color: #f8d7da;
        }
        .highlight-sensitive {
            background-color: #fff3cd;
        }
        .detail-button {
            background-color: #0066cc;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            text-decoration: none;
            display: inline-block;
            margin-top: 5px;
        }
        .detail-button:hover {
            background-color: #0056b3;
        }
        #searchGlobal {
            width: 100%;
            padding: 10px;
            margin-bottom: 20px;
            border: 2px solid #0066cc;
            border-radius: 4px;
            font-size: 16px;
        }
    </style>
</head>
<body>
    <h1>COBALT PROPHET - Azure Enumeration Report</h1>
    <p>Report generated on $(Get-Date)</p>
    <div class="security-warning">
        <strong>Security Notice:</strong> This report contains sensitive information about your Azure environment. Handle with care.
    </div>
    
    <input type="text" id="searchGlobal" placeholder="Search across the entire report...">
    
"@
        
        # Find all CSV files in the directory and subdirectories
        $csvFiles = Get-ChildItem -Path $InputDirectory -Filter "*.csv" -Recurse
        
        if (-not $csvFiles -or $csvFiles.Count -eq 0) {
            $htmlContent += "<p>No CSV files found in the directory.</p>"
            $htmlContent += "</body></html>"
            Set-Content -Path $OutputPath -Value $htmlContent
            Write-Host "[+] Empty HTML report saved to $OutputPath" -ForegroundColor Green
            return
        }
        
        # Group files by directory
        $filesByDirectory = $csvFiles | Group-Object -Property DirectoryName
        
        # Create Table of Contents
        $htmlContent += @"
    <div class="toc">
        <h2>Table of Contents</h2>
        <ul>
            <li><a href="#summary">Findings Summary</a></li>
"@

        # Add high-value findings section to TOC if applicable
        $highValueFiles = $csvFiles | Where-Object { $_.Name -match "high_value|public|vulnerable" }
        if ($highValueFiles -and $highValueFiles.Count -gt 0) {
            $htmlContent += "            <li><a href='#high-value'>High-Value Findings</a></li>`n"
        }
        
        # Add other sections to TOC
        foreach ($dirGroup in $filesByDirectory) {
            $dirName = Split-Path -Path $dirGroup.Name -Leaf
            $dirId = $dirName -replace '[^a-zA-Z0-9]', '-'
            $htmlContent += "            <li><a href='#$dirId'>$dirName</a>`n                <ul>`n"
            
            foreach ($file in $dirGroup.Group) {
                $fileName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                $fileId = ($dirId + "-" + ($fileName -replace '[^a-zA-Z0-9]', '-'))
                $htmlContent += "                    <li><a href='#$fileId'>$fileName</a></li>`n"
            }
            
            $htmlContent += "                </ul>`n            </li>`n"
        }
        
        $htmlContent += "        </ul>`n    </div>`n"
        
        # Add summary section
        $htmlContent += @"
    <div class="section" id="summary">
        <h2>Findings Summary</h2>
        <p>This report contains data from ${$csvFiles.Count} CSV files.</p>
"@
        
        # Add high-value findings section if applicable
        if ($highValueFiles -and $highValueFiles.Count -gt 0) {
            $htmlContent += @"
        <div class="high-value" id="high-value">
            <h3>High-Value Findings</h3>
            <p>The following high-value resources were identified:</p>
            <ul>
"@
            
            foreach ($file in $highValueFiles) {
                $data = Import-Csv -Path $file.FullName
                if ($data -and $data.Count -gt 0) {
                    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                    $dirName = Split-Path -Path $file.DirectoryName -Leaf
                    $dirId = $dirName -replace '[^a-zA-Z0-9]', '-'
                    $fileId = ($dirId + "-" + ($fileName -replace '[^a-zA-Z0-9]', '-'))
                    $htmlContent += "                <li><a href='#$fileId'><strong>$fileName</strong></a>: $($data.Count) findings</li>`n"
                }
            }
            
            $htmlContent += "            </ul>`n        </div>`n"
        }
        
        $htmlContent += "    </div>`n"
        
        # Process each directory group
        foreach ($dirGroup in $filesByDirectory) {
            $dirName = Split-Path -Path $dirGroup.Name -Leaf
            $dirId = $dirName -replace '[^a-zA-Z0-9]', '-'
            $htmlContent += @"
    <div class="section" id="$dirId">
        <h2>$dirName</h2>
"@
            
            # Process each CSV file in the directory
            foreach ($file in $dirGroup.Group) {
                $data = Import-Csv -Path $file.FullName
                $fileName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                $fileId = ($dirId + "-" + ($fileName -replace '[^a-zA-Z0-9]', '-'))
                
                $htmlContent += @"
        <div class="subsection" id="$fileId">
            <h3>$fileName</h3>
"@
                
                if (-not $data -or $data.Count -eq 0) {
                    $htmlContent += "            <p>No data found in this file.</p>`n        </div>`n"
                    continue
                }
                
                # Add a quick summary for this file
                $htmlContent += "            <p>Total records: $($data.Count)</p>`n"
                
                # Create a table filter for this specific table
                $searchId = "search-$fileId"
                $tableId = "table-$fileId"
                $htmlContent += @"
            <input type="text" id="$searchId" class="filter-input" placeholder="Filter this table...">
            <div style="overflow-x: auto;">
                <table id="$tableId">
                    <thead>
                        <tr>
"@
                
                # Get the headers
                $headers = $data[0].PSObject.Properties.Name
                
                # Add table headers
                foreach ($header in $headers) {
                    $htmlContent += "                            <th>$header</th>`n"
                }
                
                $htmlContent += "                        </tr>`n                    </thead>`n                    <tbody>`n"
                
                # Limit rows for readability
                # Limit rows for readability
                $rowsToProcess = if ($MaxRowsPerTable -gt 0 -and $data.Count -gt $MaxRowsPerTable) { 
                    $data[0..($MaxRowsPerTable - 1)] 
                }
                else { 
                    $data 
                }

                # Add data rows
                foreach ($row in $rowsToProcess) {
                    $htmlContent += "                        <tr>`n"
                    foreach ($header in $headers) {
                        $cellValue = $row.$header
                        # Replace any null values with empty string
                        if ($null -eq $cellValue) { $cellValue = "" }
                        # Make special formatting for certain values
                        if ($cellValue -eq "True") {
                            $htmlContent += "                            <td class='highlight-true'>$cellValue</td>`n"
                        }
                        elseif ($cellValue -eq "False") {
                            $htmlContent += "                            <td class='highlight-false'>$cellValue</td>`n"
                        }
                        elseif ($cellValue -match "key|secret|password|token|connection|pwd|credential" -and $cellValue -ne "") {
                            $htmlContent += "                            <td class='highlight-sensitive'>$cellValue</td>`n"
                        }
                        else {
                            # Truncate long values for display
                            $displayValue = $cellValue
                            if ($displayValue.Length -gt 100) {
                                $displayValue = $displayValue.Substring(0, 97) + "..."
                            }
                            $htmlContent += "                            <td>$displayValue</td>`n"
                        }
                    }
                    $htmlContent += "                        </tr>`n"
                }

                $htmlContent += "                    </tbody>`n                </table>`n            </div>`n"

                # If we limited the rows, add a note and a link to the detailed report
                if ($MaxRowsPerTable -gt 0 -and $data.Count -gt $MaxRowsPerTable) {
                    # Generate a detailed HTML report for this CSV
                    $detailedReportPath = ConvertTo-HtmlReport -CsvPath $file.FullName -Title "Detailed Report: $fileName"
                    $relativeReportPath = $detailedReportPath.Replace($InputDirectory, "").TrimStart("\")
    
                    $htmlContent += @"
<p class="note">
Note: Showing $MaxRowsPerTable of $($data.Count) total rows. 
<a href="$relativeReportPath" class="detail-button" target="_blank">View Full Data</a>
</p>
"@
                }

                # Add JavaScript for this specific table's filter
                $htmlContent += @"
<script>
document.getElementById('$searchId').addEventListener('keyup', function() {
    let input = this.value.toLowerCase();
    let table = document.getElementById('$tableId');
    let rows = table.getElementsByTagName('tr');
    
    for (let i = 1; i < rows.length; i++) {
        let visible = false;
        let cells = rows[i].getElementsByTagName('td');
        
        for (let j = 0; j < cells.length; j++) {
            if (cells[j].textContent.toLowerCase().indexOf(input) > -1) {
                visible = true;
                break;
            }
        }
        
        rows[i].style.display = visible ? '' : 'none';
    }
});
</script>
</div>
"@
            }

            $htmlContent += "    </div>`n"
        }

        # Add a footer section
        $htmlContent += @"
<div class="section">
<h2>About</h2>
<p>This report was generated by COBALT PROPHET, an Azure red team enumeration tool.</p>
</div>

<script>
document.getElementById('searchGlobal').addEventListener('keyup', function() {
let input = this.value.toLowerCase();
let sections = document.querySelectorAll('.subsection');

for (let i = 0; i < sections.length; i++) {
let textContent = sections[i].textContent.toLowerCase();
if (textContent.indexOf(input) > -1) {
    sections[i].style.display = '';
} else {
    sections[i].style.display = 'none';
}
}

// Show section headers if search is empty
if (input === '') {
let sectionHeaders = document.querySelectorAll('.section');
for (let i = 0; i < sectionHeaders.length; i++) {
    sectionHeaders[i].style.display = '';
}
}
});
</script>
</body>
</html>
"@

        # Save the HTML content
        Set-Content -Path $OutputPath -Value $htmlContent

        Write-Host "[+] Consolidated HTML report saved to $OutputPath" -ForegroundColor Green
        return $OutputPath
    }
    catch {
        Write-Error "[-] Failed to generate consolidated HTML report: $_"
        return $null
    }
}

# Main Enumeration Function
function Start-AzureEnumeration {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $false)]
        [string]$OutputDirectory = ".\AzureEnum_$(Get-Date -Format 'yyyyMMdd_HHmmss')",

        [Parameter(Mandatory = $false)]
        [switch]$Comprehensive,

        [Parameter(Mandatory = $false)]
        [switch]$SkipExport,

        [Parameter(Mandatory = $false)]
        [ValidateSet("None", "Markdown", "HTML", "Both")]
        [string]$ReportFormat = "Both"
    )

    try {
        Write-Host "[*] Starting Azure enumeration with provided token" -ForegroundColor Cyan

        # Create output directory if export is enabled
        if (-not $SkipExport) {
            if (-not (Test-Path -Path $OutputDirectory)) {
                New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
                Write-Host "[+] Created output directory: $OutputDirectory" -ForegroundColor Green
            }
        }

        # Get subscriptions
        Write-Host "[*] Enumerating accessible subscriptions..." -ForegroundColor Cyan
        $subscriptions = Get-SubscriptionID -Token $Token

        if (-not $subscriptions -or $subscriptions.Count -eq 0) {
            Write-Error "[-] No accessible subscriptions found. Check token permissions and try again."
            return
        }

        if (-not $SkipExport) {
            Export-AzureResultsToCSV -Data $subscriptions -FilePath "$OutputDirectory\subscriptions.csv"
        }

        # Process each subscription
        foreach ($sub in $subscriptions) {
            $subscriptionId = $sub.subscriptionId
            $subscriptionName = $sub.displayName

            Write-Host "`n[*] Processing subscription: $subscriptionName ($subscriptionId)" -ForegroundColor Cyan

            # Create subscription-specific directory
            $subDirectory = "$OutputDirectory\$subscriptionId"
            if (-not $SkipExport) {
                if (-not (Test-Path -Path $subDirectory)) {
                    New-Item -Path $subDirectory -ItemType Directory -Force | Out-Null
                }
            }

            # Get subscription permissions
            Write-Host "[*] Checking permissions for subscription $subscriptionId..." -ForegroundColor Cyan
            $permissions = Get-AzureSubscriptionPermissions -Token $Token -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $permissions) {
                Export-AzureResultsToCSV -Data $permissions -FilePath "$subDirectory\subscription_permissions.csv"
            }

            # Get resource groups
            Write-Host "[*] Enumerating resource groups..." -ForegroundColor Cyan
            $resourceGroups = Get-AzureResourceGroups -Token $Token -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $resourceGroups) {
                Export-AzureResultsToCSV -Data $resourceGroups -FilePath "$subDirectory\resource_groups.csv"
            }

            # Get all resources
            Write-Host "[*] Enumerating all resources..." -ForegroundColor Cyan
            $resources = Get-AzureResourceList -Token $Token -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $resources) {
                Export-AzureResultsToCSV -Data $resources -FilePath "$subDirectory\resources.csv"
            }

            # Identify high-value targets
            Write-Host "[*] Identifying high-value targets..." -ForegroundColor Cyan

            # Key Vaults
            Write-Host "[*] Enumerating Key Vaults..." -ForegroundColor Cyan
            $keyVaults = Get-AzureKeyVaults -Token $Token -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $keyVaults) {
                Export-AzureResultsToCSV -Data $keyVaults -FilePath "$subDirectory\key_vaults.csv"
            }

            # Storage Accounts
            Write-Host "[*] Enumerating Storage Accounts..." -ForegroundColor Cyan
            $storageAccounts = Get-AzureStorageAccounts -Token $Token -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $storageAccounts) {
                Export-AzureResultsToCSV -Data $storageAccounts -FilePath "$subDirectory\storage_accounts.csv"
            }

            # Check for storage accounts with public access
            Write-Host "[*] Checking for storage accounts with public access..." -ForegroundColor Cyan
            $publicStorageAccounts = Get-AzureStorageAccountsWithAnonymousAccess -Token $Token -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $publicStorageAccounts) {
                Export-AzureResultsToCSV -Data $publicStorageAccounts -FilePath "$subDirectory\public_storage_accounts.csv"
            }

            # Virtual Machines
            Write-Host "[*] Enumerating Virtual Machines..." -ForegroundColor Cyan
            $vms = Get-AzureVirtualMachines -Token $Token -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $vms) {
                Export-AzureResultsToCSV -Data $vms -FilePath "$subDirectory\virtual_machines.csv"
            }

            # Network Security Groups
            Write-Host "[*] Enumerating Network Security Groups..." -ForegroundColor Cyan
            $nsgs = Get-AzureNetworkSecurityGroups -Token $Token -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $nsgs) {
                Export-AzureResultsToCSV -Data $nsgs -FilePath "$subDirectory\network_security_groups.csv"
            }

            # Public IP Addresses
            Write-Host "[*] Enumerating Public IP Addresses..." -ForegroundColor Cyan
            $publicIPs = Get-AzurePublicIPAddresses -Token $Token -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $publicIPs) {
                Export-AzureResultsToCSV -Data $publicIPs -FilePath "$subDirectory\public_ip_addresses.csv"
            }

            # Function Apps
            Write-Host "[*] Enumerating Function Apps..." -ForegroundColor Cyan
            $functionApps = Get-AzureFunctionApps -Token $Token -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $functionApps) {
                Export-AzureResultsToCSV -Data $functionApps -FilePath "$subDirectory\function_apps.csv"
            }

            # Automation Accounts
            Write-Host "[*] Enumerating Automation Accounts..." -ForegroundColor Cyan
            $automationAccounts = Get-AzureAutomationAccounts -Token $Token -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $automationAccounts) {
                Export-AzureResultsToCSV -Data $automationAccounts -FilePath "$subDirectory\automation_accounts.csv"
            }

            # Managed Identities
            Write-Host "[*] Enumerating Managed Identities..." -ForegroundColor Cyan
            $managedIdentities = Get-AzureManagedIdentities -Token $Token -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $managedIdentities) {
                Export-AzureResultsToCSV -Data $managedIdentities -FilePath "$subDirectory\managed_identities.csv"
            }

            # If comprehensive scan is requested
            if ($Comprehensive) {
                Write-Host "[*] Performing comprehensive enumeration (this may take time)..." -ForegroundColor Cyan

                # Check Key Vault access policies
                if ($keyVaults) {
                    Write-Host "[*] Checking Key Vault access policies..." -ForegroundColor Cyan
                    $keyVaultPolicies = @()
                    foreach ($kv in $keyVaults) {
                        $policies = Get-AzureKeyVaultAccessPolicies -Token $Token -KeyVaultID $kv.id
                        if ($policies) {
                            foreach ($policy in $policies) {
                                $policy | Add-Member -NotePropertyName "KeyVaultName" -NotePropertyValue $kv.name -Force
                                $policy | Add-Member -NotePropertyName "KeyVaultID" -NotePropertyValue $kv.id -Force
                                $keyVaultPolicies += $policy
                            }
                        }
                    }
                    if (-not $SkipExport -and $keyVaultPolicies) {
                        Export-AzureResultsToCSV -Data $keyVaultPolicies -FilePath "$subDirectory\key_vault_policies.csv"
                    }
                }

                # Check App Service connection strings and settings
                if ($functionApps) {
                    Write-Host "[*] Checking App Service connection strings..." -ForegroundColor Cyan
                    $connectionStringsInfo = @()
                    foreach ($app in $functionApps) {
                        $connStrings = Get-AzureAppServiceConnectionStrings -Token $Token -AppServiceID $app.id
                        if ($connStrings -and $connStrings.PSObject.Properties.Count -gt 0) {
                            $connInfo = [PSCustomObject]@{
                                AppName              = $app.name
                                AppID                = $app.id
                                HasConnectionStrings = $true
                                Count                = $connStrings.PSObject.Properties.Count
                            }
                            $connectionStringsInfo += $connInfo
                        }
                    }
                    if (-not $SkipExport -and $connectionStringsInfo) {
                        Export-AzureResultsToCSV -Data $connectionStringsInfo -FilePath "$subDirectory\connection_strings_info.csv"
                    }
    
                    # Check App Settings (often contain secrets)
                    Write-Host "[*] Checking App Service settings..." -ForegroundColor Cyan
                    $appSettingsInfo = @()
                    foreach ($app in $functionApps) {
                        $settings = Get-AzureAppServiceSettings -Token $Token -AppServiceID $app.id
                        if ($settings -and $settings.PSObject.Properties.Count -gt 0) {
                            $settingsInfo = [PSCustomObject]@{
                                AppName          = $app.name
                                AppID            = $app.id
                                HasAppSettings   = $true
                                Count            = $settings.PSObject.Properties.Count
                                # Flag if any settings might contain secrets
                                PotentialSecrets = ($settings.PSObject.Properties.Name -match "key|secret|password|token|connection|pwd|credential" -join ", ")
                            }
                            $appSettingsInfo += $settingsInfo
                        }
                    }
                    if (-not $SkipExport -and $appSettingsInfo) {
                        Export-AzureResultsToCSV -Data $appSettingsInfo -FilePath "$subDirectory\app_settings_info.csv"
                    }
                }

                # If automation accounts exist, check for runbooks
                if ($automationAccounts) {
                    Write-Host "[*] Checking for Automation Runbooks..." -ForegroundColor Cyan
                    $runbooksFound = @()
                    foreach ($account in $automationAccounts) {
                        $URI = "https://management.azure.com$($account.id)/runbooks?api-version=2022-08-08"
                        $RequestParams = @{
                            Method  = 'GET'
                            Uri     = $URI
                            Headers = @{
                                'Authorization' = "Bearer $Token"
                            }
                        }
        
                        try {
                            $runbooks = (Invoke-RestMethod @RequestParams).value
                            if ($runbooks -and $runbooks.Count -gt 0) {
                                foreach ($runbook in $runbooks) {
                                    $runbook | Add-Member -NotePropertyName "AutomationAccountName" -NotePropertyValue $account.name -Force
                                    $runbooksFound += $runbook
                                }
                            }
                        }
                        catch {
                            Write-Warning "[-] Failed to retrieve runbooks for automation account $($account.name). Error: $_"
                        }
                    }
    
                    if (-not $SkipExport -and $runbooksFound) {
                        Export-AzureResultsToCSV -Data $runbooksFound -FilePath "$subDirectory\automation_runbooks.csv"
                    }
                }

                # If VMs exist, get more detailed information
                if ($vms) {
                    Write-Host "[*] Getting detailed VM information..." -ForegroundColor Cyan
    
                    # Check VM network interfaces
                    $vmNetworkInfo = @()
                    foreach ($vm in $vms) {
                        $networkInterfaces = Get-AzureVirtualMachineNetworkInterfaces -Token $Token -VirtualMachineID $vm.id
                        if ($networkInterfaces) {
                            foreach ($nic in $networkInterfaces) {
                                $nicInfo = [PSCustomObject]@{
                                    VMName               = $vm.name
                                    VMID                 = $vm.id
                                    NetworkInterfaceName = $nic.name
                                    NetworkInterfaceID   = $nic.id
                                    PrivateIPAddress     = $nic.properties.ipConfigurations[0].properties.privateIPAddress
                                    PublicIPAddress      = if ($nic.properties.ipConfigurations[0].properties.publicIPAddress) { "Has public IP" } else { "No public IP" }
                                }
                                $vmNetworkInfo += $nicInfo
                            }
                        }
                    }
    
                    if (-not $SkipExport -and $vmNetworkInfo) {
                        Export-AzureResultsToCSV -Data $vmNetworkInfo -FilePath "$subDirectory\vm_network_info.csv"
                    }
    
                    # Check VM run commands if resource groups are available
                    if ($resourceGroups) {
                        $vmRunCommands = @()
                        foreach ($vm in $vms) {
                            if ($vm.id -match "/resourceGroups/([^/]+)/") {
                                $rgName = $matches[1]
                                $runCommands = Get-AzureVMRunCommands -Token $Token -VMResourceGroupName $rgName -VMName $vm.name -SubscriptionID $subscriptionId
                
                                if ($runCommands) {
                                    foreach ($cmd in $runCommands) {
                                        $cmd | Add-Member -NotePropertyName "VMName" -NotePropertyValue $vm.name -Force
                                        $vmRunCommands += $cmd
                                    }
                                }
                            }
                        }
        
                        if (-not $SkipExport -and $vmRunCommands) {
                            Export-AzureResultsToCSV -Data $vmRunCommands -FilePath "$subDirectory\vm_run_commands.csv"
                        }
                    }
                }

                # Try to check storage account keys (highly sensitive)
                if ($storageAccounts) {
                    Write-Host "[*] Attempting to get storage account keys (high value)..." -ForegroundColor Cyan
                    $storageAccountKeyInfo = @()
                    foreach ($sa in $storageAccounts) {
                        try {
                            $keys = Get-AzureStorageAccountKeys -Token $Token -StorageAccountID $sa.id
                            if ($keys -and $keys.keys) {
                                $keyInfo = [PSCustomObject]@{
                                    StorageAccountName = $sa.name
                                    StorageAccountID   = $sa.id
                                    KeysAccessible     = $true
                                    KeyCount           = $keys.keys.Count
                                }
                                $storageAccountKeyInfo += $keyInfo
                                Write-Host "[!] Found accessible keys for storage account $($sa.name)!" -ForegroundColor Yellow
                            }
                        }
                        catch {
                            $keyInfo = [PSCustomObject]@{
                                StorageAccountName = $sa.name
                                StorageAccountID   = $sa.id
                                KeysAccessible     = $false
                                KeyCount           = 0
                            }
                            $storageAccountKeyInfo += $keyInfo
                        }
                    }
    
                    if (-not $SkipExport -and $storageAccountKeyInfo) {
                        Export-AzureResultsToCSV -Data $storageAccountKeyInfo -FilePath "$subDirectory\storage_account_key_access.csv"
                    }
                }

                # Check permissions for important resources
                Write-Host "[*] Checking permissions for important resources..." -ForegroundColor Cyan
                $permissionFindings = @()

                # Check permissions on VMs
                if ($vms) {
                    foreach ($vm in $vms) {
                        $permissionResults = Test-AzureResourceActions -Token $Token -ResourceID $vm.id
                        foreach ($result in $permissionResults) {
                            $result | Add-Member -NotePropertyName "ResourceType" -NotePropertyValue "VirtualMachine" -Force
                            $result | Add-Member -NotePropertyName "ResourceName" -NotePropertyValue $vm.name -Force
                            $permissionFindings += $result
                        }
                    }
                }

                # Check permissions on Key Vaults
                if ($keyVaults) {
                    foreach ($kv in $keyVaults) {
                        $permissionResults = Test-AzureResourceActions -Token $Token -ResourceID $kv.id
                        foreach ($result in $permissionResults) {
                            $result | Add-Member -NotePropertyName "ResourceType" -NotePropertyValue "KeyVault" -Force
                            $result | Add-Member -NotePropertyName "ResourceName" -NotePropertyValue $kv.name -Force
                            $permissionFindings += $result
                        }
                    }
                }

                # Check permissions on Storage Accounts
                if ($storageAccounts) {
                    foreach ($sa in $storageAccounts) {
                        $permissionResults = Test-AzureResourceActions -Token $Token -ResourceID $sa.id
                        foreach ($result in $permissionResults) {
                            $result | Add-Member -NotePropertyName "ResourceType" -NotePropertyValue "StorageAccount" -Force
                            $result | Add-Member -NotePropertyName "ResourceName" -NotePropertyValue $sa.name -Force
                            $permissionFindings += $result
                        }
                    }
                }

                # Check permissions on Function Apps
                if ($functionApps) {
                    foreach ($app in $functionApps) {
                        $permissionResults = Test-AzureResourceActions -Token $Token -ResourceID $app.id
                        foreach ($result in $permissionResults) {
                            $result | Add-Member -NotePropertyName "ResourceType" -NotePropertyValue "FunctionApp" -Force
                            $result | Add-Member -NotePropertyName "ResourceName" -NotePropertyValue $app.name -Force
                            $permissionFindings += $result
                        }
                    }
                }

                # Check subscription-level permissions for privilege escalation
                $subPermissionResults = Test-AzureResourceActions -Token $Token -ResourceID "subscriptions/$subscriptionId"
                foreach ($result in $subPermissionResults) {
                    $result | Add-Member -NotePropertyName "ResourceType" -NotePropertyValue "Subscription" -Force
                    $result | Add-Member -NotePropertyName "ResourceName" -NotePropertyValue $subscriptionName -Force
                    $permissionFindings += $result
                }

                # Export permission findings
                if (-not $SkipExport -and $permissionFindings) {
                    Export-AzureResultsToCSV -Data $permissionFindings -FilePath "$subDirectory\permission_findings.csv"
    
                    # Also export a filtered view of high-value permissions
                    $highValuePermissions = $permissionFindings | Where-Object { 
                        $_.Allowed -eq $true -and ($_.Action -like "*write*" -or 
                            $_.Action -like "*action*" -or 
                            $_.Action -like "*listKeys*" -or 
                            $_.Action -like "*secrets*")
                    }
    
                    if ($highValuePermissions) {
                        Export-AzureResultsToCSV -Data $highValuePermissions -FilePath "$subDirectory\high_value_permissions.csv"
                        Write-Host "[!] Found $($highValuePermissions.Count) high-value permissions! Check high_value_permissions.csv" -ForegroundColor Yellow
                    }
                }
            }
        }

        # Generate reports based on selected format
        if (-not $SkipExport -and $ReportFormat -ne "None") {
            if ($ReportFormat -eq "Markdown" -or $ReportFormat -eq "Both") {
                Write-Host "[*] Generating markdown reports..." -ForegroundColor Cyan
                $markdownReportPath = New-AzureEnumerationMarkdownReport -InputDirectory $OutputDirectory
                Write-Host "[+] Consolidated markdown report saved to $markdownReportPath" -ForegroundColor Green
            }

            if ($ReportFormat -eq "HTML" -or $ReportFormat -eq "Both") {
                Write-Host "[*] Generating HTML reports..." -ForegroundColor Cyan
                $htmlReportPath = New-AzureEnumerationHtmlReport -InputDirectory $OutputDirectory
                Write-Host "[+] Consolidated HTML report saved to $htmlReportPath" -ForegroundColor Green
            }
        }

        Write-Host "`n[+] Azure enumeration completed successfully!" -ForegroundColor Green
        Write-Host "[+] Results saved to: $OutputDirectory" -ForegroundColor Green

        # Return a summary object
        $summary = [PSCustomObject]@{
            Subscriptions         = $subscriptions.Count
            ResourceGroups        = ($resourceGroups | Measure-Object).Count
            Resources             = ($resources | Measure-Object).Count
            KeyVaults             = ($keyVaults | Measure-Object).Count
            StorageAccounts       = ($storageAccounts | Measure-Object).Count
            PublicStorageAccounts = ($publicStorageAccounts | Measure-Object).Count
            VirtualMachines       = ($vms | Measure-Object).Count
            NetworkSecurityGroups = ($nsgs | Measure-Object).Count
            PublicIPAddresses     = ($publicIPs | Measure-Object).Count
            FunctionApps          = ($functionApps | Measure-Object).Count
            AutomationAccounts    = ($automationAccounts | Measure-Object).Count
            ManagedIdentities     = ($managedIdentities | Measure-Object).Count
            OutputDirectory       = $OutputDirectory
        }

        # Add report paths if generated
        if (-not $SkipExport) {
            if ($ReportFormat -eq "Markdown" -or $ReportFormat -eq "Both") {
                $summary | Add-Member -NotePropertyName "MarkdownReportPath" -NotePropertyValue $markdownReportPath -Force
            }

            if ($ReportFormat -eq "HTML" -or $ReportFormat -eq "Both") {
                $summary | Add-Member -NotePropertyName "HtmlReportPath" -NotePropertyValue $htmlReportPath -Force
            }
        }

        return $summary
    }
    catch {
        Write-Error "[-] An error occurred during enumeration: $_"
    }
}

# Function to get a token interactively (useful if you don't already have one)
function Get-AzureToken {
    param(
        [Parameter(Mandatory = $false)]
        [string]$TenantId = "common",

        [Parameter(Mandatory = $false)]
        [string]$ClientId = "1950a258-227b-4e31-a9cf-717495945fc2", # Azure PowerShell Client ID

        [Parameter(Mandatory = $false)]
        [string]$Resource = "https://management.azure.com/"
    )

    try {
        # For red team operators, you might have different ways to obtain tokens
        # This is a simplified example using the MSAL.PS module if available

        # Check if MSAL.PS is available
        if (Get-Module -ListAvailable -Name MSAL.PS) {
            Write-Host "[*] Using MSAL.PS module to acquire token..." -ForegroundColor Cyan
            Import-Module MSAL.PS

            $token = Get-MsalToken -TenantId $TenantId -ClientId $ClientId -Resource $Resource -Interactive
            return $token.AccessToken
        }
        else {
            Write-Warning "[!] MSAL.PS module not found. Please install it with 'Install-Module MSAL.PS' or provide your own token."
            Write-Host "[*] You can also obtain a token manually through other means and pass it to the Start-AzureEnumeration function." -ForegroundColor Yellow
            return $null
        }
    }
    catch {
        Write-Error "[-] Failed to acquire token: $_"
        return $null
    }
}
