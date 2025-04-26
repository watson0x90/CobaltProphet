<#
.SYNOPSIS
AZ COBALT PROPHET - Azure Cloud Enumeration Tool using Az PowerShell Modules

.DESCRIPTION
A comprehensive PowerShell module for Azure environment enumeration during red team operations.
This tool uses Az PowerShell modules to enumerate resources, permissions, configurations, and potential security weaknesses.

.NOTES
Author: Ryan Watson (watson0x90)
Version: 1.0.0
Requires: PowerShell 5.1 or higher, Az PowerShell modules
#>

# Base Azure Functions
function Get-AzCPSubscriptionID {
    [CmdletBinding()]
    param()
    
    try {
        $subs = Get-AzSubscription
        Write-Host "[+] Found $($subs.Count) accessible subscriptions" -ForegroundColor Green
        return $subs
    }
    catch {
        Write-Error "[-] Failed to retrieve subscriptions. Error: $_"
        return $null
    }
}

function Get-AzCPResourceList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    try {
        # Set the context to the specified subscription
        Set-AzContext -Subscription $SubscriptionID | Out-Null
        
        # Get all resources in the subscription
        $resources = Get-AzResource
        Write-Host "[+] Found $($resources.Count) resources in subscription $SubscriptionID" -ForegroundColor Green
        return $resources
    }
    catch {
        Write-Error "[-] Failed to retrieve resources in subscription $SubscriptionID. Error: $_"
        return $null
    }
}

function Get-AzCPResourcePermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceID
    )
    
    try {
        $permissions = Get-AzRoleAssignment -Scope $ResourceID
        Write-Host "[+] Successfully retrieved permissions for resource $ResourceID" -ForegroundColor Green
        return $permissions
    }
    catch {
        Write-Warning "[-] Failed to retrieve permissions for resource $ResourceID. Error: $_"
        return $null
    }
}

function Get-AzCPRoleAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceID
    )
    
    try {
        $roleAssignments = Get-AzRoleAssignment -Scope $ResourceID
        Write-Host "[+] Found $($roleAssignments.Count) role assignments for resource $ResourceID" -ForegroundColor Green
        return $roleAssignments
    }
    catch {
        Write-Warning "[-] Failed to retrieve role assignments for resource $ResourceID. Error: $_"
        return $null
    }
}

function Get-AzCPResourceGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    try {
        # Set the context to the specified subscription
        Set-AzContext -Subscription $SubscriptionID | Out-Null
        
        $resourceGroups = Get-AzResourceGroup
        Write-Host "[+] Found $($resourceGroups.Count) resource groups in subscription $SubscriptionID" -ForegroundColor Green
        return $resourceGroups
    }
    catch {
        Write-Error "[-] Failed to retrieve resource groups in subscription $SubscriptionID. Error: $_"
        return $null
    }
}

function Get-AzCPResourceDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceID
    )
    
    try {
        $resourceDetails = Get-AzResource -ResourceId $ResourceID -ExpandProperties
        Write-Host "[+] Successfully retrieved details for resource $ResourceID" -ForegroundColor Green
        return $resourceDetails
    }
    catch {
        Write-Warning "[-] Failed to retrieve details for resource $ResourceID. Error: $_"
        return $null
    }
}

# Storage Account Functions
function Get-AzCPStorageAccounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    try {
        # Set the context to the specified subscription
        Set-AzContext -Subscription $SubscriptionID | Out-Null
        
        $storageAccounts = Get-AzStorageAccount
        Write-Host "[+] Found $($storageAccounts.Count) storage accounts in subscription $SubscriptionID" -ForegroundColor Green
        return $storageAccounts
    }
    catch {
        Write-Warning "[-] Failed to retrieve storage accounts in subscription $SubscriptionID. Error: $_"
        return $null
    }
}

function Get-AzCPStorageAccountsWithAnonymousAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    try {
        # Set the context to the specified subscription
        Set-AzContext -Subscription $SubscriptionID | Out-Null
        
        $storageAccounts = Get-AzStorageAccount
        $vulnerableAccounts = @()
        
        foreach ($account in $storageAccounts) {
            try {
                $blobProperties = Get-AzStorageServiceProperty -ResourceGroupName $account.ResourceGroupName -Name $account.StorageAccountName -ServiceType Blob
                
                if ($blobProperties.AllowPublicAccess -eq $true) {
                    Write-Host "[!] Found storage account with public access: $($account.StorageAccountName)" -ForegroundColor Yellow
                    $vulnerableAccounts += $account
                }
            }
            catch {
                Write-Verbose "Could not check blob properties for account $($account.StorageAccountName). Error: $_"
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
function Get-AzCPStorageAccountKeys {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName
    )
    
    try {
        $keys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
        
        Write-Host "[+] Successfully retrieved keys for storage account $StorageAccountName" -ForegroundColor Green
        Write-Host "[!] Storage account keys are highly sensitive! Handle with care." -ForegroundColor Yellow
        return $keys
    }
    catch {
        Write-Warning "[-] Failed to retrieve keys for storage account $StorageAccountName. Error: $_"
        return $null
    }
}

# Compute Functions
function Get-AzCPVirtualMachines {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    try {
        # Set the context to the specified subscription
        Set-AzContext -Subscription $SubscriptionID | Out-Null
        
        $vms = Get-AzVM
        Write-Host "[+] Found $($vms.Count) virtual machines in subscription $SubscriptionID" -ForegroundColor Green
        return $vms
    }
    catch {
        Write-Warning "[-] Failed to retrieve virtual machines in subscription $SubscriptionID. Error: $_"
        return $null
    }
}

# VM Network Interfaces
function Get-AzCPVirtualMachineNetworkInterfaces {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$VMName
    )
    
    try {
        $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
        $networkInterfaces = @()
        
        foreach ($nicRef in $vm.NetworkProfile.NetworkInterfaces) {
            $nicId = $nicRef.Id
            $nicName = $nicId.Split('/')[-1]
            $nicRg = ($nicId -split '/resourceGroups/')[1].Split('/')[0]
            
            $nic = Get-AzNetworkInterface -ResourceGroupName $nicRg -Name $nicName
            $networkInterfaces += $nic
        }
        
        Write-Host "[+] Found $($networkInterfaces.Count) network interfaces for VM $VMName" -ForegroundColor Green
        return $networkInterfaces
    }
    catch {
        Write-Warning "[-] Failed to retrieve network interfaces for VM $VMName. Error: $_"
        return $null
    }
}

# Key Vault Functions
function Get-AzCPKeyVaults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    try {
        # Set the context to the specified subscription
        Set-AzContext -Subscription $SubscriptionID | Out-Null
        
        $keyVaults = Get-AzKeyVault
        Write-Host "[+] Found $($keyVaults.Count) key vaults in subscription $SubscriptionID" -ForegroundColor Green
        return $keyVaults
    }
    catch {
        Write-Warning "[-] Failed to retrieve key vaults in subscription $SubscriptionID. Error: $_"
        return $null
    }
}

function Get-AzCPKeyVaultAccessPolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$KeyVaultName
    )
    
    try {
        $keyVault = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName
        $accessPolicies = $keyVault.AccessPolicies
        
        Write-Host "[+] Found $($accessPolicies.Count) access policies for Key Vault $KeyVaultName" -ForegroundColor Green
        return $accessPolicies
    }
    catch {
        Write-Warning "[-] Failed to retrieve Key Vault access policies. Error: $_"
        return $null
    }
}

# Permission Functions
function Get-AzCPSubscriptionPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    try {
        # Set the context to the specified subscription
        Set-AzContext -Subscription $SubscriptionID | Out-Null
        
        $permissions = Get-AzRoleAssignment -Scope "/subscriptions/$SubscriptionID"
        
        Write-Host "[+] Successfully retrieved permissions for subscription $SubscriptionID" -ForegroundColor Green
        return $permissions
    }
    catch {
        Write-Warning "[-] Failed to retrieve permissions for subscription $SubscriptionID. Error: $_"
        return $null
    }
}

# Function to enumerate permissions for a resource
function Get-AzCPResourceRoleAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceID
    )
    
    try {
        $roleAssignments = Get-AzRoleAssignment -Scope $ResourceID
        
        Write-Host "[+] Found $($roleAssignments.Count) role assignments for resource $ResourceID" -ForegroundColor Green
        
        # Extract principal IDs for later reference
        $principalIds = $roleAssignments | Select-Object -ExpandProperty ObjectId -Unique
        
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
function Test-AzCPResourceActions {
    [CmdletBinding()]
    param(
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
    
    # Getting current context
    $context = Get-AzContext
    
    foreach ($action in $actionsToTest) {
        try {
            # Check if the role assignment grants the specific action
            $allowed = $false
            
            # Get role assignments for the scope
            $roles = Get-AzRoleAssignment -Scope $ResourceID
            
            foreach ($role in $roles) {
                $roleDefinition = Get-AzRoleDefinition -Name $role.RoleDefinitionName
                
                if ($roleDefinition.Actions -contains $action -or $roleDefinition.Actions -contains "*") {
                    $allowed = $true
                    break
                }
            }
            
            $results += [PSCustomObject]@{
                ResourceID = $ResourceID
                Action     = $action
                Allowed    = $allowed
            }
        }
        catch {
            Write-Verbose "Could not test action $action on resource $ResourceID. Error: $_"
        }
    }
    
    return $results
}

# Identity Functions
function Get-AzCPManagedIdentities {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    try {
        # Set the context to the specified subscription
        Set-AzContext -Subscription $SubscriptionID | Out-Null
        
        # Get all user-assigned managed identities
        $identities = Get-AzResource -ResourceType "Microsoft.ManagedIdentity/userAssignedIdentities"
        
        Write-Host "[+] Found $($identities.Count) user-assigned managed identities in subscription $SubscriptionID" -ForegroundColor Green
        return $identities
    }
    catch {
        Write-Warning "[-] Failed to retrieve managed identities. Error: $_"
        return $null
    }
}

# Web App Functions
function Get-AzCPFunctionApps {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    try {
        # Set the context to the specified subscription
        Set-AzContext -Subscription $SubscriptionID | Out-Null
        
        # Get all function apps
        $functionApps = Get-AzFunctionApp
        
        Write-Host "[+] Found $($functionApps.Count) Function Apps in subscription $SubscriptionID" -ForegroundColor Green
        return $functionApps
    }
    catch {
        Write-Warning "[-] Failed to retrieve Function Apps. Error: $_"
        return $null
    }
}

function Get-AzCPAppServiceConnectionStrings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$AppServiceName
    )
    
    try {
        $webApp = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $AppServiceName
        $connectionStrings = $webApp.SiteConfig.ConnectionStrings
        
        if ($connectionStrings -and $connectionStrings.Count -gt 0) {
            Write-Host "[+] Found $($connectionStrings.Count) connection strings for App Service $AppServiceName" -ForegroundColor Green
            Write-Host "[!] Connection strings may contain sensitive information" -ForegroundColor Yellow
        }
        else {
            Write-Host "[+] No connection strings found for App Service $AppServiceName" -ForegroundColor Green
        }
        
        return $connectionStrings
    }
    catch {
        Write-Warning "[-] Failed to retrieve App Service connection strings. Error: $_"
        return $null
    }
}

# Function to get app settings (may contain secrets)
function Get-AzCPAppServiceSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$AppServiceName
    )
    
    try {
        $webApp = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $AppServiceName
        $appSettings = $webApp.SiteConfig.AppSettings
        
        if ($appSettings -and $appSettings.Count -gt 0) {
            Write-Host "[+] Found $($appSettings.Count) app settings for App Service $AppServiceName" -ForegroundColor Green
            Write-Host "[!] App settings may contain sensitive information" -ForegroundColor Yellow
        }
        else {
            Write-Host "[+] No app settings found for App Service $AppServiceName" -ForegroundColor Green
        }
        
        return $appSettings
    }
    catch {
        Write-Warning "[-] Failed to retrieve App Service settings. Error: $_"
        return $null
    }
}

# Automation Functions
function Get-AzCPAutomationAccounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    try {
        # Set the context to the specified subscription
        Set-AzContext -Subscription $SubscriptionID | Out-Null
        
        $automationAccounts = Get-AzAutomationAccount
        
        Write-Host "[+] Found $($automationAccounts.Count) automation accounts in subscription $SubscriptionID" -ForegroundColor Green
        return $automationAccounts
    }
    catch {
        Write-Warning "[-] Failed to retrieve automation accounts. Error: $_"
        return $null
    }
}

function Get-AzCPRunbookContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$AutomationAccountName,
        
        [Parameter(Mandatory = $true)]
        [string]$RunbookName
    )
    
    try {
        $content = Export-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunbookName -Slot "Published" -OutputFolder (Get-Location) -Force
        
        if ($content) {
            Write-Host "[+] Successfully retrieved runbook content for $RunbookName" -ForegroundColor Green
            Write-Host "[!] Runbook content may contain credentials or other sensitive information" -ForegroundColor Yellow
            
            # Read the content of the exported file
            $filePath = Join-Path -Path (Get-Location) -ChildPath "$RunbookName.ps1"
            $runbookContent = Get-Content -Path $filePath -Raw
            
            # Clean up the exported file
            Remove-Item -Path $filePath -Force
            
            return $runbookContent
        }
        else {
            Write-Warning "[-] Failed to retrieve runbook content. No content returned."
            return $null
        }
    }
    catch {
        Write-Warning "[-] Failed to retrieve runbook content. Error: $_"
        return $null
    }
}

# Resource Search Function
function Find-AzCPResourcesByType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceType,
        
        [Parameter(Mandatory = $false)]
        [string]$SubscriptionID
    )
    
    try {
        # If no subscription is provided, get all accessible subscriptions
        if (-not $SubscriptionID) {
            $subscriptions = Get-AzCPSubscriptionID
        }
        else {
            $subscriptions = @([PSCustomObject]@{Id = $SubscriptionID })
        }
        
        $allResources = @()
        
        foreach ($sub in $subscriptions) {
            $subId = $sub.Id
            
            # Set the context to the specified subscription
            Set-AzContext -Subscription $subId | Out-Null
            
            try {
                $resources = Get-AzResource -ResourceType $ResourceType
                
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
function Export-AzCPResultsToCSV {
    [CmdletBinding()]
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
function Get-AzCPNetworkSecurityGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    try {
        # Set the context to the specified subscription
        Set-AzContext -Subscription $SubscriptionID | Out-Null
        
        $nsgs = Get-AzNetworkSecurityGroup
        
        Write-Host "[+] Found $($nsgs.Count) Network Security Groups in subscription $SubscriptionID" -ForegroundColor Green
        return $nsgs
    }
    catch {
        Write-Warning "[-] Failed to retrieve Network Security Groups in subscription $SubscriptionID. Error: $_"
        return $null
    }
}

# Function to get public IP addresses
function Get-AzCPPublicIPAddresses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionID
    )
    
    try {
        # Set the context to the specified subscription
        Set-AzContext -Subscription $SubscriptionID | Out-Null
        
        $publicIPs = Get-AzPublicIpAddress
        
        Write-Host "[+] Found $($publicIPs.Count) Public IP Addresses in subscription $SubscriptionID" -ForegroundColor Green
        return $publicIPs
    }
    catch {
        Write-Warning "[-] Failed to retrieve Public IP Addresses in subscription $SubscriptionID. Error: $_"
        return $null
    }
}

# Function to get VM run commands - these can be used for privilege escalation
function Get-AzCPVMRunCommands {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$VMName
    )
    
    try {
        # Using Azure CLI to get VM run commands since there's no direct Az PowerShell command
        $runCommands = Invoke-Expression "az vm run-command list --resource-group $ResourceGroupName --vm-name $VMName --query '[].name' -o tsv"
        $runCommandsList = $runCommands -split "`n" | Where-Object { $_ -ne "" }
        
        $formattedCommands = @()
        foreach ($cmdName in $runCommandsList) {
            $formattedCommands += [PSCustomObject]@{
                Name          = $cmdName
                VMName        = $VMName
                ResourceGroup = $ResourceGroupName
            }
        }
        
        Write-Host "[+] Found $($formattedCommands.Count) Run Commands for VM $VMName" -ForegroundColor Green
        return $formattedCommands
    }
    catch {
        Write-Warning "[-] Failed to retrieve Run Commands for VM $VMName. Error: $_"
        return $null
    }
}

# Function to execute VM run command - can be used for privilege escalation
function Invoke-AzCPVMRunCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $true)]
        [string]$CommandId,
        
        [Parameter(Mandatory = $true)]
        [string]$ScriptToRun
    )
    
    try {
        Write-Host "[!] WARNING: Executing command on VM $VMName. This is a high-risk operation!" -ForegroundColor Yellow
        
        $params = @{
            'ResourceGroupName' = $ResourceGroupName
            'VMName'            = $VMName
            'CommandId'         = $CommandId
            'ScriptString'      = $ScriptToRun
        }
        
        $result = Invoke-AzVMRunCommand @params
        
        Write-Host "[+] Command execution completed on VM $VMName." -ForegroundColor Green
        return $result
    }
    catch {
        Write-Error "[-] Failed to execute command on VM $VMName. Error: $_"
        return $null
    }
}

# Function to convert CSV to Markdown report
function ConvertTo-AzCPMarkdownReport {
    [CmdletBinding()]
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
        $markdownContent += "- Report generated by AZ COBALT PROPHET`n"
        
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
function New-AzCPEnumerationMarkdownReport {
    [CmdletBinding()]
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
            $OutputPath = Join-Path -Path $InputDirectory -ChildPath "AzCobaltProphet_Report_$timestamp.md"
        }
        
        # Create the markdown content
        $markdownContent = "# AZ COBALT PROPHET - Azure Enumeration Report`n`n"
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
                    ConvertTo-AzCPMarkdownReport -CsvPath $file.FullName -Title "Detailed Report: $fileName"
                }
                
                $markdownContent += "`n"
            }
        }
        
        # Add a note about the tool
        $markdownContent += "`n## About`n`n"
        $markdownContent += "This report was generated by AZ COBALT PROPHET, an Azure red team enumeration tool.`n"
        
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
function ConvertTo-AzCPHtmlReport {
    [CmdletBinding()]
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
            <li>Report generated by AZ COBALT PROPHET</li>
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
function New-AzCPEnumerationHtmlReport {
    [CmdletBinding()]
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
            $OutputPath = Join-Path -Path $InputDirectory -ChildPath "AzCobaltProphet_Report_$timestamp.html"
        }
        
        # Create HTML header and CSS
        $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AZ COBALT PROPHET - Azure Enumeration Report</title>
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
    <h1>AZ COBALT PROPHET - Azure Enumeration Report</h1>
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
                    $detailedReportPath = ConvertTo-AzCPHtmlReport -CsvPath $file.FullName -Title "Detailed Report: $fileName"
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
<p>This report was generated by AZ COBALT PROPHET, an Azure red team enumeration tool.</p>
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
function Start-AzCPEnumeration {
    [CmdletBinding()]
    param(
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
        Write-Host "[*] Starting Azure enumeration using Az PowerShell modules" -ForegroundColor Cyan
        Write-Host "[*] Verifying connection to Azure..." -ForegroundColor Cyan
        
        # Test connection to Azure
        try {
            $context = Get-AzContext
            if (-not $context) {
                Write-Error "[-] Not connected to Azure. Please run Connect-AzAccount before using this tool."
                return
            }
            Write-Host "[+] Connected to Azure as $($context.Account)" -ForegroundColor Green
        }
        catch {
            Write-Error "[-] Failed to verify Azure connection: $_"
            Write-Host "[!] Please run Connect-AzAccount to authenticate to Azure." -ForegroundColor Yellow
            return
        }
        
        # Create output directory if export is enabled
        if (-not $SkipExport) {
            if (-not (Test-Path -Path $OutputDirectory)) {
                New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
                Write-Host "[+] Created output directory: $OutputDirectory" -ForegroundColor Green
            }
        }
        
        # Get subscriptions
        Write-Host "[*] Enumerating accessible subscriptions..." -ForegroundColor Cyan
        $subscriptions = Get-AzCPSubscriptionID
        
        if (-not $subscriptions -or $subscriptions.Count -eq 0) {
            Write-Error "[-] No accessible subscriptions found. Check permissions and try again."
            return
        }
        
        if (-not $SkipExport) {
            Export-AzCPResultsToCSV -Data $subscriptions -FilePath "$OutputDirectory\subscriptions.csv"
        }
        
        # Process each subscription
        foreach ($sub in $subscriptions) {
            $subscriptionId = $sub.Id
            $subscriptionName = $sub.Name
            
            Write-Host "`n[*] Processing subscription: $subscriptionName ($subscriptionId)" -ForegroundColor Cyan
            
            # Set the context to the current subscription
            Set-AzContext -Subscription $subscriptionId | Out-Null
            
            # Create subscription-specific directory
            $subDirectory = "$OutputDirectory\$subscriptionId"
            if (-not $SkipExport) {
                if (-not (Test-Path -Path $subDirectory)) {
                    New-Item -Path $subDirectory -ItemType Directory -Force | Out-Null
                }
            }
            
            # Get subscription permissions
            Write-Host "[*] Checking permissions for subscription $subscriptionId..." -ForegroundColor Cyan
            $permissions = Get-AzCPSubscriptionPermissions -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $permissions) {
                Export-AzCPResultsToCSV -Data $permissions -FilePath "$subDirectory\subscription_permissions.csv"
            }
            
            # Get resource groups
            Write-Host "[*] Enumerating resource groups..." -ForegroundColor Cyan
            $resourceGroups = Get-AzCPResourceGroups -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $resourceGroups) {
                Export-AzCPResultsToCSV -Data $resourceGroups -FilePath "$subDirectory\resource_groups.csv"
            }
            
            # Get all resources
            Write-Host "[*] Enumerating all resources..." -ForegroundColor Cyan
            $resources = Get-AzCPResourceList -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $resources) {
                Export-AzCPResultsToCSV -Data $resources -FilePath "$subDirectory\resources.csv"
            }
            
            # Identify high-value targets
            Write-Host "[*] Identifying high-value targets..." -ForegroundColor Cyan
            
            # Key Vaults
            Write-Host "[*] Enumerating Key Vaults..." -ForegroundColor Cyan
            $keyVaults = Get-AzCPKeyVaults -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $keyVaults) {
                Export-AzCPResultsToCSV -Data $keyVaults -FilePath "$subDirectory\key_vaults.csv"
            }
            
            # Storage Accounts
            Write-Host "[*] Enumerating Storage Accounts..." -ForegroundColor Cyan
            $storageAccounts = Get-AzCPStorageAccounts -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $storageAccounts) {
                Export-AzCPResultsToCSV -Data $storageAccounts -FilePath "$subDirectory\storage_accounts.csv"
            }
            
            # Check for storage accounts with public access
            Write-Host "[*] Checking for storage accounts with public access..." -ForegroundColor Cyan
            $publicStorageAccounts = Get-AzCPStorageAccountsWithAnonymousAccess -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $publicStorageAccounts) {
                Export-AzCPResultsToCSV -Data $publicStorageAccounts -FilePath "$subDirectory\public_storage_accounts.csv"
            }
            
            # Virtual Machines
            Write-Host "[*] Enumerating Virtual Machines..." -ForegroundColor Cyan
            $vms = Get-AzCPVirtualMachines -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $vms) {
                Export-AzCPResultsToCSV -Data $vms -FilePath "$subDirectory\virtual_machines.csv"
            }
            
            # Network Security Groups
            Write-Host "[*] Enumerating Network Security Groups..." -ForegroundColor Cyan
            $nsgs = Get-AzCPNetworkSecurityGroups -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $nsgs) {
                Export-AzCPResultsToCSV -Data $nsgs -FilePath "$subDirectory\network_security_groups.csv"
            }
            
            # Public IP Addresses
            Write-Host "[*] Enumerating Public IP Addresses..." -ForegroundColor Cyan
            $publicIPs = Get-AzCPPublicIPAddresses -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $publicIPs) {
                Export-AzCPResultsToCSV -Data $publicIPs -FilePath "$subDirectory\public_ip_addresses.csv"
            }
            
            # Function Apps
            Write-Host "[*] Enumerating Function Apps..." -ForegroundColor Cyan
            $functionApps = Get-AzCPFunctionApps -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $functionApps) {
                Export-AzCPResultsToCSV -Data $functionApps -FilePath "$subDirectory\function_apps.csv"
            }
            
            # Automation Accounts
            Write-Host "[*] Enumerating Automation Accounts..." -ForegroundColor Cyan
            $automationAccounts = Get-AzCPAutomationAccounts -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $automationAccounts) {
                Export-AzCPResultsToCSV -Data $automationAccounts -FilePath "$subDirectory\automation_accounts.csv"
            }
            
            # Managed Identities
            Write-Host "[*] Enumerating Managed Identities..." -ForegroundColor Cyan
            $managedIdentities = Get-AzCPManagedIdentities -SubscriptionID $subscriptionId
            if (-not $SkipExport -and $managedIdentities) {
                Export-AzCPResultsToCSV -Data $managedIdentities -FilePath "$subDirectory\managed_identities.csv"
            }
            
            # If comprehensive scan is requested
            if ($Comprehensive) {
                Write-Host "[*] Performing comprehensive enumeration (this may take time)..." -ForegroundColor Cyan
                
                # Check Key Vault access policies
                if ($keyVaults) {
                    Write-Host "[*] Checking Key Vault access policies..." -ForegroundColor Cyan
                    $keyVaultPolicies = @()
                    foreach ($kv in $keyVaults) {
                        $policies = Get-AzCPKeyVaultAccessPolicies -ResourceGroupName $kv.ResourceGroupName -KeyVaultName $kv.VaultName
                        if ($policies) {
                            foreach ($policy in $policies) {
                                $policyObj = [PSCustomObject]@{
                                    KeyVaultName              = $kv.VaultName
                                    KeyVaultID                = $kv.ResourceId
                                    ObjectId                  = $policy.ObjectId
                                    TenantId                  = $policy.TenantId
                                    PermissionsToKeys         = $policy.PermissionsToKeys -join ", "
                                    PermissionsToSecrets      = $policy.PermissionsToSecrets -join ", "
                                    PermissionsToCertificates = $policy.PermissionsToCertificates -join ", "
                                    PermissionsToStorage      = $policy.PermissionsToStorage -join ", "
                                }
                                $keyVaultPolicies += $policyObj
                            }
                        }
                    }
                    if (-not $SkipExport -and $keyVaultPolicies) {
                        Export-AzCPResultsToCSV -Data $keyVaultPolicies -FilePath "$subDirectory\key_vault_policies.csv"
                    }
                }
                
                # Check App Service connection strings and settings
                if ($functionApps) {
                    Write-Host "[*] Checking App Service connection strings..." -ForegroundColor Cyan
                    $connectionStringsInfo = @()
                    foreach ($app in $functionApps) {
                        $connStrings = Get-AzCPAppServiceConnectionStrings -ResourceGroupName $app.ResourceGroup -AppServiceName $app.Name
                        if ($connStrings -and $connStrings.Count -gt 0) {
                            $connInfo = [PSCustomObject]@{
                                AppName              = $app.Name
                                AppID                = $app.Id
                                HasConnectionStrings = $true
                                Count                = $connStrings.Count
                            }
                            $connectionStringsInfo += $connInfo
                        }
                    }
                    if (-not $SkipExport -and $connectionStringsInfo) {
                        Export-AzCPResultsToCSV -Data $connectionStringsInfo -FilePath "$subDirectory\connection_strings_info.csv"
                    }
                    
                    # Check App Settings (often contain secrets)
                    Write-Host "[*] Checking App Service settings..." -ForegroundColor Cyan
                    $appSettingsInfo = @()
                    foreach ($app in $functionApps) {
                        $settings = Get-AzCPAppServiceSettings -ResourceGroupName $app.ResourceGroup -AppServiceName $app.Name
                        if ($settings -and $settings.Count -gt 0) {
                            $potentialSecrets = $settings | Where-Object { $_.Name -match "key|secret|password|token|connection|pwd|credential" } | Select-Object -ExpandProperty Name
                            
                            $settingsInfo = [PSCustomObject]@{
                                AppName          = $app.Name
                                AppID            = $app.Id
                                HasAppSettings   = $true
                                Count            = $settings.Count
                                PotentialSecrets = ($potentialSecrets -join ", ")
                            }
                            $appSettingsInfo += $settingsInfo
                        }
                    }
                    if (-not $SkipExport -and $appSettingsInfo) {
                        Export-AzCPResultsToCSV -Data $appSettingsInfo -FilePath "$subDirectory\app_settings_info.csv"
                    }
                }
                
                # If automation accounts exist, check for runbooks
                if ($automationAccounts) {
                    Write-Host "[*] Checking for Automation Runbooks..." -ForegroundColor Cyan
                    $runbooksFound = @()
                    foreach ($account in $automationAccounts) {
                        $runbooks = Get-AzAutomationRunbook -AutomationAccountName $account.AutomationAccountName -ResourceGroupName $account.ResourceGroupName
                        
                        if ($runbooks -and $runbooks.Count -gt 0) {
                            foreach ($runbook in $runbooks) {
                                $runbookObj = [PSCustomObject]@{
                                    RunbookName           = $runbook.Name
                                    RunbookId             = $runbook.RunbookId
                                    RunbookType           = $runbook.RunbookType
                                    AutomationAccountName = $account.AutomationAccountName
                                    ResourceGroupName     = $account.ResourceGroupName
                                    State                 = $runbook.State
                                    LastModifiedTime      = $runbook.LastModifiedTime
                                }
                                $runbooksFound += $runbookObj
                            }
                        }
                    }
                    
                    if (-not $SkipExport -and $runbooksFound) {
                        Export-AzCPResultsToCSV -Data $runbooksFound -FilePath "$subDirectory\automation_runbooks.csv"
                    }
                }
                
                # If VMs exist, get more detailed information
                if ($vms) {
                    Write-Host "[*] Getting detailed VM information..." -ForegroundColor Cyan
                    
                    # Check VM network interfaces
                    $vmNetworkInfo = @()
                    foreach ($vm in $vms) {
                        $networkInterfaces = Get-AzCPVirtualMachineNetworkInterfaces -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name
                        if ($networkInterfaces) {
                            foreach ($nic in $networkInterfaces) {
                                # Check if the NIC has IP configurations
                                if ($nic.IpConfigurations -and $nic.IpConfigurations.Count -gt 0) {
                                    $privateIPAddress = $nic.IpConfigurations[0].PrivateIpAddress
                                    $hasPublicIP = if ($nic.IpConfigurations[0].PublicIpAddress) { "Has public IP" } else { "No public IP" }
                                }
                                else {
                                    $privateIPAddress = "No IP configuration"
                                    $hasPublicIP = "No IP configuration"
                                }
                                
                                $nicInfo = [PSCustomObject]@{
                                    VMName               = $vm.Name
                                    VMID                 = $vm.Id
                                    NetworkInterfaceName = $nic.Name
                                    NetworkInterfaceID   = $nic.Id
                                    PrivateIPAddress     = $privateIPAddress
                                    PublicIPAddress      = $hasPublicIP
                                }
                                $vmNetworkInfo += $nicInfo
                            }
                        }
                    }
                    
                    if (-not $SkipExport -and $vmNetworkInfo) {
                        Export-AzCPResultsToCSV -Data $vmNetworkInfo -FilePath "$subDirectory\vm_network_info.csv"
                    }
                    
                    # Check VM run commands
                    $vmRunCommands = @()
                    foreach ($vm in $vms) {
                        try {
                            $runCommands = Get-AzCPVMRunCommands -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name
                            if ($runCommands) {
                                foreach ($cmd in $runCommands) {
                                    $vmRunCommands += $cmd
                                }
                            }
                        }
                        catch {
                            Write-Verbose "Could not get run commands for VM $($vm.Name): $_"
                        }
                    }
                    
                    if (-not $SkipExport -and $vmRunCommands) {
                        Export-AzCPResultsToCSV -Data $vmRunCommands -FilePath "$subDirectory\vm_run_commands.csv"
                    }
                }
                
                # Try to check storage account keys (highly sensitive)
                if ($storageAccounts) {
                    Write-Host "[*] Attempting to get storage account keys (high value)..." -ForegroundColor Cyan
                    $storageAccountKeyInfo = @()
                    foreach ($sa in $storageAccounts) {
                        try {
                            $keys = Get-AzCPStorageAccountKeys -ResourceGroupName $sa.ResourceGroupName -StorageAccountName $sa.StorageAccountName
                            if ($keys -and $keys.Count -gt 0) {
                                $keyInfo = [PSCustomObject]@{
                                    StorageAccountName = $sa.StorageAccountName
                                    StorageAccountID   = $sa.Id
                                    KeysAccessible     = $true
                                    KeyCount           = $keys.Count
                                }
                                $storageAccountKeyInfo += $keyInfo
                                Write-Host "[!] Found accessible keys for storage account $($sa.StorageAccountName)!" -ForegroundColor Yellow
                            }
                        }
                        catch {
                            $keyInfo = [PSCustomObject]@{
                                StorageAccountName = $sa.StorageAccountName
                                StorageAccountID   = $sa.Id
                                KeysAccessible     = $false
                                KeyCount           = 0
                            }
                            $storageAccountKeyInfo += $keyInfo
                        }
                    }
                    
                    if (-not $SkipExport -and $storageAccountKeyInfo) {
                        Export-AzCPResultsToCSV -Data $storageAccountKeyInfo -FilePath "$subDirectory\storage_account_key_access.csv"
                    }
                }
                
                # Check permissions for important resources
                Write-Host "[*] Checking permissions for important resources..." -ForegroundColor Cyan
                $permissionFindings = @()
                
                # Check permissions on VMs
                if ($vms) {
                    foreach ($vm in $vms) {
                        $permissionResults = Test-AzCPResourceActions -ResourceID $vm.Id
                        foreach ($result in $permissionResults) {
                            $result | Add-Member -NotePropertyName "ResourceType" -NotePropertyValue "VirtualMachine" -Force
                            $result | Add-Member -NotePropertyName "ResourceName" -NotePropertyValue $vm.Name -Force
                            $permissionFindings += $result
                        }
                    }
                }
                
                # Check permissions on Key Vaults
                if ($keyVaults) {
                    foreach ($kv in $keyVaults) {
                        $permissionResults = Test-AzCPResourceActions -ResourceID $kv.ResourceId
                        foreach ($result in $permissionResults) {
                            $result | Add-Member -NotePropertyName "ResourceType" -NotePropertyValue "KeyVault" -Force
                            $result | Add-Member -NotePropertyName "ResourceName" -NotePropertyValue $kv.VaultName -Force
                            $permissionFindings += $result
                        }
                    }
                }
                
                # Check permissions on Storage Accounts
                if ($storageAccounts) {
                    foreach ($sa in $storageAccounts) {
                        $permissionResults = Test-AzCPResourceActions -ResourceID $sa.Id
                        foreach ($result in $permissionResults) {
                            $result | Add-Member -NotePropertyName "ResourceType" -NotePropertyValue "StorageAccount" -Force
                            $result | Add-Member -NotePropertyName "ResourceName" -NotePropertyValue $sa.StorageAccountName -Force
                            $permissionFindings += $result
                        }
                    }
                }
                
                # Check permissions on Function Apps
                if ($functionApps) {
                    foreach ($app in $functionApps) {
                        $permissionResults = Test-AzCPResourceActions -ResourceID $app.Id
                        foreach ($result in $permissionResults) {
                            $result | Add-Member -NotePropertyName "ResourceType" -NotePropertyValue "FunctionApp" -Force
                            $result | Add-Member -NotePropertyName "ResourceName" -NotePropertyValue $app.Name -Force
                            $permissionFindings += $result
                        }
                    }
                }
                
                # Check subscription-level permissions for privilege escalation
                $subPermissionResults = Test-AzCPResourceActions -ResourceID "/subscriptions/$subscriptionId"
                foreach ($result in $subPermissionResults) {
                    $result | Add-Member -NotePropertyName "ResourceType" -NotePropertyValue "Subscription" -Force
                    $result | Add-Member -NotePropertyName "ResourceName" -NotePropertyValue $subscriptionName -Force
                    $permissionFindings += $result
                }
                
                # Export permission findings
                if (-not $SkipExport -and $permissionFindings) {
                    Export-AzCPResultsToCSV -Data $permissionFindings -FilePath "$subDirectory\permission_findings.csv"
                    
                    # Also export a filtered view of high-value permissions
                    $highValuePermissions = $permissionFindings | Where-Object { 
                        $_.Allowed -eq $true -and ($_.Action -like "*write*" -or 
                            $_.Action -like "*action*" -or 
                            $_.Action -like "*listKeys*" -or 
                            $_.Action -like "*secrets*")
                    }
                    
                    if ($highValuePermissions) {
                        Export-AzCPResultsToCSV -Data $highValuePermissions -FilePath "$subDirectory\high_value_permissions.csv"
                        Write-Host "[!] Found $($highValuePermissions.Count) high-value permissions! Check high_value_permissions.csv" -ForegroundColor Yellow
                    }
                }
            }
        }
        
        # Generate reports based on selected format
        if (-not $SkipExport -and $ReportFormat -ne "None") {
            if ($ReportFormat -eq "Markdown" -or $ReportFormat -eq "Both") {
                Write-Host "[*] Generating markdown reports..." -ForegroundColor Cyan
                $markdownReportPath = New-AzCPEnumerationMarkdownReport -InputDirectory $OutputDirectory
                Write-Host "[+] Consolidated markdown report saved to $markdownReportPath" -ForegroundColor Green
            }
            
            if ($ReportFormat -eq "HTML" -or $ReportFormat -eq "Both") {
                Write-Host "[*] Generating HTML reports..." -ForegroundColor Cyan
                $htmlReportPath = New-AzCPEnumerationHtmlReport -InputDirectory $OutputDirectory
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

# Function to validate Azure connection
function Test-AzCPConnection {
    [CmdletBinding()]
    param()
    
    try {
        $context = Get-AzContext
        if (-not $context) {
            return $false
        }
        return $true
    }
    catch {
        return $false
    }
}

# Function to connect to Azure and start enumeration in one step
function Start-AzCPAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$Interactive,
        
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputDirectory = ".\AzureEnum_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
        
        [Parameter(Mandatory = $false)]
        [switch]$Comprehensive,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("None", "Markdown", "HTML", "Both")]
        [string]$ReportFormat = "Both"
    )
    
    try {
        # Check if already connected to Azure
        $connected = Test-AzCPConnection
        
        if (-not $connected) {
            Write-Host "[*] Not connected to Azure. Initiating connection..." -ForegroundColor Cyan
            
            # Connect to Azure
            if ($Interactive) {
                if ($TenantId) {
                    Connect-AzAccount -TenantId $TenantId
                }
                else {
                    Connect-AzAccount
                }
            }
            else {
                if ($TenantId) {
                    Connect-AzAccount -TenantId $TenantId -UseDeviceAuthentication
                }
                else {
                    Connect-AzAccount -UseDeviceAuthentication
                }
            }
            
            # Verify connection was successful
            $connected = Test-AzCPConnection
            if (-not $connected) {
                Write-Error "[-] Failed to connect to Azure. Please try again."
                return
            }
        }
        
        # Start enumeration
        Write-Host "[*] Starting Azure enumeration..." -ForegroundColor Cyan
        Start-AzCPEnumeration -OutputDirectory $OutputDirectory -Comprehensive:$Comprehensive -ReportFormat $ReportFormat
    }
    catch {
        Write-Error "[-] An error occurred: $_"
    }
}