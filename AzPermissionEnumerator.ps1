<#
.SYNOPSIS
AZ PERMISSION ENUMERATOR - Enumerate Azure user permissions without subscription access

.DESCRIPTION
A PowerShell script that identifies Azure permissions and access levels for users who don't have
direct subscription access. Focuses on user roles, permissions, and accessible resources.

.NOTES
Author: Based on Ryan Watson's COBALT PROPHET toolkit
Version: 1.0.0
Requires: PowerShell 5.1 or higher, Az PowerShell modules
#>

# Base Functions
function Test-AzConnection {
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

function Get-AzUserInfo {
    [CmdletBinding()]
    param()
    
    try {
        $context = Get-AzContext
        $account = $context.Account
        
        if ($account) {
            $userType = $account.Type
            $userId = $account.Id
            
            $userInfo = [PSCustomObject]@{
                UserId   = $userId
                UserType = $userType
                TenantId = $context.Tenant.Id
                Name     = $context.Tenant.Directory
            }
            
            Write-Host "[+] Successfully retrieved user information for $userId" -ForegroundColor Green
            return $userInfo
        }
        else {
            Write-Error "[-] Failed to retrieve user information. No account context found."
            return $null
        }
    }
    catch {
        Write-Error "[-] Failed to retrieve user information. Error: $_"
        return $null
    }
}

function Get-AzDirectoryRoles {
    [CmdletBinding()]
    param()
    
    try {
        $roles = Get-AzRoleDefinition
        
        if ($roles) {
            Write-Host "[+] Successfully retrieved $($roles.Count) Azure role definitions" -ForegroundColor Green
            return $roles
        }
        else {
            Write-Warning "[-] No Azure role definitions found."
            return $null
        }
    }
    catch {
        Write-Warning "[-] Failed to retrieve Azure role definitions. Error: $_"
        return $null
    }
}

function Get-AzUserAssignedRoles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$UserId
    )
    
    try {
        if (-not $UserId) {
            $context = Get-AzContext
            $UserId = $context.Account.Id
        }
        
        $assignments = Get-AzRoleAssignment -SignInName $UserId -ErrorAction SilentlyContinue
        
        if ($assignments) {
            Write-Host "[+] Successfully retrieved $($assignments.Count) role assignments for user $UserId" -ForegroundColor Green
            return $assignments
        }
        else {
            # Try to get assignments by Object ID if SignInName fails
            try {
                # This might fail if the user doesn't have permissions to read Graph data
                $userObjectId = (Get-AzADUser -UserPrincipalName $UserId).Id
                if ($userObjectId) {
                    $assignments = Get-AzRoleAssignment -ObjectId $userObjectId -ErrorAction SilentlyContinue
                    if ($assignments) {
                        Write-Host "[+] Successfully retrieved $($assignments.Count) role assignments for user $UserId by ObjectId" -ForegroundColor Green
                        return $assignments
                    }
                }
            }
            catch {
                Write-Verbose "Could not retrieve user object ID: $_"
            }
            
            Write-Warning "[-] No role assignments found for user $UserId using standard methods."
            return @()
        }
    }
    catch {
        Write-Warning "[-] Failed to retrieve role assignments for user $UserId. Error: $_"
        return @()
    }
}

function Get-AzUserAccessibleSubscriptions {
    [CmdletBinding()]
    param()
    
    try {
        $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue
        
        if ($subscriptions -and $subscriptions.Count -gt 0) {
            Write-Host "[+] Found $($subscriptions.Count) accessible subscriptions" -ForegroundColor Green
            return $subscriptions
        }
        else {
            Write-Warning "[-] No accessible subscriptions found."
            return @()
        }
    }
    catch {
        Write-Warning "[-] Failed to retrieve subscriptions. Error: $_"
        return @()
    }
}

function Get-AzUserAccessibleResourceGroups {
    [CmdletBinding()]
    param()
    
    try {
        $resourceGroups = @()
        $subscriptions = Get-AzUserAccessibleSubscriptions
        
        foreach ($sub in $subscriptions) {
            try {
                Set-AzContext -Subscription $sub.Id | Out-Null
                $groups = Get-AzResourceGroup -ErrorAction SilentlyContinue
                
                if ($groups) {
                    foreach ($group in $groups) {
                        $group | Add-Member -NotePropertyName "SubscriptionId" -NotePropertyValue $sub.Id -Force
                        $group | Add-Member -NotePropertyName "SubscriptionName" -NotePropertyValue $sub.Name -Force
                        $resourceGroups += $group
                    }
                }
            }
            catch {
                Write-Verbose "Could not access resource groups in subscription $($sub.Id): $_"
            }
        }
        
        if ($resourceGroups.Count -gt 0) {
            Write-Host "[+] Found $($resourceGroups.Count) accessible resource groups" -ForegroundColor Green
            return $resourceGroups
        }
        else {
            Write-Warning "[-] No accessible resource groups found."
            return @()
        }
    }
    catch {
        Write-Warning "[-] Failed to retrieve resource groups. Error: $_"
        return @()
    }
}

function Get-AzUserAccessibleResources {
    [CmdletBinding()]
    param()
    
    try {
        $resources = @()
        $subscriptions = Get-AzUserAccessibleSubscriptions
        
        foreach ($sub in $subscriptions) {
            try {
                Set-AzContext -Subscription $sub.Id | Out-Null
                $subResources = Get-AzResource -ErrorAction SilentlyContinue
                
                if ($subResources) {
                    foreach ($resource in $subResources) {
                        $resource | Add-Member -NotePropertyName "SubscriptionId" -NotePropertyValue $sub.Id -Force
                        $resource | Add-Member -NotePropertyName "SubscriptionName" -NotePropertyValue $sub.Name -Force
                        $resources += $resource
                    }
                }
            }
            catch {
                Write-Verbose "Could not access resources in subscription $($sub.Id): $_"
            }
        }
        
        if ($resources.Count -gt 0) {
            Write-Host "[+] Found $($resources.Count) accessible resources" -ForegroundColor Green
            return $resources
        }
        else {
            Write-Warning "[-] No accessible resources found via standard methods."
            return @()
        }
    }
    catch {
        Write-Warning "[-] Failed to retrieve resources. Error: $_"
        return @()
    }
}

function Get-AzUserAccessibleResourcesByType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceType
    )
    
    try {
        $resources = @()
        $subscriptions = Get-AzUserAccessibleSubscriptions
        
        foreach ($sub in $subscriptions) {
            try {
                Set-AzContext -Subscription $sub.Id | Out-Null
                $subResources = Get-AzResource -ResourceType $ResourceType -ErrorAction SilentlyContinue
                
                if ($subResources) {
                    foreach ($resource in $subResources) {
                        $resource | Add-Member -NotePropertyName "SubscriptionId" -NotePropertyValue $sub.Id -Force
                        $resource | Add-Member -NotePropertyName "SubscriptionName" -NotePropertyValue $sub.Name -Force
                        $resources += $resource
                    }
                }
            }
            catch {
                Write-Verbose "Could not access $ResourceType resources in subscription $($sub.Id): $_"
            }
        }
        
        Write-Host "[+] Found $($resources.Count) accessible $ResourceType resources" -ForegroundColor Green
        return $resources
    }
    catch {
        Write-Warning "[-] Failed to retrieve $ResourceType resources. Error: $_"
        return @()
    }
}

function Test-AzUserResourceActions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceId
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
        try {
            # This will check if the current user can perform the action on the resource
            $allowed = Get-AzRoleAssignment | Where-Object {
                $_.Scope -eq $ResourceId -or $_.Scope -eq "/" -or 
                $ResourceId -like "$($_.Scope)/*"
            } | ForEach-Object {
                $roleDef = Get-AzRoleDefinition -Name $_.RoleDefinitionName -ErrorAction SilentlyContinue
                if ($roleDef) {
                    $roleDef.Actions -contains $action -or $roleDef.Actions -contains "*"
                }
                else {
                    $false
                }
            } | Where-Object { $_ -eq $true } | Select-Object -First 1
            
            $results += [PSCustomObject]@{
                ResourceID = $ResourceId
                Action     = $action
                Allowed    = [bool]$allowed
            }
        }
        catch {
            Write-Verbose "Could not test action $action on resource $ResourceId. Error: $_"
            $results += [PSCustomObject]@{
                ResourceID = $ResourceId
                Action     = $action
                Allowed    = $false
                Error      = $_.Exception.Message
            }
        }
    }
    
    return $results
}

function Get-AzUserDirectoryGroups {
    [CmdletBinding()]
    param()
    
    try {
        # Get current user's group memberships
        $groups = Get-AzADGroup -ErrorAction SilentlyContinue
        
        if ($groups) {
            Write-Host "[+] Successfully retrieved Azure AD groups. User may have directory read access." -ForegroundColor Green
            return $groups
        }
        else {
            Write-Warning "[-] No Azure AD groups found or user lacks permissions to view them."
            return @()
        }
    }
    catch {
        Write-Warning "[-] Failed to retrieve Azure AD groups. User likely lacks directory read permissions. Error: $_"
        return @()
    }
}

function Get-AzUserMemoryMappedToken {
    [CmdletBinding()]
    param()
    
    try {
        $token = Get-AzAccessToken -ErrorAction SilentlyContinue
        
        if ($token) {
            # Don't actually show the token in the output
            $tokenInfo = [PSCustomObject]@{
                Token        = "Retrieved Successfully - Use Get-AzAccessToken to view"
                ExpiresOn    = $token.ExpiresOn
                TokenType    = $token.TokenType
                TenantId     = $token.TenantId
                UserId       = (Get-AzContext).Account.Id
                Scopes       = "https://management.azure.com/"
                IsValid      = $true
            }
            
            Write-Host "[+] Successfully retrieved Azure access token" -ForegroundColor Green
            return $tokenInfo
        }
        else {
            Write-Warning "[-] No Azure access token found or user lacks permissions."
            return $null
        }
    }
    catch {
        Write-Warning "[-] Failed to retrieve Azure access token. Error: $_"
        return $null
    }
}

function Get-AzUserARMAccess {
    [CmdletBinding()]
    param()
    
    try {
        # Test if we can interact with ARM API
        $result = Invoke-AzRestMethod -Path "/subscriptions?api-version=2020-01-01" -Method GET -ErrorAction SilentlyContinue
        
        if ($result.StatusCode -eq 200) {
            # Successfully connected to ARM API
            $output = [PSCustomObject]@{
                ARMAccessible = $true
                StatusCode    = $result.StatusCode
                ResponseBody  = ($result.Content | ConvertFrom-Json).value
                Method        = "GET"
                Path          = "/subscriptions?api-version=2020-01-01"
            }
            
            Write-Host "[+] Successfully accessed Azure Resource Manager API" -ForegroundColor Green
            return $output
        }
        else {
            # Connected but got a different status code
            $output = [PSCustomObject]@{
                ARMAccessible = $false
                StatusCode    = $result.StatusCode
                ResponseBody  = $result.Content
                Method        = "GET"
                Path          = "/subscriptions?api-version=2020-01-01"
            }
            
            Write-Warning "[-] Access to Azure Resource Manager API returned status code $($result.StatusCode)"
            return $output
        }
    }
    catch {
        Write-Warning "[-] Failed to access Azure Resource Manager API. Error: $_"
        return [PSCustomObject]@{
            ARMAccessible = $false
            StatusCode    = 0
            ResponseBody  = $_.Exception.Message
            Method        = "GET"
            Path          = "/subscriptions?api-version=2020-01-01"
        }
    }
}

function Test-AzUserResourceProvider {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProviderNamespace
    )
    
    try {
        $subscriptions = Get-AzUserAccessibleSubscriptions
        
        if ($subscriptions.Count -eq 0) {
            Write-Warning "[-] No accessible subscriptions found to test resource provider access."
            return $false
        }
        
        # Try each subscription until we find one where we can test the provider
        foreach ($sub in $subscriptions) {
            try {
                Set-AzContext -Subscription $sub.Id | Out-Null
                $provider = Get-AzResourceProvider -ProviderNamespace $ProviderNamespace -ErrorAction SilentlyContinue
                
                if ($provider) {
                    Write-Host "[+] Successfully accessed $ProviderNamespace resource provider in subscription $($sub.Id)" -ForegroundColor Green
                    return $true
                }
            }
            catch {
                Write-Verbose "Could not access $ProviderNamespace provider in subscription $($sub.Id): $_"
            }
        }
        
        Write-Warning "[-] Could not access $ProviderNamespace resource provider in any subscription."
        return $false
    }
    catch {
        Write-Warning "[-] Failed to test resource provider access. Error: $_"
        return $false
    }
}

function Get-AzUserManagedIdentityAccess {
    [CmdletBinding()]
    param()
    
    try {
        $identities = @()
        $subscriptions = Get-AzUserAccessibleSubscriptions
        
        foreach ($sub in $subscriptions) {
            try {
                Set-AzContext -Subscription $sub.Id | Out-Null
                $subIdentities = Get-AzUserAssignedIdentity -ErrorAction SilentlyContinue
                
                if ($subIdentities) {
                    foreach ($identity in $subIdentities) {
                        $identity | Add-Member -NotePropertyName "SubscriptionId" -NotePropertyValue $sub.Id -Force
                        $identity | Add-Member -NotePropertyName "SubscriptionName" -NotePropertyValue $sub.Name -Force
                        $identities += $identity
                    }
                }
            }
            catch {
                Write-Verbose "Could not access managed identities in subscription $($sub.Id): $_"
            }
        }
        
        if ($identities.Count -gt 0) {
            Write-Host "[+] Found $($identities.Count) accessible managed identities" -ForegroundColor Green
            return $identities
        }
        else {
            Write-Warning "[-] No accessible managed identities found."
            return @()
        }
    }
    catch {
        Write-Warning "[-] Failed to retrieve managed identities. Error: $_"
        return @()
    }
}

function Export-AzUserPermissionResultsToCSV {
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

function Convert-AzUserPermissionToMDReport {
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
        $markdownContent += "- Report generated by AZ PERMISSION ENUMERATOR`n"
        
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

function New-AzUserPermissionMDReport {
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
            $OutputPath = Join-Path -Path $InputDirectory -ChildPath "AzPermissionEnumerator_Report_$timestamp.md"
        }
        
        # Create the markdown content
        $markdownContent = "# AZ PERMISSION ENUMERATOR - User Access Report`n`n"
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
        
        $markdownContent += "`n## User Access Summary`n`n"
        
        # Add a summary of high-value findings
        $highValueFiles = $csvFiles | Where-Object { $_.Name -match "role_assignments|permissions|access|high_value" }
        if ($highValueFiles -and $highValueFiles.Count -gt 0) {
            $markdownContent += "### Key Access Findings`n`n"
            $markdownContent += "The following high-value access permissions were identified:`n`n"
            
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
                    Convert-AzUserPermissionToMDReport -CsvPath $file.FullName -Title "Detailed Report: $fileName"
                }
                
                $markdownContent += "`n"
            }
        }
        
        # Add a note about the tool
        $markdownContent += "`n## About`n`n"
        $markdownContent += "This report was generated by AZ PERMISSION ENUMERATOR, a tool for identifying Azure user permissions even without direct subscription access.`n"
        
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

function Convert-AzUserPermissionToHTMLReport {
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
        <strong>Security Notice:</strong> This report contains information about Azure user permissions. Handle with care.
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
                elseif ($cellValue -match "Owner|Contributor|Admin" -and $cellValue -ne "") {
                    $htmlContent += "                    <td style='background-color: #ffdddd; font-weight: bold;'>$cellValue</td>`n"
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
            <li>Report generated by AZ PERMISSION ENUMERATOR</li>
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

function New-AzUserPermissionHTMLReport {
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
            $OutputPath = Join-Path -Path $InputDirectory -ChildPath "AzPermissionEnumerator_Report_$timestamp.html"
        }
        
        # Create HTML header and CSS
        $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AZ PERMISSION ENUMERATOR - User Access Report</title>
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
        .highlight-owner {
            background-color: #ffdddd;
            font-weight: bold;
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
    <h1>AZ PERMISSION ENUMERATOR - User Access Report</h1>
    <p>Report generated on $(Get-Date)</p>
    <div class="security-warning">
        <strong>Security Notice:</strong> This report contains information about Azure user permissions. Handle with care.
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
            <li><a href="#summary">User Access Summary</a></li>
"@

        # Add high-value findings section to TOC if applicable
        $highValueFiles = $csvFiles | Where-Object { $_.Name -match "role_assignments|permissions|access|high_value" }
        if ($highValueFiles -and $highValueFiles.Count -gt 0) {
            $htmlContent += "            <li><a href='#high-value'>Key Access Findings</a></li>`n"
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
        <h2>User Access Summary</h2>
        <p>This report contains data from ${$csvFiles.Count} CSV files documenting Azure permissions for the current user.</p>
"@
        
        # Add high-value findings section if applicable
        if ($highValueFiles -and $highValueFiles.Count -gt 0) {
            $htmlContent += @"
        <div class="high-value" id="high-value">
            <h3>Key Access Findings</h3>
            <p>The following high-value access permissions were identified:</p>
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
                        elseif ($cellValue -match "Owner|Contributor|Admin" -and $cellValue -ne "") {
                            $htmlContent += "                            <td class='highlight-owner'>$cellValue</td>`n"
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
                    $detailedReportPath = Convert-AzUserPermissionToHTMLReport -CsvPath $file.FullName -Title "Detailed Report: $fileName"
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
<p>This report was generated by AZ PERMISSION ENUMERATOR, a tool for identifying Azure user permissions even without direct subscription access.</p>
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

function Test-AzPassthroughAuth {
    [CmdletBinding()]
    param()
    
    try {
        # Try to see if the current credential can be used to authenticate to other services
        # First, check if we can get an access token for Microsoft Graph
        $graphToken = Get-AzAccessToken -ResourceTypeName MSGraph -ErrorAction SilentlyContinue
        $armToken = Get-AzAccessToken -ResourceTypeName ARM -ErrorAction SilentlyContinue
        $keyVaultToken = Get-AzAccessToken -ResourceTypeName KeyVault -ErrorAction SilentlyContinue
        
        $results = [PSCustomObject]@{
            ARMToken = $null -ne $armToken
            GraphToken = $null -ne $graphToken
            KeyVaultToken = $null -ne $keyVaultToken
            ARMTokenExpiresOn = if ($armToken) { $armToken.ExpiresOn } else { $null }
            GraphTokenExpiresOn = if ($graphToken) { $graphToken.ExpiresOn } else { $null }
            KeyVaultTokenExpiresOn = if ($keyVaultToken) { $keyVaultToken.ExpiresOn } else { $null }
        }
        
        Write-Host "[+] Successfully tested passthrough authentication capabilities" -ForegroundColor Green
        return $results
    }
    catch {
        Write-Warning "[-] Failed to test passthrough authentication. Error: $_"
        return [PSCustomObject]@{
            ARMToken = $false
            GraphToken = $false
            KeyVaultToken = $false
            ARMTokenExpiresOn = $null
            GraphTokenExpiresOn = $null
            KeyVaultTokenExpiresOn = $null
        }
    }
}

# Main Enumeration Function
function Start-AzUserPermissionEnumeration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputDirectory = ".\AzPermissionEnum_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipExport,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("None", "Markdown", "HTML", "Both")]
        [string]$ReportFormat = "Both",
        
        [Parameter(Mandatory = $false)]
        [switch]$PreAuthenticatedContext
    )
    
    try {
        Write-Host "[*] Starting Azure permission enumeration" -ForegroundColor Cyan
        
        # Check if already authenticated or need to authenticate
        if (-not $PreAuthenticatedContext) {
            Write-Host "[*] Verifying connection to Azure..." -ForegroundColor Cyan
            
            # Test connection to Azure
            $connected = Test-AzConnection
            if (-not $connected) {
                Write-Error "[-] Not connected to Azure. Please run Connect-AzAccount before using this tool."
                return
            }
        }
        
        Write-Host "[+] Connected to Azure" -ForegroundColor Green
        
        # Create output directory if export is enabled
        if (-not $SkipExport) {
            if (-not (Test-Path -Path $OutputDirectory)) {
                New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
                Write-Host "[+] Created output directory: $OutputDirectory" -ForegroundColor Green
            }
        }
        
        # Create user info directory
        $userInfoDirectory = "$OutputDirectory\UserInfo"
        if (-not $SkipExport) {
            if (-not (Test-Path -Path $userInfoDirectory)) {
                New-Item -Path $userInfoDirectory -ItemType Directory -Force | Out-Null
            }
        }
        
        # Get current user information
        Write-Host "[*] Retrieving user account information..." -ForegroundColor Cyan
        $userInfo = Get-AzUserInfo
        if (-not $SkipExport -and $userInfo) {
            Export-AzUserPermissionResultsToCSV -Data $userInfo -FilePath "$userInfoDirectory\user_info.csv"
        }
        
        # Test passthrough authentication
        Write-Host "[*] Testing passthrough authentication capabilities..." -ForegroundColor Cyan
        $passthroughAuth = Test-AzPassthroughAuth
        if (-not $SkipExport -and $passthroughAuth) {
            Export-AzUserPermissionResultsToCSV -Data $passthroughAuth -FilePath "$userInfoDirectory\passthrough_auth.csv"
        }
        
        # Try getting memory-mapped tokens
        Write-Host "[*] Checking for available access tokens..." -ForegroundColor Cyan
        $tokenInfo = Get-AzUserMemoryMappedToken
        if (-not $SkipExport -and $tokenInfo) {
            Export-AzUserPermissionResultsToCSV -Data $tokenInfo -FilePath "$userInfoDirectory\token_info.csv"
        }
        
        # Test direct ARM API access
        Write-Host "[*] Testing direct ARM API access..." -ForegroundColor Cyan
        $armAccess = Get-AzUserARMAccess
        if (-not $SkipExport -and $armAccess) {
            Export-AzUserPermissionResultsToCSV -Data $armAccess -FilePath "$userInfoDirectory\arm_access.csv"
        }
        
        # Get directory roles and definitions if possible
        Write-Host "[*] Checking for directory role definitions..." -ForegroundColor Cyan
        $directoryRoles = Get-AzDirectoryRoles
        if (-not $SkipExport -and $directoryRoles) {
            Export-AzUserPermissionResultsToCSV -Data $directoryRoles -FilePath "$userInfoDirectory\directory_roles.csv"
        }
        
        # Check for Azure AD group memberships
        Write-Host "[*] Checking for Azure AD group memberships..." -ForegroundColor Cyan
        $directoryGroups = Get-AzUserDirectoryGroups
        if (-not $SkipExport -and $directoryGroups) {
            Export-AzUserPermissionResultsToCSV -Data $directoryGroups -FilePath "$userInfoDirectory\directory_groups.csv"
        }
        
        # Get user's role assignments
        Write-Host "[*] Retrieving user role assignments..." -ForegroundColor Cyan
        $roleAssignments = Get-AzUserAssignedRoles
        if (-not $SkipExport -and $roleAssignments) {
            Export-AzUserPermissionResultsToCSV -Data $roleAssignments -FilePath "$userInfoDirectory\user_role_assignments.csv"
        }
        
        # Check for subscription access
        Write-Host "[*] Checking for accessible subscriptions..." -ForegroundColor Cyan
        $subscriptions = Get-AzUserAccessibleSubscriptions
        if (-not $SkipExport -and $subscriptions) {
            Export-AzUserPermissionResultsToCSV -Data $subscriptions -FilePath "$userInfoDirectory\accessible_subscriptions.csv"
        }
        
        # Create a resources directory if there are subscriptions
        if ($subscriptions -and $subscriptions.Count -gt 0) {
            $resourcesDirectory = "$OutputDirectory\Resources"
            if (-not $SkipExport) {
                if (-not (Test-Path -Path $resourcesDirectory)) {
                    New-Item -Path $resourcesDirectory -ItemType Directory -Force | Out-Null
                }
            }
            
            # Get resource groups
            Write-Host "[*] Checking for accessible resource groups..." -ForegroundColor Cyan
            $resourceGroups = Get-AzUserAccessibleResourceGroups
            if (-not $SkipExport -and $resourceGroups) {
                Export-AzUserPermissionResultsToCSV -Data $resourceGroups -FilePath "$resourcesDirectory\resource_groups.csv"
            }
            
            # Get all resources
            Write-Host "[*] Checking for all accessible resources..." -ForegroundColor Cyan
            $resources = Get-AzUserAccessibleResources
            if (-not $SkipExport -and $resources) {
                Export-AzUserPermissionResultsToCSV -Data $resources -FilePath "$resourcesDirectory\all_resources.csv"
            }
            
            # Check for specific resource types
            
            # Check for Storage Accounts
            Write-Host "[*] Checking for accessible Storage Accounts..." -ForegroundColor Cyan
            $storageAccounts = Get-AzUserAccessibleResourcesByType -ResourceType "Microsoft.Storage/storageAccounts"
            if (-not $SkipExport -and $storageAccounts) {
                Export-AzUserPermissionResultsToCSV -Data $storageAccounts -FilePath "$resourcesDirectory\storage_accounts.csv"
            }
            
            # Check for Key Vaults
            Write-Host "[*] Checking for accessible Key Vaults..." -ForegroundColor Cyan
            $keyVaults = Get-AzUserAccessibleResourcesByType -ResourceType "Microsoft.KeyVault/vaults"
            if (-not $SkipExport -and $keyVaults) {
                Export-AzUserPermissionResultsToCSV -Data $keyVaults -FilePath "$resourcesDirectory\key_vaults.csv"
            }
            
            # Check for Virtual Machines
            Write-Host "[*] Checking for accessible Virtual Machines..." -ForegroundColor Cyan
            $virtualMachines = Get-AzUserAccessibleResourcesByType -ResourceType "Microsoft.Compute/virtualMachines"
            if (-not $SkipExport -and $virtualMachines) {
                Export-AzUserPermissionResultsToCSV -Data $virtualMachines -FilePath "$resourcesDirectory\virtual_machines.csv"
            }
            
            # Check for Function Apps
            Write-Host "[*] Checking for accessible Function Apps..." -ForegroundColor Cyan
            $functionApps = Get-AzUserAccessibleResourcesByType -ResourceType "Microsoft.Web/sites"
            if (-not $SkipExport -and $functionApps) {
                Export-AzUserPermissionResultsToCSV -Data $functionApps -FilePath "$resourcesDirectory\function_apps.csv"
            }
            
            # Check for Network Security Groups
            Write-Host "[*] Checking for accessible Network Security Groups..." -ForegroundColor Cyan
            $nsgs = Get-AzUserAccessibleResourcesByType -ResourceType "Microsoft.Network/networkSecurityGroups"
            if (-not $SkipExport -and $nsgs) {
                Export-AzUserPermissionResultsToCSV -Data $nsgs -FilePath "$resourcesDirectory\network_security_groups.csv"
            }
            
            # Check for Public IP Addresses
            Write-Host "[*] Checking for accessible Public IP Addresses..." -ForegroundColor Cyan
            $publicIPs = Get-AzUserAccessibleResourcesByType -ResourceType "Microsoft.Network/publicIPAddresses"
            if (-not $SkipExport -and $publicIPs) {
                Export-AzUserPermissionResultsToCSV -Data $publicIPs -FilePath "$resourcesDirectory\public_ip_addresses.csv"
            }
            
            # Check for managed identities
            Write-Host "[*] Checking for accessible Managed Identities..." -ForegroundColor Cyan
            $managedIdentities = Get-AzUserManagedIdentityAccess
            if (-not $SkipExport -and $managedIdentities) {
                Export-AzUserPermissionResultsToCSV -Data $managedIdentities -FilePath "$resourcesDirectory\managed_identities.csv"
            }
            
            # Test resource provider access
            Write-Host "[*] Testing access to key resource providers..." -ForegroundColor Cyan
            $providerResults = @()
            
            $providersToTest = @(
                "Microsoft.Compute",
                "Microsoft.Storage",
                "Microsoft.KeyVault",
                "Microsoft.Web",
                "Microsoft.Network",
                "Microsoft.Authorization",
                "Microsoft.ManagedIdentity",
                "Microsoft.Resources"
            )
            
            foreach ($provider in $providersToTest) {
                $hasAccess = Test-AzUserResourceProvider -ProviderNamespace $provider
                $providerResults += [PSCustomObject]@{
                    ProviderNamespace = $provider
                    HasAccess = $hasAccess
                }
            }
            
            if (-not $SkipExport -and $providerResults) {
                Export-AzUserPermissionResultsToCSV -Data $providerResults -FilePath "$resourcesDirectory\resource_provider_access.csv"
            }
            
            # Create a permissions directory for detailed permission analysis
            $permissionsDirectory = "$OutputDirectory\Permissions"
            if (-not $SkipExport) {
                if (-not (Test-Path -Path $permissionsDirectory)) {
                    New-Item -Path $permissionsDirectory -ItemType Directory -Force | Out-Null
                }
            }
            
            # Check for resources where user has high-value permissions
            Write-Host "[*] Analyzing key resources for high-value permissions..." -ForegroundColor Cyan
            $highValuePermissions = @()
            
            # Check permissions on key vaults
            if ($keyVaults) {
                foreach ($kv in $keyVaults) {
                    $permissionResults = Test-AzUserResourceActions -ResourceId $kv.Id
                    foreach ($result in $permissionResults) {
                        if ($result.Allowed -eq $true) {
                            $result | Add-Member -NotePropertyName "ResourceType" -NotePropertyValue "KeyVault" -Force
                            $result | Add-Member -NotePropertyName "ResourceName" -NotePropertyValue $kv.Name -Force
                            $highValuePermissions += $result
                        }
                    }
                }
            }
            
            # Check permissions on storage accounts
            if ($storageAccounts) {
                foreach ($sa in $storageAccounts) {
                    $permissionResults = Test-AzUserResourceActions -ResourceId $sa.Id
                    foreach ($result in $permissionResults) {
                        if ($result.Allowed -eq $true) {
                            $result | Add-Member -NotePropertyName "ResourceType" -NotePropertyValue "StorageAccount" -Force
                            $result | Add-Member -NotePropertyName "ResourceName" -NotePropertyValue $sa.Name -Force
                            $highValuePermissions += $result
                        }
                    }
                }
            }
            
            # Check permissions on VMs
            if ($virtualMachines) {
                foreach ($vm in $virtualMachines) {
                    $permissionResults = Test-AzUserResourceActions -ResourceId $vm.Id
                    foreach ($result in $permissionResults) {
                        if ($result.Allowed -eq $true) {
                            $result | Add-Member -NotePropertyName "ResourceType" -NotePropertyValue "VirtualMachine" -Force
                            $result | Add-Member -NotePropertyName "ResourceName" -NotePropertyValue $vm.Name -Force
                            $highValuePermissions += $result
                        }
                    }
                }
            }
            
            if (-not $SkipExport -and $highValuePermissions) {
                Export-AzUserPermissionResultsToCSV -Data $highValuePermissions -FilePath "$permissionsDirectory\high_value_permissions.csv"
            }
            
            # Create a specific collection of write/modify permissions - these are the most interesting for privilege escalation
            $writePermissions = $highValuePermissions | Where-Object { 
                $_.Action -like "*write*" -or 
                $_.Action -like "*delete*" -or 
                $_.Action -like "*action*" 
            }
            
            if (-not $SkipExport -and $writePermissions) {
                Export-AzUserPermissionResultsToCSV -Data $writePermissions -FilePath "$permissionsDirectory\write_permissions.csv"
            }
        }
        else {
            Write-Warning "[!] No accessible subscriptions found. Limited user permission analysis will be performed."
        }
        
        # Generate reports based on selected format
        if (-not $SkipExport -and $ReportFormat -ne "None") {
            if ($ReportFormat -eq "Markdown" -or $ReportFormat -eq "Both") {
                Write-Host "[*] Generating markdown reports..." -ForegroundColor Cyan
                $markdownReportPath = New-AzUserPermissionMDReport -InputDirectory $OutputDirectory
                Write-Host "[+] Consolidated markdown report saved to $markdownReportPath" -ForegroundColor Green
            }
            
            if ($ReportFormat -eq "HTML" -or $ReportFormat -eq "Both") {
                Write-Host "[*] Generating HTML reports..." -ForegroundColor Cyan
                $htmlReportPath = New-AzUserPermissionHTMLReport -InputDirectory $OutputDirectory
                Write-Host "[+] Consolidated HTML report saved to $htmlReportPath" -ForegroundColor Green
            }
        }
        
        Write-Host "`n[+] Azure permission enumeration completed successfully!" -ForegroundColor Green
        Write-Host "[+] Results saved to: $OutputDirectory" -ForegroundColor Green
        
        # Return a summary object
        $summary = [PSCustomObject]@{
            UserInfo            = $userInfo
            Subscriptions       = $subscriptions.Count
            RoleAssignments     = ($roleAssignments | Measure-Object).Count
            Resources           = ($resources | Measure-Object).Count
            DirectoryGroups     = ($directoryGroups | Measure-Object).Count
            HasARMAccess        = if ($armAccess) { $armAccess.ARMAccessible } else { $false }
            HasPassthroughAuth  = if ($passthroughAuth) { ($passthroughAuth.ARMToken -or $passthroughAuth.GraphToken -or $passthroughAuth.KeyVaultToken) } else { $false }
            OutputDirectory     = $OutputDirectory
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

# Function to connect and start enumeration in one step
function Start-AzUserPermissionAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$Interactive,
        
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputDirectory = ".\AzPermissionEnum_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("None", "Markdown", "HTML", "Both")]
        [string]$ReportFormat = "Both"
    )
    
    try {
        # Check if already connected to Azure
        $connected = Test-AzConnection
        
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
            $connected = Test-AzConnection
            if (-not $connected) {
                Write-Error "[-] Failed to connect to Azure. Please try again."
                return
            }
        }
        
        # Start enumeration
        Write-Host "[*] Starting Azure permission enumeration..." -ForegroundColor Cyan
        Start-AzUserPermissionEnumeration -OutputDirectory $OutputDirectory -ReportFormat $ReportFormat -PreAuthenticatedContext
    }
    catch {
        Write-Error "[-] An error occurred: $_"
    }
}
