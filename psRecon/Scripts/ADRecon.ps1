function Invoke-ADRecon {
    Write-Output "=== Active Directory Reconnaissance Script ==="

    # Roasting Category
    Write-Output "`n========== Roasting =========="

    # ASREPRoasting
    Write-Output "`n--- ASREPRoasting ---"
    try {
        Get-DomainUser -PreauthNotRequired | Select samaccountname, userprincipalname, useraccountcontrol | Format-List
    } catch {
        Write-Output "Error running ASREPRoasting command: $_"
    }

    # Kerberoasting
    Write-Output "`n--- Kerberoasting ---"
    try {
        Invoke-Kerberoast
    } catch {
        Write-Output "Error running Kerberoasting command: $_"
    }

    # Delegation Category
    Write-Output "`n========== Delegation =========="

    # Unconstrained Delegation
    Write-Output "`n--- Unconstrained Delegation ---"
    try {
        Get-NetComputer -Unconstrained | Select -Property name
        Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
    } catch {
        Write-Output "Error running Unconstrained Delegation commands: $_"
    }

    # Constrained Delegation
    Write-Output "`n--- Constrained Delegation ---"
    try {
        Get-DomainComputer -TrustedToAuth
        Get-DomainUser -TrustedToAuth
    } catch {
        Write-Output "Error running Constrained Delegation commands: $_"
    }

    # Resource-Based Constrained Delegation (RBCD)
    Write-Output "`n--- Resource-Based Constrained Delegation (RBCD) ---"

    function Resolve-SIDToName {
        param (
            [string]$SID
        )
        try {
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($SID)
            return $sidObj.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            return $SID # Return the SID itself if it cannot be resolved
        }
    }

    function Get-DangerousPerms {
        $targetPermissions = @("WriteDacl", "GenericAll", "GenericWrite", "WriteProperty", "Self", "AllExtendedRights", "WriteOwner")
        $extendedRights = @("User-Force-Change-Password", "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All", "Self-membership", "Validated-SPN")
        $excludedAccounts = @(
            "Domain Admins", "Enterprise Admins", "Administrators", "Creator Owner",
            "NT AUTHORITY\\SELF", "NT AUTHORITY\\SYSTEM", "SELF", "SYSTEM",
            "NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS", "ENTERPRISE DOMAIN CONTROLLERS"
        )
        $excludedObjects = @("DFSR-LocalSettings", "Domain System Volume", "SYSVOL Subscription")
        $results = @()
        $allAcls = Get-DomainObjectAcl -ResolveGUIDs

        foreach ($acl in $allAcls) {
            if ($targetPermissions -contains $acl.ActiveDirectoryRights -or $extendedRights -contains $acl.ObjectType) {
                $resolvedAccountWithPermission = Resolve-SIDToName -SID $acl.SecurityIdentifier
                if ($resolvedAccountWithPermission -eq $acl.SecurityIdentifier) { continue }

                $targetObject = ($acl.ObjectDN -split ',')[0] -replace '^CN=', ''
                if ($excludedObjects -contains $targetObject) { continue }

                $accountBaseName = $resolvedAccountWithPermission.Split('\')[-1]
                if ($excludedAccounts -notcontains $accountBaseName -and $excludedAccounts -notcontains $resolvedAccountWithPermission) {
                    $results += [PSCustomObject]@{
                        AccountWithPermission = $resolvedAccountWithPermission
                        PermissionType        = $acl.ActiveDirectoryRights
                        ExtendedRight         = $acl.ObjectType
                        TargetObject          = $targetObject
                    }
                }
            }
        }
        Write-Output "Users or Groups with Specified Permissions and Extended Rights (Excluding Privileged Groups, Accounts, and Objects):"
        $results | Format-Table -AutoSize
    }

    try {
        Get-DangerousPerms
    } catch {
        Write-Output "Error running RBCD checks: $_"
    }
}

# To run the script, simply call the function:
# Invoke-ADRecon