# Function to resolve SID to account name
function Resolve-SIDToName {
    param (
        [string]$SID
    )

    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($SID)
        return $sidObj.Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        return $SID # Return the SID itself if it cannot be resolved
    }
}

# Function to find users/groups with specific ACL permissions and extended rights
function Get-ADObjectsWithSpecificPermissions {
    # Define the permissions of interest
    $targetPermissions = @("WriteDacl", "GenericAll", "GenericWrite", "WriteProperty", "Self", "AllExtendedRights", "WriteOwner")

    # Define the extended rights of interest
    $extendedRights = @("User-Force-Change-Password", "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All", "Self-membership", "Validated-SPN")

    # Define the list of privileged groups and accounts to filter out (case-sensitive for exact match)
    $excludedAccounts = @(
        "Domain Admins", "Enterprise Admins", "Administrators", "Creator Owner",
        "NT AUTHORITY\\SELF", "NT AUTHORITY\\SYSTEM", "SELF", "SYSTEM",
        "NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS", "ENTERPRISE DOMAIN CONTROLLERS"
    )

    # Define the list of objects to exclude in the TargetObject field
    $excludedObjects = @("DFSR-LocalSettings", "Domain System Volume", "SYSVOL Subscription")

    # Create array to hold the results
    $results = @()

    # Retrieve ACLs for all AD objects
    $allAcls = Get-DomainObjectAcl -ResolveGUIDs

    foreach ($acl in $allAcls) {
        # Check if the ACL permission or extended right matches any in the target permissions or extended rights
        if ($targetPermissions -contains $acl.ActiveDirectoryRights -or $extendedRights -contains $acl.ObjectType) {
            # Resolve SID to account name of the user or group with the permission
            $resolvedAccountWithPermission = Resolve-SIDToName -SID $acl.SecurityIdentifier

            # Skip entries where the SID could not be resolved to a readable name
            if ($resolvedAccountWithPermission -eq $acl.SecurityIdentifier) {
                continue
            }

            # Resolve the name of the object that the permissions are applied over
            # Extract the "name" part from the distinguished name (e.g., "CN=Name")
            $targetObject = ($acl.ObjectDN -split ',')[0] -replace '^CN=', ''

            # Skip entries in the TargetObject field that match excluded objects
            if ($excludedObjects -contains $targetObject) {
                continue
            }

            # Extract the base name (last segment after \) for specific exclusions like "SELF" and "SYSTEM"
            $accountBaseName = $resolvedAccountWithPermission.Split('\')[-1]

            # Filter out if the account name matches any in the excluded list
            if ($excludedAccounts -notcontains $accountBaseName -and 
                $excludedAccounts -notcontains $resolvedAccountWithPermission) {
                $results += [PSCustomObject]@{
                    AccountWithPermission = $resolvedAccountWithPermission
                    PermissionType        = $acl.ActiveDirectoryRights
                    ExtendedRight         = $acl.ObjectType # Display the extended right if applicable
                    TargetObject          = $targetObject
                }
            }
        }
    }

    # Display results
    Write-Output "Users or Groups with Specified Permissions and Extended Rights (Excluding Privileged Groups, Accounts, and Objects):"
    $results | Format-Table -AutoSize
}
