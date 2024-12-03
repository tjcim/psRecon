function Expand-EnvironmentVariables {
  [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
        )

# Define the regex pattern to capture the environment variable and the remainder of the path
      $Pattern = "^%([^%]+)%\\?(.*)$"

# Match the input string against the pattern
      if ($Path -match $Pattern) {
        $CapturedString = $Matches[1]
          $Remainder = $Matches[2]
          $EnvValue = [Environment]::GetEnvironmentVariable($CapturedString)

          if ($EnvValue) {
            if ($Remainder) {
              return Join-Path -Path $EnvValue -ChildPath $Remainder
            } else {
              return $EnvValue
            }
          } else {
            return "Invalid environment variable: %$CapturedString%"
          }
      } else {
        return "No match found in the input string: $Path"
      }
}

function Check-Permissions {
  param (
      [Parameter(Mandatory = $true)]
      [string]$Path
      )

  Write-Output "Checking $Path for weak permissions."
    Get-ChildItem $Path -Directory -Recurse -Depth 1 -ErrorAction SilentlyContinue | Where-Object {
      $_.FullName -notlike "*\WinSxS*"
    } | ForEach-Object {
      $dir = $_.FullName
        $icaclsOutput = icacls $dir 2>&1
        if ($icaclsOutput) {
          $hasDesiredPermissions = $false
            $matchedIdentity = ""
            $matchedRights = ""
            $icaclsOutput | ForEach-Object {
              $line = [string]$_ -replace '^\s+|\s+$', '' # Cast to string and trim spaces
                if ($line -match '^(?:.+? )?(?<Identity>.+?)\s*:\s*\((?<Rights>.+)\)$') {
                  $identity = $matches['Identity'] -replace '^\s+|\s+$', '' # Trim spaces from Identity
                    $rights = $matches['Rights']
                    $normalizedRights = ($rights -replace '[\(\)]', '' -split '[, ]' | Where-Object { $_ -ne '' })
                    if (($identity -match 'NT AUTHORITY\\Authenticated Users|BUILTIN\\Users') -and
                        (($normalizedRights -contains 'WD' -and $normalizedRights -contains 'X') -or
                         ($normalizedRights -contains 'W' -and $normalizedRights -contains 'X') -or
                         ($normalizedRights -contains 'WD' -and $normalizedRights -contains 'RX') -or
                         ($normalizedRights -contains 'W' -and $normalizedRights -contains 'RX'))) {
                      $hasDesiredPermissions = $true
                        $matchedIdentity = $identity
                        $matchedRights = $normalizedRights -join ', '
                    }
                }
            }
          if ($hasDesiredPermissions) {
# Convert normalized rights into friendly descriptions
            $friendlyRights = $matchedRights -replace 'RX', 'ReadAndExecute' `
              -replace 'X', 'ExecuteFile' `
              -replace 'WD', 'CreateFiles' `
              -replace 'W', 'Write' `
              -replace 'AD', 'AppendData' `
              -replace 'S', 'Synchronize' `
              -replace 'R', 'Read'
              Write-Output "${dir}: ${matchedIdentity} (${friendlyRights})"
          }
        }
    }
}

function Invoke-ApplockerRecon {
  $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $BuiltIn = @(
        "NT AUTHORITY\SYSTEM",
        "NT AUTHORITY\LOCAL SERVICE",
        "NT AUTHORITY\NETWORK SERVICE",
        "IIS APPPOOL\DefaultAppPool"
        )

    if ($CurrentUser -in $BuiltIn) {
      Write-Output "Applocker policies do not apply to $CurrentUser"
        return
    }

  $Rules = Get-ChildItem -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
    if (-not $Rules) {
      Write-Output "No rules found in the specified registry path."
        return
    }

  foreach ($ID in $Rules) {
    $RuleName = $($ID.PSChildName)
      $Enforcement = switch ($(Get-ItemProperty -Path "$($ID.PSPath)" -Name "EnforcementMode" -ErrorAction SilentlyContinue).EnforcementMode) {
        1 { 'Enforced' }
        0 { 'Not Enforced' }
        $Null { 'Not Configured' }
      }

    $Actions = Get-ChildItem -Path "$($ID.PSPath)" -ErrorAction SilentlyContinue

      foreach ($Action in $Actions) {
        $XML = Get-ItemProperty -Path "$($Action.PSPath)" -Name "Value" -ErrorAction SilentlyContinue

          if ($XML.Value) {
            $XmlDocument = [xml]$XML.Value
              $Id = $XmlDocument.DocumentElement.Id
              $Name = $XmlDocument.DocumentElement.Name
              $Description = $XmlDocument.DocumentElement.Description
              $Conditions = $XmlDocument | Select-Xml -XPath "//Conditions/*"
              $UserOrGroupSid = $XmlDocument.DocumentElement.UserOrGroupSid

              $UserName = if ($UserOrGroupSid) {
                try {
                  (New-Object System.Security.Principal.SecurityIdentifier($UserOrGroupSid)).Translate([System.Security.Principal.NTAccount]).Value
                } catch {
                  "Unknown ($UserOrGroupSid)"
                }
              } else {
                "N/A"
              }

# Write rule information
            Write-Output "Rule        : $RuleName"
              Write-Output "Enforcement : $Enforcement"
              Write-Output "ID          : $Id"
              Write-Output "Name        : $Name"
              Write-Output "Description : $Description"
              Write-Output "UserOrGroup : $UserName"
              Write-Output "Action      : $($XmlDocument.DocumentElement.Action)"
              Write-Output "Conditions  : $($Conditions | ForEach-Object { $_.Node.OuterXml })"
              Write-Output ""

              foreach ($Condition in $Conditions) {
                if ($Condition.Node.LocalName -ne "FilePublisherCondition") {
                  $PathCondition = if ($Condition.Node.Attributes["Path"]) {
                    $Condition.Node.Attributes["Path"].Value
                  } else {
                    $null
                  }

                  $ExpandedPath = if ($PathCondition) {
                    Expand-EnvironmentVariables -Path $PathCondition
                  } else {
                    $null
                  }

                  $ExpandedPath = $ExpandedPath.TrimEnd('*')

                    if ($ExpandedPath -and $UserName -ne "BUILTIN\Administrators") {
                      if (Test-Path -Path $ExpandedPath -PathType Container) {
                        Check-Permissions -Path $ExpandedPath
                          Write-Output ""
                          Write-Output ""
                      }
                    }
                }
              }
          }
      }
  }
}