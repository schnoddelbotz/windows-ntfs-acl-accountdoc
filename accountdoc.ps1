<#
.SYNOPSIS
    accountdoc - used to doctor and document user accounts and shares.
.DESCRIPTION
    Handling filesystem permissions can be tedious and errorprone.
    The idea behind the script is to not manage permissions by clicking
    around in a GUI but by defining desired state in a file and
    letting some tool (this script) ensure that everything is in place.
    Upon invocation, accountdoc will provide a list of customers to choose
    from. Every customer relates to a customer's .yml, that holds some
    basic customer data like which shares to mange and where desired ACLs
    are defined. By default accountdoc will only report what is wrong.
    At the end of the run, you may select issues to be fixed automatically.
    Things checked / fixed:
     * User existance, AD user object location
     * User (un)desired (mail / security) group memberships
     * Match of .yml configuration vs AD (users, groups)
     * User permissions on folders
	  Requires RSAT from
	  http://www.microsoft.com/en-us/download/details.aspx?displaylang=en&id=7887
    And as YAML simply makes more sense here than .ini or .xml, it also requires
    https://github.com/scottmuc/PowerYaml  and
    https://github.com/aaubry/YamlDotNet  (working version of both included)
.NOTES
    File Name      : accountdoc.ps1
    Author         : ID SDL-MS
    Prerequisite   : PowerShell V2
    Copyright 2013 - Nobody - WTFP License
.LINK
    Script posted over:
    https://svn.id.ethz.ch/trac/sdl-ms/tools/accountdoc
.EXAMPLE
    Wherever you checked out accountdoc, just double click
    rundoc.cmd
#>
# ugh. starting off dfs ... FIXME ... just looks ugly.
cls
# bail out & log if any error occurs; you don't want to run ahead if unsure...
$ErrorActionPreference = "Stop"
# path to self required as first argument, done by rundoc.cmd
$accountdocBasedir = $Args[0]
# to keep record of any issues found (including solutions)
$global:issues = @()

Import-Module ActiveDirectory
Import-Module "$accountdocBasedir\PowerYaml.psm1"

###### Helper functions #######################################################

Function Select-Customer {
  $numCustomers = 0
  $customers = @{}
  Write-Host "`r`n Choose customer:`r`n"
  ls $accountdocBasedir\customers-data.accountdoc\*.yml | % FullName | ForEach-Object {
      $numCustomers++
      $filename = $_ | Split-Path -leaf
      $customers[$numCustomers] = $_
      Write-Host "  $numCustomers. $filename"
  }
  if ($numCustomers -eq 0) {
    Write-Host "  Sorry! No customers-data.accountdoc/*.yml found!"
    Sleep 2
    exit
  }
  $sel = Read-Host "`r`n Select customer by id, x or just ENTER to exit: "
  if (($sel) -eq "x" -or ($sel) -eq "") {
    Write-Host "`r`nOk - see you next time. Bye."
    sleep 2
    exit
  }
  $customers[[int]$sel]
}

Function Push-Issue($errorMsg, $fixCmd) {
  # called to fill up list of errors and how to fix em
  $issue = new-object PSObject
  $issue | add-member -type NoteProperty -Name Description -Value $errorMsg
  $issue | add-member -type NoteProperty -Name FixCommand -Value $fixCmd
  $global:issues += $issue
}

Function Write-FixitBatch($outFile) {
  Write-Debug "Writing Fix-it script to $outFile"
  $theBatch = '';
  $theBatch += "@echo off`r`n"
  $theBatch += "echo Want to run fix-it batch?`r`n";
  $theBatch += "pause`r`n`r`n"
  $global:issues | % {
    $theBatch += "REM " + $_.Description + "`r`n"
    $theBatch += $_.FixCommand + "`r`n`r`n"
  }
  $theBatch += "`r`necho.`r`n"
  $theBatch += "echo JOB COMPLETED. YOU MAY CLOSE THIS WINDOW NOW.`r`n"
  $theBatch += "pause`r`n"
  $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding($False)
  [System.IO.File]::WriteAllLines($outFile, $theBatch, $Utf8NoBomEncoding)
}

Function Parse-PermissionsConfig($cfg,$fullpath,$cfguser) {
  # input: value from permissions: entry
  # output: object: {roles:array, acl:ACL-Object{Owner,Group,Access}}
  # http://blogs.technet.com/b/josebda/archive/2010/11/12/how-to-handle-ntfs-folder-permissions-security-descriptors-and-acls-in-powershell.aspx
  $roles  = @()
  $owner  = ''
  $group  = ''
  $access = ''
  $ACL = New-Object System.Security.AccessControl.DirectorySecurity

  # $retval.roles will be an array of 'affected' roles
  if ($cfg -match "Roles\{([^}]+)\}") {
    $roles = $matches[1].Split(" ")
  }

  # $retval.acl will be a compareable ACL object, fill 'er up
  if ($cfg -match "Owner\{([^}]+)\}") {
    $owner = $matches[1]
    $owner = $owner -replace "<USER>",$cfguser
    $ACL.SetOwner([System.Security.Principal.NTAccount]$owner)
  }
  if ($cfg -match "Group\{([^}]+)\}") {
    $group = $matches[1]
    $ACL.SetGroup([System.Security.Principal.NTAccount]$group)
  }
  if ($cfg -match "Access\{([^}]+)\}") {
    $access = $matches[1]
    $access = $access -replace "<USER>",$cfguser
    $access.Split(";") | % {
      # OF COURSE Import-CSV can only work with files. Crêpe. Back to regexes...
      # "Administrators", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"
      if ($_ -match '^\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*$') {
        $username = $matches[1] #
        $access   = $matches[2] # eg. FullControl
        $inherit  = $matches[3] # eg. ContainerInherit, ObjectInherit
        $foobar   = $matches[4] #
        $grant    = $matches[5] # Allow or Deny
        Write-Debug "    got u $username a $access i $inherit f $foobar g $grant"
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($username, $access, $inherit, $foobar, $grant)
        $ACL.AddAccessRule($rule)
      } else {
        Write-Host "  EXIT: Invalid ACL specification in config file:" -foregroundColor "red"
        Write-Host "  $_"
        exit 1
      }
    }
  }

  $retval = new-object PSObject
  $retval | add-member -type NoteProperty -Name roles -Value $roles
  $retval | add-member -type NoteProperty -Name acl -Value $ACL
  $retval
}

###### Doctor helpers #########################################################

Function Resolve-adgroupMembers($pseudoUserListString) {
  [Array]$members = @()
  Write-Debug "   Fetching Users for $pseudoUserListString"
  $pseudoUserListString.Split(" ") | ForEach {
    $rawMember = $_
    if ($rawMember.StartsWith('%')) {
      $rawMember = $rawMember.replace('%','')
      Write-Debug "     Resolve %'$rawMember'"
      $members += ($cfg.roles.$rawMember).split(" ")
    } elseif ($rawMember.StartsWith('@')) {
      # unsure about this.
      # the tool should be able to distinguish a group from a list of users...
      $rawMember = $rawMember.replace('@','')
      Write-Debug "     Resolve @'$rawMember'"
      $currentMembers = Get-ADGroupMember $rawMember -Recursive
      foreach ($member in $currentMembers) {
        $members += $member.SamAccountName
      }
   } else {
      # just a username, as-is
      $members += $rawMember
   }
  }
  $members
}

###### Doctor checks ##########################################################

Function Verify-AdGroups {
  # http://blogs.technet.com/b/heyscriptingguy/archive/2014/11/25/active-directory-week-explore-group-membership-with-powershell.aspx
  $cfg.adgroups.GetEnumerator() | % {
    $groupName  = $($_.key)
    $rawMembers = $($_.value)
    Write-Host "--- Verifying memberships of group $groupName ($rawMembers)"

    # get desired members from YAML config
    $desiredMembers = Resolve-adgroupMembers($rawMembers)
    # get current members via PS AD module
    $currentMembers = Get-ADGroupMember $groupName -Recursive

    $currentMembersArray = @()
    foreach ($member in $currentMembers) {
      $currentMembersArray += $member.SamAccountName
    }

    # direction one: check that all desired memebers are here
    foreach ($member in $desiredMembers) {
      if ($currentMembersArray -contains $member) {
        Write-Debug "      desired member-1: $member"
      } else {
        Write-Host "    User missing membership: '$member'" -foregroundColor "red"
        # should be dn ... not just username ... FIXME + hashtable
        # $dn = resolve-DN $member ...?
        Push-Issue "Groups: '$member' missing in '$groupName'" "dsmod group $groupName -addmbr `"$member`""
      }
    }

    # direction two: check that no unwanted members are part of the group!
    foreach ($member in $currentMembers) {
      $mname = $member.SamAccountName
      if ($desiredMembers -contains $mname) {
        Write-Debug "      desired member-2: $mname"
      } else {
        Write-Host "    User with undesired membership: '$mname'" -foregroundColor "red"
        Push-Issue "Groups: '$mname' wrongly in '$groupName'" "dsmod group $groupName -rmmbr `"$mname`""
      }
    }
  }
}

Function Verify-RoleAccounts {
  $cfg.roles.GetEnumerator() | % {
    $roleName = $($_.key)
    $roleMembers = $($_.value)
    Write-Host "--- Verifying members of role $roleName ($roleMembers)"
    $roleMembers.Split(" ") | ForEach {
      $tuser = $_
      $ErrorActionPreference = "Continue"
      $adobj = Get-ADUser -Filter {SamAccountName -eq $tuser} -Properties "*"
      $ErrorActionPreference = "Stop"
      if ($adobj) {
        Write-Debug "    check $tuser success, checking desired_ad_attributes"
        $desired = $cfg.desired_ad_attributes.$roleName
        if($desired) {
          $desired.GetEnumerator() | ForEach {
            $d = $_
            # this might look nicer... YAML single item list vs multi... hack.
            if ($d.GetType().Name -eq "Hashtable") {
              # HUH??? this FAILS if $d.value string startsWith '+' sign
              $d.GetEnumerator() | ForEach {
                $x = $_
                $dK = $x.name
                $dV = $x.value
                $dV = $dV -replace "<USER>",$tuser
                $pattern = $adobj.$dK
                if ($pattern -and $pattern -match $dV) {
                  Write-Host "    OK: $tuser $dK  $pattern" -foregroundColor "green"
                } else {
                  Write-Host "    $tuser : undesired $dK " -foregroundColor "red" -NoNewline
                  Write-Host "($pattern)"
                }
              }
            } else {
              $desiredKey  = $d.key
              $desiredName = $d.name
              $desiredVal = $d.value
              $desiredVal = $desiredVal -replace "<USER>",$tuser
              $pattern = $adobj.$desiredKey
              if ($pattern -and $pattern -match $desiredVal) {
                Write-Host "    OK: $tuser $desiredKey  $pattern" -foregroundColor "green"
              } else {
                Write-Host "    $tuser : undesired $desiredKey " -foregroundColor "red"  -NoNewline
                Write-Host "($pattern)"
              }
            }
          }
        }
      } else {
        Write-Host "!!! *** MISSING AD user $tuser" -foregroundColor "red"
      }
    }
  }
}

Function Verify-ShareDfsLinks {
  # Ensure Share is accessible via \\nas\share and \\d\dfs\share
  $cfg.shares.GetEnumerator() | % {
    $shareAlias = $($_.key)
    $shareUncPath = $($_.value)
    $shareDfsPath = $cfg.dfs.$shareAlias
    if (!$shareDfsPath) {
        Write-Host "--- No DFS path defined for share $shareUncPath" -foregroundColor "red"
      } else {
        Write-Host "--- $shareDfsPath => $shareUncPath"
        # mhhh. dfs cmdlets require PS4.0?
    }
  }
  # same for each user...?
}

Function Verify-ShareAccess($path) {
  if (!(Test-Path $path -pathType container)) {
    Write-Host "FATAL ERROR: Cannot access share as $($env:username)" -foregroundColor "red"
    exit 1
  }
  Write-Host "  share access as $($env:username) successful" -foregroundColor "green"
}

Function Verify-UserSharePermissions($shareAlias, $checkUser, $userRole) {
  $cfg.permissions.GetEnumerator() | % {
    $cfgKey   = $($_.key)
    $cfgValue = $($_.value)
    $realPath = $cfg.shares.$shareAlias + ( $cfgKey -replace $shareAlias,"" -replace "<USER>",$checkUser)
    $desiredConfig = Parse-PermissionsConfig $cfgValue $realPath $checkUser
    if (($cfgKey -match "<USER>") -and ($desiredConfig.roles -contains $userRole)) {
      if (!(Test-Path $realPath -pathType container)) {
        Write-Host "    $realPath MISSING" -foregroundColor "red"
        Push-Issue "NAS: Missing userdir for $checkUser : $realPath" "mkdir `"$realPath`""
      } else {
        Verify-SingleACL $realPath $desiredConfig.acl
      }
    } else {
      Write-Debug "    skipping $cfgKey for $checkUser, as not that role"
    }
  }
}

Function Verify-GlobalSharePermissions($shareAlias) {
  Write-Host "  Checking global permissions for $shareAlias ..."
  $cfg.permissions.GetEnumerator() | % {
    $cfgKey   = $($_.key)
    $cfgValue = $($_.value)
    if ($cfgKey -notmatch "<USER>") {
      $realPath = $cfg.shares.$shareAlias + ( $cfgKey -replace $shareAlias,"")
      if (!(Test-Path $realPath -pathType container)) {
        Write-Host "    Directory non-existant: $realPath" -foregroundColor "red"
        Push-Issue "NAS: Missing share directory: $realPath" "mkdir `"$realPath`""
      } else {
        $desiredConfig = Parse-PermissionsConfig $cfgValue $realPath "no-username-to-replace"
        Verify-SingleACL $realPath $desiredConfig.acl
      }
    }
  }
}

Function Verify-SingleACL($path, $desiredACL) {
  $ErrorActionPreference = "SilentlyContinue"
  $currentACL = Get-ACL $path
  $ErrorActionPreference = "Stop"
  # now diff ... using Compare-Object as proposed in
  # http://blogs.technet.com/b/heyscriptingguy/archive/2013/06/30/weekend-scripter-find-errant-acls-inside-a-folder-with-powershell.aspx
  if ($currentACL) {
    $diff = Compare-Object -ReferenceObject $desiredACL -DifferenceObject $currentACL -Property access
    if ($diff) {
      Write-Host "    $path" -foregroundColor "red"
      # TBD FIXME .... to be continued. Differences detected, re-apply ...
      # Push-Issue "Bad ACLs on $path" "icacls ? power-shell Set-ACL $desiredACL ? how-post?"
      # $diff | Format-List
      # should be two-way check as with group members:
      # - ensure all desired are present
      # - ensure that no user/group is in current that is not in desiredACL
    } else {
      Write-Host "    $path" -foregroundColor "green"
    }

  } else {
    Write-Host "    Unable to read ACLs of $path" -foregroundColor "red"
  }
}

Function UNUSED-VerifySingleFolder($dir,$perms,$owner) {
  ## legacy stuff that could be partially recycled ...
  $rw = [System.Security.AccessControl.FileSystemRights]"Read, Write"
  $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
  $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
  $objType =[System.Security.AccessControl.AccessControlType]::Allow
  $path = "$($shareUnc)\$($dir)"
  Write-Host "`n Folder: $($path)"

  # check whether path exists or user wants to create it. return otherwise.
  if (!(Test-Path $path)) {
    if ($dmode -Match "verify") {
      Write-Host "   missing $($dir); use -fixit to create it" -foregroundColor "green"
      return
    }
    if (!(CreateDirectoryInteractive $path)) {
      Write-Host "   Failed to create directory, skipping ACL setup." -foregroundColor "red"
      return
    }
  }

  $acls = Get-ACL $path
  Write-Host " Owner: $($acls.Owner) - Group: $($acls.Group)"
  foreach ($e in $acls.Access) {
    Write-Host "  $($e.IdentityReference) has $($e.AccessControlType) $($e.FileSystemRights)"
    # | Format-List
    #Write-Host "$($e) has value $($e.Access.Keys)"
  }
}

###### Doctor run #############################################################

Function Run-DoctorChecks {
  # runs any checks to find mis-configurations. won't trigger modifications!
  $customerName = $cfg.customer.name
  $customerSla = $cfg.customer.sla

  Write-Host "`r`n*** Running doctor for customer: $customerName (SLA $customerSla)" -foregroundColor "yellow"

  Write-Host "`r`n*** Phase I  : Verifying AD entries " -foregroundColor "yellow"
  # Ensure accounts do exist and have desired_ad_attributes
  Verify-RoleAccounts
  # Ensure accounts have desired group memberships
  Verify-AdGroups

  Write-Host "`r`n*** Phase II : Verifying NAS DFS Links" -foregroundColor "yellow"
  # Ensure any share has a DFS link as desired
  Verify-ShareDfsLinks
  # Ensure correct DFS links for user accounts
  #Verify-UserDfsLinks

  Write-Host "`r`n*** Phase III: Verifying NAS Permissions" -foregroundColor "yellow"
  $cfg.shares.GetEnumerator() | % {
    $shareAlias = $($_.key)
    $shareUncPath = $($_.value)
    $shareDfsPath = $cfg.dfs.$shareAlias
    Write-Host "--- Processing share aliased '$shareAlias' ..."
    Write-Host "  NAS UNC: $shareUncPath"
    Write-Host "  NAS DFS: $shareDfsPath"

    # Test share overall accessability, will error out on failure
    Verify-ShareAccess $shareUncPath

    # Check permissions on any non-<USER>-shares/directories
    Verify-GlobalSharePermissions $shareAlias

    # Check permissions on <USER> shares for each role/users
    $cfg.roles.GetEnumerator() | % {
      $roleName = $($_.key)
      $roleMembers = $($_.value)
      Write-Host "  Verifying permissions for members of role $roleName"
      $roleMembers.Split(" ") | ForEach {
        Verify-UserSharePermissions $shareAlias $_ $roleName
      }
    }
  }

  # TBD: Find former users & unknown SIDs on ACLs - ask to remove
  # TBD: Find orphan directories in any <USER> dirs
  # TBD: For each user, report further groupmemberships (non-'desired')
  Write-Host "`r`n*** Doctor completed checks.`r`n" -foregroundColor "yellow"
}

###### MAIN ###################################################################

Function Main {
  # enlarge terminal window. de-uglify...?
  # TBD: add mode to provide storage usage per user / xls
  $pshost = get-host
  $pswindow = $pshost.ui.rawui
  $pswindow.windowtitle = "AccountDoc - Choose customer"
  $newsize = $pswindow.windowsize
  $newsize.height = 60
  $pswindow.windowsize = $newsize
  cls

  # Let user choose customer's config file
  # tbd: support $0.ps1 -customerYMLfile <path_to_file> (non-interactive use)
  $customerYMLfile = Select-Customer

  # Try to parse customer's config file
  $cfg = Get-Yaml -FromFile $customerYMLfile
  $pswindow.windowtitle = "AccountDoc - " + $cfg.customer.name
  # Test-cfg -- ensure sanity !! FIXME; e.g. no user twice...

  # Find issues for selected customer
  Run-DoctorChecks

  # Write issues / fixes to "FixIt" Batch file
  $outputFileName = $accountdocBasedir + "fixit.cmd" # fixme dyn/date filename
  Write-Host "Wrote FixIt-Batch to:"
  Write-Host "  $outputFileName" -foregroundColor "yellow"
  Write-FixitBatch $outputFileName
  # TBD: let user decide on how to react on each issue.
  # $selectedIssues = checkbox gui ...?
  # http://stackoverflow.com/questions/14527832/powershell-how-to-invoke-a-checkbox-windows-with-multiple-choice
  # http://sysadminemporium.wordpress.com/2012/12/07/powershell-gui-for-your-scripts-episode-3/
  # ... could also be a single 'do it' button for each fix?
}

Main
