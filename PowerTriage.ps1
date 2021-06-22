<#
.SYNOPSIS
    Backups lots of forensically relevant data from a computer and presents saved data to an analyst in form of gridviews
.DESCRIPTION
    Logon on the remote computer is realised via LAPS (or if not available via entered credentials as a fallback)
    There is a wide range of options of data sources to capture available. Choose them with the -Options parameter
    Capturing of all data (especially RAMDump and EventLogReports) will take quite some time depending on disk I/O and network speed.
.EXAMPLE
    PS> .\PowerTriage.ps1 -ComputerName "RemoteComputer" -LAPSUserName "Administrator" -Resultsfolder "C:\Temp\Capture\"

    Runs all available capture options against the computer "RemoteComputer" and displays the results.
    The password for the LAPS user will automatically tried to retrieve from the AD
.EXAMPLE
    PS> .\PowerTriage.ps1 -ComputerName "RemoteComputer" -Resultsfolder "C:\Temp\Capture\" -Options "TimeDriftCheck", "Autostarts", "Processes"

    Only captures and displays autostart and process information on "RemoteComputer".
    Also tests for major time drift >250ms between source and target system.
#>

[CmdletBinding()]

Param (
    # The Computer to target
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias("Computer")]
    [string] $ComputerName,

    # The name of the local / LAPS account
    # If not set remote authentication will be attempted with the
    # current user credentials. Since that is not a local account
    # and password hashes will be transmitted to the destination
    # computer it's less safe than using a local / LAPS account though
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [string] $LAPSUserName,

    # The password for the local / LAPS account
    # If a LAPSUserName is set but password is not the script
    # will automatically try to query the pw from ad instead
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [SecureString] $LAPSPassword,

    # Define the algorithms that the script should run against the target machine to save and capture
    # Autostarts: Captures all autostarts using autorunsc.exe
    # Networking: Captures active TCP connections, UDP data, routing information and ARP cache
    # FileHandles: Captures all open file handles using Sysinternals handle.exe
    # RamDump: Creates a memory image using Belkasoft RAM Capturer
    # ComputerInfo: Captures general system information, like computer name, windows edition, ...
    # Processes: Captures all active processes
    # Bitlocker: Captures bitlocker keys for all active volumes. (will not get displayed, just backed up)
    # TimeDriftCheck: Checks the time difference between source and target system and alerts if the difference is >250ms
    # LocalUsers: Captures all local users
    # EnvironmentalVariables: Calputes environmental variables of the system and all active users
    # EventLogs: Creates backups of all event log files
    # EventLogReports: Uses backed up event log files to generate a list of reports (User logons, ran PowerShell scripts)
    # HashAndCompress: Calculates hashes for all captured files and stores them as a zip file
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("Autostarts","Networking","FileHandles","RamDump", "ComputerInfo", "Processes", "Bitlocker", "TimeDriftCheck", "LocalUsers", "EnvironmentalVariables", "Eventlogs", "EventlogReports", "HashAndCompress")]
    [string[]] $Options = @("Autostarts","Networking","FileHandles","RamDump", "ComputerInfo", "Processes", "Bitlocker", "TimeDriftCheck", "LocalUsers", "EnvironmentalVariables", "Eventlogs", "EventlogReports", "HashAndCompress"),

    # The folder where all capture output should be saved to
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [string] $ResultsFolder
)

Begin {

    ####################################
    #region    FUNCTIONS               #
    ####################################


    ####################################
    #region    LOGGING                 #
    ####################################
    
    <#
    .SYNOPSIS
        Writes the given message to the Information stream, with timestamp.
        That way it can easily be logged by tools or commands like Start-Transcript
    #>
    Function Log-Information {

        [cmdletbinding()]

        Param (
            # The message to output with timestamp
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string] $Message
        )

        $formattedDate = Get-Date -Format "yyyy-MM-dd_HH:mm:ss.fff"
        Write-Information "$formattedDate $Message"
    }

    <#
    .SYNOPSIS
        Displays the message in a progress bar and
        writes the given message to the Information stream, with timestamp.
        That way it can easily be logged by tools or commands like Start-Transcript
    #>
    Function Log-Progress {

        [cmdletbinding()]

        Param (
            # The message to output with timestamp
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string] $Message,

            # The message to output with timestamp
            [Parameter(Mandatory=$true)]
            [ValidateRange(0,100)]
            [int] $PercentComplete
        )

        if($Percentage -eq 100) {
            Write-Progress -Id 0 -Completed
        } else {
            Write-Progress -Id 0 -Activity "Running PowerTriage" -PercentComplete $PercentComplete -CurrentOperation $Message
        }

        Log-Information -Message $Message
    }
    
    <#
    .SYNOPSIS
        Writes the given message to the Information stream, with timestamp.
        That way it can easily be logged by tools or commands like Start-Transcript
    #>
    Function Log-Warning {

        [cmdletbinding()]

        Param (
            # The message to output with timestamp
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string] $Message
        )

        $formattedDate = Get-Date -Format "yyyy-MM-dd_HH:mm:ss.fff"
        Write-Warning "$formattedDate $Message"
    }  
    
    <#
    .SYNOPSIS
        Writes the given message to the Information stream, with timestamp.
        That way it can easily be logged by tools or commands like Start-Transcript
    #>
    Function Log-Error {

        [cmdletbinding()]

        Param (
            # The message to output with timestamp
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string] $Message
        )

        $formattedDate = Get-Date -Format "yyyy-MM-dd_HH:mm:ss.fff"
        Write-Error "$formattedDate $Message"
    }    
    
    ####################################
    #endregion LOGGING                 #
    ####################################


    ####################################
    #region    LAPS                    #
    ####################################
    
    <#
    .SYNOPSIS
        Connects to the local AD and retrieves the LAPS password from a computer
    #>
    Function Get-LAPSPasswordFromAD {

        [cmdletbinding()]

        Param (
            # The Computer to query the LAPS password from
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string] $ComputerName
        )

        Get-ADComputer $ComputerName -Properties "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime" | 
        Select-Object -Property DNSHostName, "ms-Mcs-AdmPwd", @{ Label = "ExpirationTime"; Expression={(Get-Date 1/1/1601).AddDays($_."ms-Mcs-AdmPwdExpirationTime"/864000000000)}}
    }    
    
    ####################################
    #endregion LAPS                    #
    ####################################

    
    ####################################
    #region    WSMan Configuration     #
    ####################################

    <#
    .SYNOPSIS
        Query WSMan encryption configuration status as a server or client
    #>
    Function Test-WSManEncryptionEnabled {
    
        Param (
            # If client or server side configuration should be tested
            [Parameter(Mandatory=$true)]
            [ValidateSet("Client", "Server")]
            [string] $Side
        )    
    
        try {
            if($Side -eq "Client") {
                $value = (Get-Childitem WSMan:\localhost\Client -ErrorAction Stop | Where-Object Name -EQ AllowUnencrypted).Value
            } else {
                $value = (Get-Childitem WSMan:\localhost\Service -ErrorAction Stop | Where-Object Name -EQ AllowUnencrypted).Value
            }

            if($value -eq "false") {
                Write-Output $true
            } else {
                Write-Output $false
            }
        } catch {
            Write-Output "No permission to query local WSMan configuration. Is the script running as admin?"
        }
    }

    ####################################
    #endregion WSMan Configuration     #
    ####################################


    ####################################
    #region    NETWORK                 #
    ####################################

    <#
    .SYNOPSIS
        Query actice TCP connections
    #>
    Function Get-TCPInformation {
        Get-NetTCPConnection | Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, CreationTime, State
    }

    <#
    .SYNOPSIS
        Querycurrent UDP endpoint statistics
    #>
    Function Get-UDPInformation {
        Get-NetUDPEndpoint | Select-Object -Property LocalAddress, LocalPort, OwningProcess, CreationTime
    }

    <#
    .SYNOPSIS
        Query IP routing information
    #>
    Function Get-RoutingInformation {
        Get-NetRoute | Select-Object -Property DestinationPrefix, NextHop, RouteMetric, ifIndex, Store, State, Protocol, InterfaceAlias
    }

    <#
    .SYNOPSIS
        Query ARP cache entries (IP->MAC)
    #>
    Function Get-ARPCacheInformation { 
        Get-NetNeighbor | Select-Object -Property InterfaceAlias, IpAddress, AddressFamily, LinkLayerAddress, State, Store
    }

    ####################################
    #endregion NETWORK                 #
    ####################################


    ####################################
    #region    FILE HANDLES            #
    ####################################

    <#
    .SYNOPSIS
        Lists all open handles
    .DESCRIPTION
        Utilizes handle64.exe (because of lack of a proper cmdlet) 
        for capturing all current handles on the system and converts them 
        to well-formed PS objects
    .EXAMPLE
        PS> Get-FileHandles

        Lists all handles while searching for the handle64.exe 
        in the same path as the script
    .EXAMPLE
        PS> Get-FileHandles -Handle64ExePath "C:\Temp\handle64.exe"

        Lists all handles while searching for the handle64.exe 
        in the given path
    #>
    Function Get-FileHandles {

        [cmdletbinding()]

        Param (
            # Path to the handle64.exe. If not set will be searched in ScriptRoot
            [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string] $Handle64ExePath
        )

        # Dynamic Path to handle64.exe based on if the param is set or not
        if (-not $Handle64ExePath) {
            $Handle64ExePath = "$PSScriptRoot\handle64.exe"
        }

        # Test for the existence of the handle64.exe
        # Abort if it does not exist
        if(-not (Test-Path -Path $Handle64ExePath -PathType Leaf)) {
            Write-Error "Path to handle64.exe is not valid."
            return
        }

        # Regex patterns for parsing output of the handle64.exe
        # Pattern representing a process entry
        # Example: "svchost.exe pid: 16968 DST\UserName"
        [regex] $ProcessPattern = "(?<Name>\w+[.\w]+?)\s+pid:\s+(?<PID>\d+)\s+(?<User>[\\\w\s<>]+)$"
        # Pattern representing a handle entry
        # belonging to the last parsed process entry
        # Example1: "  134: File          C:\Windows\System32\Conhost.exe.mui"
        # Example2: "  1E4: Section       \Sessions\2\windows_shell_counters"
        [regex] $EntryPattern = "(?<Handle>[0-9A-F]{4})\:\s(?<Type>[\s\w.]+)\s+(?<Info>[\w\-()]+)?\s+(?<Path>[\.\w\d:\\\s().-]+)$"

        Write-Verbose "Executing handle64.exe at path `"$Handle64ExePath`""
        $data = &$Handle64ExePath -accepteula -nobanner -u
        Write-Verbose "Got $($data.count) lines of results."

        Write-Verbose "Building native powershell objects..."
        foreach ($entry in $data) {
            if($entry -match $ProcessPattern) {
               $currName = $Matches.Name
               $currPID = $Matches.PID
               $currUser = $Matches.User
            } elseif($Entry -match $EntryPattern) {
                [pscustomobject] @{
                    Name = $currName
                    PID = $currPID
                    User = $currUser
                    HandleID = $Matches.Handle
                    Type = $Matches.Type
                    Info = $Matches.Info
                    Path = $Matches.Path
                }
            }
        }
        Write-Verbose "Finished!"
    }

    ####################################
    #endregion FILE HANDLES            #
    ####################################


    ####################################
    #region    RAM DUMP                #
    ####################################

    <#
    .SYNOPSIS
        Capture RAM images of (remote) computers
    .DESCRIPTION
        The RAM capturer executable and all it’s dependencies have to reside in the
        folder "RamCapturer" in the same directory of this script or specified via
        the parameter -RamCapturerDirectory 

        The RAMCapturer executable resides on the destination system to 
        not to impact the drive even further
    .EXAMPLE
        PS> Get-MemoryImage -PSSession MyRemoteSession -DestinationFolder "C:\Triage\"

        Starts a ram capture process in MyRemoteSession and copies the resulting dump 
        to the local C:\Triage folder
    #>
    Function Invoke-MemoryImageJob {

	    [CmdletBinding()]

	    Param (
		    # Computer to capture RAM image from
		    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [ValidateScript({$_.State -eq [System.Management.Automation.Runspaces.RunspaceState]::Opened })]
		    [System.Management.Automation.Runspaces.PSSession] $PSSession,

		    # Path where to store the finished RAM image
		    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
		    [string] $DestinationFolder = "C:\",

		    # Path of the RAM Capturer executable files with it's dependencies
		    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
		    [string] $RamCapturerDirectory = "$PSScriptRoot\RamCapturer",

		    # Where to copy the executable folder to on the remote machine
		    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
		    [string] $RemoteDirectory = "C:\Temp\HelpFiles\"
	    )

        # File paths of exe and dump
        $RemoteRamCapturerDirectory = Join-Path -Path $RemoteDirectory -ChildPath (Split-Path -Path $RamCapturerDirectory -Leaf)
        $RemoteRamCapturerExePath = Join-Path -Path $RemoteRamCapturerDirectory -ChildPath "RamCapture64.exe"
        $RemoteMemDumpPath = Join-Path -Path $RemoteRamCapturerDirectory -ChildPath "dump.memdump"


	    # Copy ram capturer from the local computer to 
 	    # destination system using the C$ share
	    Write-Verbose "Copying RAM capturer executive files to remote system"
	    Copy-Item -Path $RamCapturerDirectory -Destination $RemoteDirectory -ToSession $PSSession -Force -Recurse

	    # Run capture via RamCapturer64.exe and wait until it is finished
	    Write-Verbose "Starting capturing process in background..."
	    Invoke-Command -Session $PSSession -ScriptBlock {
            Start-Process -FilePath $using:RemoteRamCapturerExePath -ArgumentList $using:RemoteMemDumpPath -Wait

            # Output the location of the memory dump for copying later
            Write-Output $using:RemoteMemDumpPath
        } -AsJob -JobName "RAMDumpCreationJob"

    }

    ####################################
    #endregion RAM DUMP                #
    ####################################


    ####################################
    #region    COMPRESS AND HASH       #
    ####################################

    <#
    .SYNOPSIS
        Calculates hashes for all files in a path and saves everything as a zip
    .DESCRIPTION
        The resulting zip file will reside in the same folder the original
        folder was and will have the same name

        If you want to delete the original files after hashing and zipping you
        can use the RemoveOriginal switch
    .EXAMPLE
        PS> Compress-DirectoryWithHashes -Path C:\Temp\data -OutputFilePath C:\Temp\data.zip

        Calculates hashes for all files in the directory Path
        a zip with all data including the hashes in the OutputPath
    #>
    Function Compress-DirectoryWithHashes {

        [CmdletBinding()]

        Param (
            # Folder to calculate hashes from and to zip
            [Parameter(Mandatory=$true)]
            [string] $Path,

            # Path where the resulting zip should be saved to
            [Parameter(Mandatory=$true)]
            [string] $OutputFilePath,

            # When set the original files will be deleted
            # Only the zip will be kept
            [Parameter(Mandatory=$false)]
            [boolean] $RemoveOriginal =$false
        )

        $DirectoryPath = Split-Path -Path $Path -Parent
        $FolderName = Split-Path -Path $Path -Leaf
        $HashFilePath = Join-Path -Path $OutputFilePath -ChildPath "hashes.csv"
        $ArchiveFilePath = Join-Path -Path $DirectoryPath -ChildPath "$FolderName.zip"

        # Calculate SHA-1 hashes for all items in the directory
        # and save the result in a csv file
        # Because Excel uses the Semicolon as default delimiter in german
        # language we use the Semicolon also so no manual splits are 
        # necessary when viewing the csv later
        $hashes = Get-ChildItem -Path $Path -Recurse | Get-FileHash -Algorithm SHA1
        $hashes | Export-Csv -Path $HashFilePath -NoTypeInformation -Delimiter ";"

        Compress-Archive -Path $Path -CompressionLevel Optimal -DestinationPath $ArchiveFilePath

        # If the switch is set remove the original folder
        if($RemoveOriginal) {
            Remove-Item -Path $Path -Force -Recurse
        }
    }

    ####################################
    #endregion COMPRESS AND HASH       #
    ####################################


    ####################################
    #region    PROCESSES               #
    ####################################

    <#
    .SYNOPSIS
        Query running process information
    #>
    Function Get-ProcessInformation {
        Get-Process -IncludeUserName | 
            Select-Object -Property ID, Name, Path,
                                    UserName, SessionId,
                                    Company, Description,
                                    StartTime,
                                    @{Name="RAM_MB"; Expression={
                                       [Math]::Round($_.WorkingSet_MB / 1MB)
                                    }},
                                    @{Name="EnvironmentalVariables"; Expression={
                                       ($_.StartInfo.EnvironmentVariables.GetEnumerator() | ForEach-Object { "$($_.Name): $($_.Value)" }) -join "; "
                                    }},
                                    @{Name="LoadedModules"; Expression={
                                       $_.Modules.FileName -join "; "
                                    }}
    }

    ####################################
    #endregion PROCESSES               #
    ####################################


    ####################################
    #region    BITLOCKER               #
    ####################################

    <#
    .SYNOPSIS
        Output bitlocker information for all mapped drives
    #>
    Function Get-BitlockerKeys {
        Get-BitLockerVolume | 
            Where-Object {$_.KeyProtector.KeyProtectorType -eq "RecoveryPassword"} | 
            Select-Object –Property MountPoint, VolumeType, VolumeStatus, CapacityGB, ProtectionStatus, @{Label=’RecoveryPassword’; Expression={$_.KeyProtector.RecoveryPassword[0] }}
    }

    ####################################
    #endregion BITLOCKER               #
    ####################################


    ####################################
    #region    TIME SYNC CHECK         #
    ####################################

    <#
    .SYNOPSIS
        Output bitlocker information for all mapped drives 
    #>
    Function Test-TimeDrift {

        Param(
            # An open PSSession on the machine to compare time information of
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [ValidateScript({$_.State -eq [System.Management.Automation.Runspaces.RunspaceState]::Opened })]
            [System.Management.Automation.Runspaces.PSSession] $RemoteSession,

            # Forces the sync of the local time via NTP before comparing
            [Parameter(Mandatory=$false)]
            [switch] $DoNTPSync
        )

        if($DoNTPSync) {
            # Sync local time via NTP to assure the local computer time 
            # does not drift. This requires local admin privileges
            w32tm /resync /force | Out-Null
            if(($result -match "denied").Count -gt 0) {
                Write-Warning "Local time could not be synced."
            }
        }

        # Query time on remote and local computers
        $remoteDateTime = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-Date }
        $localDateTime = Get-Date
        $timeDiffInMS = ($localDateTime.Ticks - $remoteDateTime.Ticks) / 10000

        # Warn when finding significant time drift between systems
        if($timeDiffInMS -gt 250 -or $timeDiffInMS -lt -250) {
            Write-Warning "Remote computer has a time difference of $timeDiffInMS. Differences over 250ms are considered significant. Other possible reason: Does the network have very high latency?"
        }

        # Output results as object
        [PSCustomObject] @{
        	LocalTime = $localDateTime
        	RemoteTime = $remoteDateTime
            TimeDiffMS = $timeDiffInMS
        }
    }

    ####################################
    #endregion TIME SYNC CHECK         #
    ####################################

    
    ####################################
    #region    USER ACCOUNTS           #
    ####################################

    <#
    .SYNOPSIS
        Output basic information about all existing local users
    #>
    Function Get-LocalUserInfo {
        Get-LocalUser | Select-Object -Property SID, Name, Enabled, Description, LastLogon, PasswordRequired, UserMayChangePassword 
    }

    ####################################
    #endregion USER ACCOUNTS           #
    ####################################


    ####################################
    #region    ENVIRONMENTAL VARIABLES #
    ####################################

    <#
    .SYNOPSIS
        Lists all environmental variables
        Includes all logged on users
        <SYSTEM> is listed as user name for global variables
    #>
    Function Get-EnvironmentalVariableInfo {
        Get-CimInstance -ClassName Win32_Environment | 
            Select-Object -Property UserName, Name, VariableValue, SystemVariable, Status | 
            Sort-Object -Property UserName, Name
    }

    ####################################
    #endregion ENVIRONMENTAL VARIABLES #
    ####################################


    ####################################
    #region    AUTOSTARTS              #
    ####################################
   
    <#
    .SYNOPSIS
        Ouputs autostart objects of a remote system using sysinternals autorunsc64.exe
    .DESCRIPTION
        Autostarts include boot execute entries, appinit DLLs, explorer addons,
        sidebar gadgets, image hijacks, ie addons, known dlls, logon startups,
        wmi entries, winsock protocol and network providers, codecs, printer monitors,
        LSA security providers, services, drivers, scheduled tasks and winlogon entries

        You can either specify an autorunsc.exe to copy to the target system
        or supply a path on the target, if the file already exists there
    .EXAMPLE
        PS> Get-AutorunsRemote -ComputerName MyComputer -Autorunsc64ExePath "C:\Sysinternals\autorunsc64.exe"

        Executes the autorunsc64.exe and parses it's output as PowerShell native objects
    #>
    Function Get-Autoruns {

        [CmdletBinding()]

        Param (
            # The path to a autorunsc64.exe
            [Parameter(Mandatory=$true)]
            [string] $Autorunsc64ExePath
        )

        # Dynamic Path to autorunsc64.exe based on if the param is set or not
        if (-not $Autorunsc64ExePath) {
            $Autorunsc64ExePath = "$PSScriptRoot\autorunsc64.exe"
        }

        # Test for the existence of the autorunsc64.exe
        # Abort if it does not exist
        if(-not (Test-Path -Path $Autorunsc64ExePath -PathType Leaf)) {
            Write-Error "Path to autorunsc64.exe is not valid."
            return
        }

        # Execute the tool with the parameters for analysing all types of
        # autostart types (-a *) and output the resulting data in csv format (-c)
        # depending if the autostart stems from a file the files hash will be 
        # calculated, too (-h)
        Write-Verbose "Querying autostarts..."
        $autostartsraw = &$Autorunsc64ExePath -a * -c -h -accepteula

        # Cut autostarts tool header and create native
        # PowerShell objects from the returned string
        $autostarts = $autostartsRaw[5..$autostartsRaw.Count] | 
            ConvertFrom-Csv -Delimiter "," | 
            Where-Object -Property Entry -NE -Value ""
        Write-Verbose "Got $($autostarts.Count) autostart entries."

        Write-Output $autostarts
    }
   
    ####################################
    #endregion AUTOSTARTS              #
    #################################### 


    ####################################
    #region    EVENT LOGS              #
    ####################################

    <#
    .SYNOPSIS
        Copies all event logs from a computer to the target destination
    #>
    Function Get-EventLogBackup {
    
        Param(
            # The computer to pull all event log files from
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string] $ComputerName,

            # The folder to copy all event logs to
            [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string] $Destination
        )

        # This whole script block runs directly on the source machine and makes
        # use of the administrative C$ share to backup the raw event log files 
        Write-Verbose "Start capturing Eventlogs..."

        # All eventlog files (.evtx) are stored in system32\winevt\logs
        # There are also a few channels stored in this folder, though they are irrelevant for us
        # -Force Creates the folder if it does not exist yet, -PassThru outputs the copied files as objects
        Write-Verbose "Copying all Files that match `"\\$ComputerName\c$\Windows\System32\winevt\Logs\*.evtx`""

        # Use Join path to explicitly request a directory path
        # In case a folder path is submitted, but it does not end in "\"
        $DestinationPath = Join-Path -Path "$Destination\" -ChildPath "\"
        
        # If the folder does not yet exist create it
        if(-not (Test-Path -Path $DestinationPath -PathType Container)) {
            New-Item -Path $DestinationPath -ItemType Directory
        }

        # Copy all files and output the destination ones into the pipeline
        Copy-Item -Path "\\$ComputerName\c$\Windows\System32\winevt\Logs\*.evtx" -Destination $DestinationPath -Force -PassThru

        Write-Verbose "Finished capturing Eventlogs."
    }

    ####################################
    #endregion EVENT LOGS              #
    ####################################

    
    ####################################
    #region    EVENT LOG REPORTS       #
    ####################################

    <#
    .SYNOPSIS  
        Function to resolve a sid based on a hashtable mapping
    .DESCRIPTION
        Can process one or a list of previously backed up logs or run against live logs
    #>
    Function Get-AccountNameOfSID {

            Param (
            # The SID to be resolved
            [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
            [string] $SID,

            # A hashtable consisting of keys of SIDs and account names as values
            [Parameter(Mandatory=$false)]
            [Hashtable] $Mapping = $script:SidToUserNameMapping
        )

        # if it's a remote system that is getting queried
        # try to resolve accounts via their remote sid mapping first
        if($Mapping) {
            if($Mapping.ContainsKey($SID)) {
                return $Mapping[$SID]
            } else {
                # most likely a domain / system account
                # => resolve via local query
            }
        }
        # local SID query. able to resolve 
        # default accounts (identical SIDs) and domain accounts
        try {
            $objSID = [System.Security.Principal.SecurityIdentifier]::new($SID)
            $name = $objSID.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            # if the sid cannot be resolved return the plain sid again
            # (in case it's a local accounts that was already deleted) 
            $name = $SID
        }
        return $name

    }

    <#
    .SYNOPSIS  
        Extract all user management events from the given event log 
    .DESCRIPTION
        Can process one or a list of previously backed up logs or run against live logs
    .EXAMPLE
        PS> Get-EventlogUserEvents -Path "C:\Windows\System32\winevt\Logs\Security.evtx"

        Returns all data from a single evtx logfile
    #>
    Function Get-EventlogUserEvents {

        [CmdletBinding()]

        Param (
            # List of files to be analyzed
            # By default runs against the live Security log
            [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
            [System.IO.FileInfo[]] $Path = "$env:WINDIR\System32\winevt\Logs\Security.evtx"
        )

        Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=4720 or EventID=4722 or EventID=4723 or EventID=4724 or EventID=4725 or EventID=4726 or EventID=4738 or EventID=4740 or EventID=4765 or EventID=4766 or EventID=4767 or EventID=4780 or EventID=4781]]" | Foreach-Object {
			# Replace CR/LF with just CR in message. Workaround for a bug / feature
			# in Out-Gridview where the lines would be truncated instead
			[PSCustomObject] @{
                Time = $_.TimeCreated
	            EventID = $_.ID
	            ProcessID = $_.ProcessID
                Message = $_.Message.replace("`r`n" , "`r" )
            }
        } | Sort-Object -Property TimeCreated -Descending
    }

    <#
    .SYNOPSIS  
        Queries login, logoff, lock and unlock data from a list of logs
    .DESCRIPTION
        Can process one or a list of previously backed up logs or run against live logs
    .EXAMPLE
        PS> Get-InteractiveUserLogons -Path "C:\Windows\System32\winevt\Logs\Security.evtx"

        Returns all data from a single evtx logfile
    #>
    Function Get-InteractiveUserLogons {

        [CmdletBinding()]

        Param (
            # List of files to be analyzed
            # By default runs against the live Security log
            [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
            [System.IO.FileInfo[]] $Path = "$env:WINDIR\System32\winevt\Logs\Security.evtx"
        )

        # Gather data from eventlog
        # All those event ids both save the users SID and names
        # Because of that the values just have to be retrieved
        # without having to resolve them manually 
        Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=4624 or EventID=4647 or EventID=4800 or EventID=4801]]" | ForEach-Object {
            $event = $_
            switch ($event.ID) {
                # Event ID 4624: "An account was successfully logged on"
                # Property 8 describes the logon tye (domain logon, local logon,  iden-tity change...)
                # Property 26 describes if the user logged on with an elevated token ("run as admin") or as a normal user
                4624 { 
                    if($event.Properties[8].Value -in @(2, 7, 10, 11)) {
                        $eventType = ""                    
                        # The Properties[6] filter only equals to true for interactive logons
                        if($event.Properties[8].Value -eq 2 -and -not ($event.Properties[6].Value -eq 'Window Manager' -or $event.Properties[6].Value -eq 'Font Driver Host')) {
                            $eventType = "Logon"
                        } elseif($event.Properties[8].Value -eq 10) {
                            $eventType = "Remote-Logon"
                        } elseif($event.Properties[8].Value -eq 11) {
                            $eventType = "Offline-Logon"
                        }

                        if($eventType) {
                            $elevated = $event.Properties[26].Value -eq "%%1843"
                            if($elevated) {
                                [PSCustomObject] @{ SystemTime=$event.TimeCreated; AccountName=$event.Properties[5].Value; SessionId=$event.Properties[7].Value; EventType="$eventType" }
                            } else {
                                [PSCustomObject] @{ SystemTime=$event.TimeCreated; AccountName=$event.Properties[5].Value; SessionId=$event.Properties[7].Value; EventType="$eventType (elevated)" }
                            }
                        }
                    }
                    break
                }
                # Event ID 4647: "User initiated logoff"
                4647 {
                    [PSCustomObject] @{ SystemTime=$event.TimeCreated; AccountName=$event.Properties[1].Value; SessionId=$event.Properties[3].Value; EventType="Logoff" }
                    break
                }
                # Event ID 4800: "The workstation was locked"
                4800 {
                    [PSCustomObject] @{ SystemTime=$event.TimeCreated; AccountName=$event.Properties[1].Value; SessionId=$event.Properties[3].Value; EventType="Lock" }
                    break
                }
                # Event ID 4801: "The workstation was unlocked"
                4801 {
                    [PSCustomObject] @{ SystemTime=$event.TimeCreated; AccountName=$event.Properties[1].Value; SessionId=$event.Properties[3].Value; EventType="Unlock" }
                    break
                }
            }
        }
    }


    <#
    .SYNOPSIS  
        Queries time, account, logontype and elevated flags from accounts logged into a system
    .DESCRIPTION
        Can process one or a list of previously backed up logs or run against live logs
    .EXAMPLE
        PS> Get-UserLogons -Path "C:\Windows\System32\winevt\Logs\Security.evtx"

        Returns all data from a single evtx logfile
    #>
    Function Get-UserLogons {

        [CmdletBinding()]

        Param (
            # List of files to be analyzed
            # By default runs against the live Security log
            [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
            [System.IO.FileInfo[]] $Path = "$env:WINDIR\System32\winevt\Logs\Security.evtx"
        )

        # Security logon type is an enum documented at:
        # https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/ne-ntsecapi-security_logon_type
        function Get-LogonType ($LogonTypeId) {
            switch ($LogonTypeId) {
                '2' { return "Interactive" }
                '3' { return "Network" }
                '4' { return "Batch" }
                '5' { return "Service" }
                '6' { return "Proxy" }
                '7' { return "Unlock" }
                '8' { return "NetworkCleartext" }
                '9' { return "NewCredentials" }
                '10' { return "RemoteInteractive" }
                '11' { return "CachedInteractive" }
                Default { return "Unknown" }
            }
        }

        # Gather data from eventlog
        # Event ID 4624: "An account was successfully logged on"
        # That event id saves the users SID and names
        # Because of that the values just have to be retrieved
        # without having to resolve them manually
        Get-WinEvent -Path $Path -FilterXPath "*[System[EventID=4624]]" | ForEach-Object {
            $timeCreated = $_.TimeCreated
            $accountName = $_.Properties[5].Value
            $logonType = Get-LogonType -LogonTypeId $_.Properties[8].Value
            $elevated = $_.Properties[26].Value -eq "%%1843"

            [PSCustomObject] @{ SystemTime=$timeCreated; AccountName=$accountName; LogonType=$logonType; Elevated=$elevated }
        }
    }



    <#
    .Synopsis
       Lists all powershell scripts executed on a system or from previously pulled po-wershell/operational logs
    .DESCRIPTION
       You can supply a hashtable to resolve 
    .EXAMPLE
       Beispiel für die Verwendung dieses Cmdlets
    .EXAMPLE
       PS> Get-ExecutedPowerShellScripts -Files 'C:\Temp\test\Powershell_Logs.evtx' -StartTime (Get-Date).AddDays(-2)

       Lists all powershell scripts that were executed the last two days from events pulled from the given log.
       Since no sids / hashtables are given as parameter the local users from the origi-nal system cannot be resolved
       and will be displayed as their SIDs instead
    #>
    function Get-ExecutedPowerShellScripts {

        [CmdletBinding()]

        Param (
            # The computer to be queried live
            [Parameter(ParameterSetName='Live', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [String] $ComputerName = "localhost",
        
            # A list of files to be analyzed
            [Parameter(ParameterSetName='FromFile', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [System.IO.FileInfo[]] $Files,

            # A hashtable consisting of SIDs as key and user names as their values
            # If a computer is queried live the list can be automatically be created
            # If not set SIDs will not be resolved and instead be displayed as-is
            [Parameter(ParameterSetName='FromFile', Mandatory=$false, ValueFromPipelineByPropertyName=$false)]
            [System.Collections.Hashtable] $UserSIDsAndNames = @{}, # Defaults to an empty hashtable if not set explicitly
        
            # The date from which events will be listed
            # Older entries will be ignored
            [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [System.DateTime] $StartTime = (Get-Date).AddDays(-1)
        )

        Begin {
            if($PSCmdlet.ParameterSetName -eq "Live" -and $ComputerName -ne "localhost" -and $UserSIDsAndNames.Count -eq 0) {
                $remoteSIDData = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-LocalUser | Select-Object -Property Name, SID }
                $remoteSIDData | ForEach-Object { $UserSIDsAndNames[$_.SID] = $_.Name }
            } else {
                $remoteSIDData = $script:SidToUserNameMapping
            }
        }

        Process {
            switch ($PSCmdlet.ParameterSetName) {
                'Live' {
                    $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{ LogName = "Microsoft-Windows-PowerShell/Operational"; StartTime = $StartTime; ID = 4104 }
                    break
                }
                'FromFile' {
                    # querying events directly from file does not support the Filter-Hashtable parameter
                    # querying with xpath instead. Result is the same
                    $timeString = $StartTime.ToUniversalTime().ToString('s')
                    $events = Get-WinEvent -Path $Files -FilterXPath "*[System[TimeCreated[@SystemTime>'$timeString']][EventID=4104]]"
                    break
                }
            }

            $events | ForEach-Object {
                [PSCustomObject] @{
	                TimeCreated = $_.TimeCreated
                    UserSid = $_.UserId.Value
                    ScriptBlockID = $_.Properties[3].Value
                    ScriptBlockCurrent = $_.Properties[0].Value
                    ScriptBlockTotal = $_.Properties[1].Value
                    ScriptBlockText = $_.Properties[2].Value
                    FilePath = $_.Properties[4].Value
                }
            } | Sort-Object -Property ScriptBlockID, ScriptBlockCurrent | Group-Object ScriptBlockID | ForEach-Object {
                $filePath = $_.Group[0].FilePath
                if($filePath) {
                    $resultPath = $filePath
                } else {
                    $resultPath = "<no path>"
                }

                [PSCustomObject] @{
	                TimeCreated = $_.Group[0].TimeCreated
                    UserName = Get-AccountNameOfSID -SID $_.Group[0].UserSid -Mapping $remoteSIDData
                    FilePath = $resultPath
                    Script = ($_.Group.ScriptBlockText -join "").replace("`r`n" , "`r" ) # converting from cr-lf to just lf so out-gridview shows the whole script insted of truncating it after a certain length
                }
            } | Sort-Object -Property TimeCreated -Descending
        }

        End {}

    }

    ####################################
    #endregion EVENT LOG REPORTS       #
    ####################################


    ####################################
    #endregion FUNCTIONS               #
    ####################################


    # Setting InformationPreference to output the information messages in the console
    # That way the user can see the current state and it can be logged via Start-Transcript
    $PreviousInfomationPreference = $InformationPreference

    # There is a Bug in Start-Transcript in PowerShell versions up to 5 
    # that only logs information messages when it should not, and does not log
    # when it should. See:
    # https://github.com/PowerShell/PowerShell/issues/4645
    if($PSVersionTable.PSVersion.Major -gt 5) {
        $global:InformationPreference = [System.Management.Automation.ActionPreference]::Continue
    }

    # The path where necessary external tools will be copied to on the remote machine
    $RemoteHelpFilesDir = "C:\Temp\HelpFiles\"

    # if ResultsFolder was not set default to a subfolder in the scripts directory
    # Since we are making use of $PSScriptRoot and the variable is not initialized
    # in the parameter block as default value it has to be assigned at a later time (aka. now)
    if(-not $ResultsFolder) {
        $ResultsFolder = "$PSScriptRoot\Captures\$Computername\"
    }
    
    # Start logging all script output and log script parameters
    # The transcript file has to reside in the top folder so it does not
    # block the hashing and zipping of backed up data (since it's still being written to)
    $TranscriptfilePath = Split-Path -Path $ResultsFolder -Parent
    Start-Transcript -OutputDirectory $TranscriptfilePath -IncludeInvocationHeader
    Log-Information "Starting PowerTriage"
    Log-Information "Target Computer: $ComputerName"
    Log-Information "Results Folder: $ResultsFolder"
    Log-Information "Enabled Options: $($Options -join ", ")"

}

Process {

    # Test local WSMan encryption settings
    Log-Progress "Testing if local WSMan encryption is enabled..." -PercentComplete 0
    $localWSmanEncryption = Test-WSManEncryptionEnabled -Side Server
    if($localWSmanEncryption -match "No permission") {
        Log-Warning "No permission to query local WSMan encryption setting. Is the script running as admin?"
    }elseif($localWSmanEncryption -ne $true) {
        Log-Error "The local WSMan is not configured to use encryption. It's not save to establish a remote connection to a potentially infected machine. Enable encryption or use a different machine."
        return
    } else {
        Log-Information "Local WSMan is correctly configured to use encryption"
    }


    # Establish the remote session on the target system
    Log-Progress "Establishing remote session..." -PercentComplete 2
    if($LAPSUserName) {
        if(-not $LAPSPassword) {
            try {
                # Get the LAPS password from the AD
                # If the LAPS password could not be gotten automatically the user is able to input a different credential for authentication later
                # Since the password is in clear text it has to get converted
                # to a SecureString ASAP, best before assigning it to a variable
                Log-Information "Retrieving LAPS password from AD..." -PercentComplete 2
                $LAPSPassword = ConvertTo-SecureString -AsPlainText -Force -String (Get-LAPSPasswordFromAD -ComputerName $ComputerName -ErrorAction Stop)."ms-Mcs-AdmPwd"
            } catch {
                # If the LAPS password could not be gotten automatically (like when missing permissions, or LAPS not active)
                # the user is able to input a different credential for authentication
                Log-Warning "Could not automatically get the LAPS password from AD. Missing permissions or does the computer not have LAPS installed?"
            }
        } 

        if($LAPSPassword) {
            Log-Information "LAPS password is available. Trying login with LAPS account..."
            $RemoteCredential = [PSCredential]::new("$ComputerName\$LAPSUserName", $LAPSPassword)
            $RemoteSession = New-PSSession -ComputerName $ComputerName -Credential $RemoteCredential -Authentication Negotiate -ErrorVariable remoteconnectionerror -ErrorAction SilentlyContinue
        }
    } else {
        # If LAPSUser is not set: Attempt to authenticate with the currently active account
        Log-Information "No LAPS account available. Logging on with current credentials..."
        $RemoteSession = New-PSSession -ComputerName $ComputerName -ErrorVariable remoteconnectionerror -ErrorAction SilentlyContinue
    }

    while(-not $RemoteSession) {
        if($remoteconnectionerror) {
            # If autentication failed
            Log-Warning "A remote connection to $ComputerName could not be established. Error: $($remoteconnectionerror[0].Exception)"
        } else {
            # If there were no valid credentials to authenticate yet
            Log-Warning "A remote connection to $ComputerName could not be established: No valid credentials"
        }

        Log-Information "Asking the user for manual credential input"
        $RemoteCredential = Get-Credential -Message "Input Remote Authentification Credentials" -UserName $LAPSUserName
        
        if($RemoteCredential) {
            $RemoteSession = New-PSSession -ComputerName $ComputerName -Credential $RemoteCredential -Authentication Negotiate -ErrorVariable remoteconnectionerror -ErrorAction SilentlyContinue
        } else {
            # If $RemoteCredential is empty (the user cancelled the credential input dialog)
            # exit the script entirely
            Log-Information "The user cancelled the credential input dialog box. Exiting PowerTriage."
            return
        }
    }
    Log-Information "Successfully established remote connection!"


    # Test if the communication is encrypted
    Log-Progress "Testing for remote WSman encryption" -PercentComplete 4
    $remoteWSmanEncryption = Invoke-Command -Session $RemoteSession -ScriptBlock ${function:Test-WSManEncryptionEnabled} -ArgumentList "Client"
    if($remoteWSmanEncryption -ne $true) {
        Log-Warning "The remote WSMan is not configured to use encryption. You are establishing a remote connection to a potentially infected machine."
    } else {
        Log-Information "Remote WSMan not configured to use encryption."
    }

    # Test for time drift bewtween the systems
    if($Options -contains "TimeDriftCheck") {
        Log-Progress "Running time drift check..." -PercentComplete 6
        # No not output drift warnings. It's handled manually afterwards with Log-Information / Log-Warning instead
        $timeData = Test-TimeDrift -RemoteSession $RemoteSession -WarningAction SilentlyContinue
        Log-Information "Local time: $(Get-Date -Date $timeData.LocalTime -Format "HH:mm:ss.fff") - Remote Time: $(Get-Date -Date $timeData.RemoteTime -Format "HH:mm:ss.fff")"
        
        # Warn when finding significant time drift between systems
        if($timeData.TimeDiffMS -gt 250 -or $timeData.TimeDiffMS -lt -250) {
            Log-Warning "Remote computer has a time difference of $($timeData.TimeDiffMS). Differences over 250ms are considered significant. Other possible reason: Does the network have very high latency?"
        } else {
            Log-Information "Remote computer has a time difference of $($timeData.TimeDiffMS). An insignificant difference. Good!"
        }
    } else {
        Log-Warning "Option to check for time drift beweeen systems is not set. Will be skipped."
    }


    ####################################
    #region    DATA CAPTURE            #
    ####################################

    # Create output directory if it does not exist yet
    if(-not (Test-Path -Path $ResultsFolder)) {
        New-Item -Path $ResultsFolder -ItemType Directory -Force | Out-Null
    }


    # SYSTEM INFO
    if($Options -contains "ComputerInfo") {
        Log-Progress "Retrieving computer information" -PercentComplete 8
        $remoteComputerInfo = @(Invoke-Command -Session $RemoteSession -ScriptBlock { Get-ComputerInfo } | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId)

        Log-Information "Finished restrieving computer information ($($remoteComputerInfo.Count) entries). Saving and displaying..."
        $remoteComputerInfo | Export-Csv -Path (Join-Path -Path $ResultsFolder -ChildPath "computerinfo.csv") -NoTypeInformation -Delimiter ";"
        $remoteComputerInfo | Select-Object -Property CsNAme,
                                                      CsDomain,
                                                      CsUserName, 
                                                      OsName,
                                                      WindowsVersion, 
                                                      OsVersion, 
                                                      CsManufacturer, 
                                                      CsModel,
                                                      OsLastBootUpTime, TimeZone | Out-GridView -Title "System Info"
        Log-Information "Finished computer information task."
    } else {
        Log-Warning "Option to capture general computer information is not set. Will be skipped."
    }


    # NETWORK
    if($Options -contains "Networking") {
        Log-Progress "Retrieving network information" -PercentComplete 10
        Log-Information "Network Step 1: TCP information"
        $remoteTCPInfo = @(Invoke-Command -Session $RemoteSession -ScriptBlock ${function:Get-TCPInformation} | Select-Object -Property * -ExcludeProperty PsComputerName, RunspaceId)
        Log-Information "Finished restrieving TCP information ($($remoteTCPInfo.Count) entries). Saving and displaying..."
        $remoteTCPInfo | Export-Csv -Path (Join-Path -Path $ResultsFolder -ChildPath "tcpconnections.csv") -NoTypeInformation -Delimiter ";"
        $remoteTCPInfo | Out-GridView -Title "TCP Connections"

        Log-Information "Network Step 2: UDP information"
        $remoteUDPInfo = @(Invoke-Command -Session $RemoteSession -ScriptBlock ${function:Get-UDPInformation} | Select-Object -Property * -ExcludeProperty PsComputerName, RunspaceId)
        Log-Information "Finished restrieving UDP information ($($remoteUDPInfo.Count) entries). Saving and displaying..."
        $remoteUDPInfo | Export-Csv -Path (Join-Path -Path $ResultsFolder -ChildPath "udpconnections.csv") -NoTypeInformation -Delimiter ";"
        $remoteUDPInfo | Out-GridView -Title "UDP Connections"

        Log-Information "Network Step 3: Routing information"
        $remoteRoutingInfo  = @(Invoke-Command -Session $RemoteSession -ScriptBlock ${function:Get-RoutingInformation} | Select-Object -Property * -ExcludeProperty PsComputerName, RunspaceId)
        Log-Information "Finished restrieving Routing information ($($remoteRoutingInfo.Count) entries). Saving and displaying..."
        $remoteRoutingInfo | Export-Csv -Path (Join-Path -Path $ResultsFolder -ChildPath "routingcache.csv") -NoTypeInformation -Delimiter ";"
        $remoteRoutingInfo | Out-GridView -Title "Routing Info"

        Log-Information "Network Step 4: ARP Cache information"
        $remoteARPCacheInfo = @(Invoke-Command -Session $RemoteSession -ScriptBlock ${function:Get-ARPCacheInformation} | Select-Object -Property * -ExcludeProperty PsComputerName, RunspaceId)
        Log-Information "Finished restrieving ARP Cache information ($($remoteARPCacheInfo.Count) entries). Saving and displaying..."
        $remoteARPCacheInfo | Export-Csv -Path (Join-Path -Path $ResultsFolder -ChildPath "arpcache.csv") -NoTypeInformation -Delimiter ";"
        $remoteARPCacheInfo | Out-GridView -Title "ARP Cache"

        Log-Information "Finished network information task."
    } else {
        Log-Warning "Option to capture network information is not set. Will be skipped."
    }

    
    # FILE HANDLES
    if($Options -contains "FileHandles") {
        Log-Progress "Retrieving file handle information" -PercentComplete 14
        $handle64Path = "$PSScriptRoot\HelpFiles\handle64.exe"
        $remoteHandle64Path = Join-Path -Path $RemoteHelpFilesDir -ChildPath "handle64.exe"
        if(Test-Path -Path $handle64Path) {
            Invoke-Command -Session $RemoteSession -ScriptBlock {
                if(-not (Test-Path -Path $using:RemoteHelpFilesDir)) {
                    New-Item -Path $using:RemoteHelpFilesDir -ItemType Directory | Out-Null
                }
            }
            Copy-Item -Path $handle64Path -Destination $remoteHandle64Path -ToSession $RemoteSession

            $remoteFileHandleInfo = @(Invoke-Command -Session $RemoteSession -ScriptBlock ${function:Get-FileHandles} -ArgumentList $remoteHandle64Path | Select-Object -Property * -ExcludeProperty PsComputerName, RunspaceId)
            Log-Information "Finished restrieving file handle information ($($remoteFileHandleInfo.Count) entries). Saving and displaying..."
            $remoteFileHandleInfo | Export-Csv -Path (Join-Path -Path $ResultsFolder -ChildPath "handles.csv") -NoTypeInformation -Delimiter ";"
            $remoteFileHandleInfo | Out-GridView -Title "Open File Handles"
        } else {
            Log-Warning "Handle64.exe required under `"$handle64Path`". The Handle collector is unable to run"
        }
    } else {
        Log-Warning "Option to capture file handles is not set. Will be skipped."
    }


    # PROCESSES
    if($Options -contains "Processes") {
        Log-Progress "Retrieving process information" -PercentComplete 20
        $remoteProcessInfo = @(Invoke-Command -Session $RemoteSession -ScriptBlock ${function:Get-ProcessInformation} | Select-Object -Property * -ExcludeProperty PsComputerName, RunspaceId) | Sort-Object -Property Name
        Log-Information "Finished restrieving process information ($($remoteProcessInfo.Count) entries). Saving and displaying..."
        $remoteProcessInfo | Export-Csv -Path (Join-Path -Path $ResultsFolder -ChildPath "processes.csv") -NoTypeInformation -Delimiter ";"
        $remoteProcessInfo | Out-GridView -Title "Running Processes"
    } else {
        Log-Warning "Option to process information is not set. Will be skipped."
    }


    # BITLOCKER
    if($Options -contains "Bitlocker") {
        # The user does not need bitlocker data for incident evaluation.
        # Just for potential offline forencics later. Therefore no Out-Gridview here
        Log-Progress "Retrieving bitlocker information" -PercentComplete 24
        $remoteBitlockerInfo = @(Invoke-Command -Session $RemoteSession -ScriptBlock ${function:Get-BitlockerKeys} | Select-Object -Property * -ExcludeProperty PsComputerName, RunspaceId)
        Log-Information "Finished restrieving bitlocker information ($($remoteBitlockerInfo.Count) entries). Saving..."
        $remoteBitlockerInfo | Export-Csv -Path (Join-Path -Path $ResultsFolder -ChildPath "bitlocker.csv") -NoTypeInformation -Delimiter ";"
    } else {
        Log-Warning "Option to capture bitlocker information is not set. Will be skipped."
    }


    # ENVIRONMENTAL VARIABLES
    if($Options -contains "EnvironmentalVariables") {
        Log-Progress "Retrieving environmental variable information" -PercentComplete 28
        $remoteEnvironmentalVariableInfo = @(Invoke-Command -Session $RemoteSession -ScriptBlock ${function:Get-EnvironmentalVariableInfo} | Select-Object -Property * -ExcludeProperty PsComputerName, RunspaceId)
        Log-Information "Finished restrieving environmental variable information ($($remoteEnvironmentalVariableInfo.Count) entries). Saving and displaying..."
        $remoteEnvironmentalVariableInfo | Export-Csv -Path (Join-Path -Path $ResultsFolder -ChildPath "environmental_variables.csv") -NoTypeInformation -Delimiter ";"
        $remoteEnvironmentalVariableInfo | Out-GridView -Title "Environmental Variables"
    } else {
        Log-Warning "Option to capture environmental variable information is not set. Will be skipped."
    }


    # LOCAL USERS
    if($Options -contains "LocalUsers") {
        Log-Progress "Retrieving user account information" -PercentComplete 32
        $remoteUserInfo = @(Invoke-Command -Session $RemoteSession -ScriptBlock ${function:Get-LocalUserInfo} | Select-Object -Property * -ExcludeProperty PsComputerName, RunspaceId)
        Log-Information "Finished restrieving user account information ($($remoteUserInfo.Count) entries). Saving and displaying..."
        $remoteUserInfo | Export-Csv -Path (Join-Path -Path $ResultsFolder -ChildPath "user_accounts.csv") -NoTypeInformation -Delimiter ";"
        $remoteUserInfo | Out-GridView -Title "Local Users"

        if($Options -contains "EventlogReports") {
            $script:SidToUserNameMapping = @{}
            $remoteUserInfo | ForEach-Object { $script:SidToUserNameMapping.Add($_.SID.Value, $_.Name) }
        }
    } else {
        Log-Warning "Option to capture local user information is not set. Will be skipped."
    }


    # AUTOSTARTS
    if($Options -contains "Autostarts") {
        Log-Progress "Retrieving autostart information" -PercentComplete 36
        $autorunsc64Path = "$PSScriptRoot\HelpFiles\autorunsc64.exe"
        $remoteAutorunsc64Path = Join-Path -Path $RemoteHelpFilesDir -ChildPath "autorunsc64.exe"
        if(Test-Path -Path $autorunsc64Path) {
            Invoke-Command -Session $RemoteSession -ScriptBlock {
                if(-not (Test-Path -Path $using:RemoteHelpFilesDir)) {
                    New-Item -Path $using:RemoteHelpFilesDir -ItemType Directory | Out-Null
                }
            }
            Copy-Item -Path $autorunsc64Path -Destination $remoteAutorunsc64Path -ToSession $RemoteSession

            $remoteAutostartInfo = @(Invoke-Command -Session $RemoteSession -ScriptBlock ${function:Get-Autoruns} -ArgumentList $remoteAutorunsc64Path | Select-Object -Property * -ExcludeProperty PsComputerName, RunspaceId)

            Log-Information "Finished restrieving autostart information ($($remoteAutostartInfo.Count) entries). Saving and displaying..."
            $remoteAutostartInfo | Export-Csv -Path (Join-Path -Path $ResultsFolder -ChildPath "autostarts.csv") -NoTypeInformation -Delimiter ";"
            $remoteAutostartInfo | Select-Object -Property Time, "Entry Location", Entry, Enabled, Category, Profile, Description, Company, ImagePath, "Launch String" | Out-GridView -Title "Autostarts"
        } else {
            Log-Warning "autorunsc64.exe required under `"$autorunsc64Path`". The Autoruns collector is unable to run"
        }
    } else {
        Log-Warning "Option to capture autostart information is not set. Will be skipped."
    }


    # EVENT LOGS
    if($Options -contains "EventLogs") {
        Log-Progress "Retrieving event logs" -PercentComplete 60
        $ResultsFolderEventlogs = Join-Path -Path $ResultsFolder -ChildPath "Eventlogs"
        $EventLogs = Get-EventLogBackup -ComputerName $ComputerName -Destination $ResultsFolderEventlogs
        Log-Information "Finished restrieving event logs ($($EventLogs.Count) entries)"
    } else {
        Log-Warning "Option to capture eventlogs is not set. Will be skipped."
    }
    

    # RAM DUMP
    if($Options -contains "RamDump") {
        Log-Progress "Creating RAM dump background task" -PercentComplete 70

        $RamCapturerDirectory = Join-Path -Path $PSScriptRoot -ChildPath "\HelpFiles\BelkasoftRamCapturer\"
        if(Test-Path -Path $RamCapturerDirectory) {
            $RamDumpCreationJob = Invoke-MemoryImageJob -PSSession $RemoteSession -DestinationFolder $ResultsFolder -RamCapturerDirectory $RamCapturerDirectory -RemoteDirectory $RemoteHelpFilesDir
        } else {
            Log-Warning "BelkasoftRamCapturer directory required under `"$RamCapturerDirectory`". The RamDump collector is unable to run"
        }
    } else {
        Log-Warning "Option to create a RAM dump is not set. Will be skipped."
    }


    ####################################
    #endregion DATA CAPTURE            #
    ####################################


    ####################################
    #region    EVENT LOG REPORTS       #
    ####################################
    

    # Only generate event log reports if the event logs have been saved
    if($Options -contains "EventLogs") {
        if($Options -contains "EventlogReports") {
            Log-Progress "Generating event log reports" -PercentComplete 75
            # Parallelizing the different jobs is not adviced because the 
            # report is mainly limited by disk IO, not computing power

            $SecurityEventLog = $EventLogs | Where-Object { $_.Name -eq "Security.evtx" }
            $PowerShellOperationalEventLog = $EventLogs | Where-Object { $_.Name -eq "Microsoft-Windows-PowerShell%4Operational.evtx" }

            if($SecurityEventLog) {
                Log-Information "Generating user logon report..."
                $userLogonReport = @(Get-UserLogons -Path $SecurityEventLog)
                $userLogonReport | Out-GridView -Title "All User Logons"

                Log-Information "Generating interactive logon report..."
	            $interactiveUserLogonReport = @(Get-InteractiveUserLogons -Path $SecurityEventLog)
                $interactiveUserLogonReport | Out-GridView -Title "Interactive User Logons"

                Log-Information "Generating user management events report..."
	            $eventlogUserManagementEventsReport = @(Get-EventlogUserEvents -Path $SecurityEventLog)  
                $eventlogUserManagementEventsReport | Out-GridView -Title "User Management Events (creation, deletion, ...)"
            } else {
                Write-Warning "The Security event log could not be backed up. Some event log reports will not run"
            }
    
            if($PowerShellOperationalEventLog) {
                Log-Information "Generating executed powershell scripts report..."
	            $eventlogUserManagementEventsReport = @(Get-ExecutedPowerShellScripts -Files $PowerShellOperationalEventLog)
                $eventlogUserManagementEventsReport | Out-GridView -Title "Executed PowerShell Scripts"
            } else {
                Write-Warning "The Powershell/Operational event log could not be backed up. Some event log reports will not run"
            }


            Log-Information "Finished generating event log reports"
        } else {
            Log-Warning "Option to create event log reports is not set. Will be skipped."
        }
    } else {
        Log-Warning "Option to capture eventlogs is not set. Therefore event log reports will not run."
    }

    
    ####################################
    #endregion EVENT LOG REPORTS       #
    ####################################

    # Before the backup of files the ram dump from the
    # target machine has to be copied
    if($Options -contains "RamDump" -and $RamDumpCreationJob) {
        if($RamDumpCreationJob.State -ne "Finished") {
            Log-Information "Waiting for the RAM Dump background job to finish..."
            Wait-Job -Job $RamDumpCreationJob | Out-Null
        }

        $MemDumpPath = Receive-Job -Job $RamDumpCreationJob

	    Log-Information "Copying ram dump from remote machine to destination folder... (this will take some time)"
        Copy-Item -Path $MemDumpPath -Destination $ResultsFolder -FromSession $RemoteSession
	    Log-Information "Finished copying ram dump."
    }


    # FILE ZIPPING AND HASHING of all files besides the transcript (is still being written to)
    # The original, not zipped files will be deleted to save disk space
    # and prevent accidental manipulation
    if($Options -contains "HashAndCompress") {
        Log-Progress "All saved files will be zipped and hashed." -PercentComplete 90
        $ZippingAndHashingTask = Start-Job -Name "ZippingAndHashingTask" -ScriptBlock ${Function:Compress-DirectoryWithHashes} -ArgumentList $ResultsFolder, $ResultsFolder, $true
    } else {
        Log-Warning "Option to hash and zip all captured files is not set. All saved file will be kept as-is."
    }


    # LAUNCH THE INTERACTIVE USER DIALOG
    Log-Progress "Displaying interactive user dialog" -PercentComplete 100
    do {
        Write-Host "Data capture, hashing and zipping is finished. Is there something else you want to do?"
        Write-Host "1. " -ForegroundColor Green -NoNewline
        Write-Host "Delete Help Files on remote machine under `"$RemoteHelpFilesDir`"" -ForegroundColor Gray
        Write-Host "2. " -ForegroundColor Green -NoNewline
        Write-Host "Start a RDP session to $ComputerName ($($env:USERNAME) with RestrictedAdmin)" -ForegroundColor Gray
        Write-Host "[any other input to finish]"
       
        $UserInput = Read-Host -Prompt "Your choice"
        $UserInputHandled = $false

        switch ($UserInput) {
            1 {
                Log-Information "User chose 1: Delete the remote help files folder"
                Invoke-Command -Session $RemoteSession -ScriptBlock { Remove-Item -Path $using:RemoteHelpFilesDir -Force -Recurse }
                $UserInputHandled = $true
            }
            2 {
                Log-Information "User chose 2: Launch RDP session with $($env:USERNAME) as RestrictedAdmin"
                mstsc.exe /V:$ComputerName /restrictedAdmin
                $UserInputHandled = $true
            }
            Default {
                Log-Information "User chose to quit the dialog"
            }
          }

    } while ($UserInputHandled -eq $true)


    # Connection to the remote PC is no longer needed at this point.
    # => Close it
    Log-Information "Closing remote session..."
    Remove-PSSession -Session $RemoteSession
    Log-Information "Remote Session closed"


    # Wait until all async jobs have finished
    if($ZippingAndHashingTask -or $RamDumpCreationJob) {
        Log-Information "Waiting for all background jobs to finish..."
        if($RamDumpCreationJob) {
            Log-Information "Status of Ram Dump background job: $($RamDumpCreationJob.State)"
            Wait-Job -Job $RamDumpCreationJob | Out-Null
        }
        if($ZippingAndHashingTask) {
            Log-Information "Status of Zipping And Hashing background job: $($ZippingAndHashingTask.State)"
            Wait-Job -Job $ZippingAndHashingTask | Out-Null
        }
        Log-Information "Hashing and zipping is finished!"
    }

}

End {

    # In case the script is aborted in any way and there still is
    # a remote session open it has to be closed to not end up with
    # a lingering session on the target computer
    if($RemoteSession -and $RemoteSession.State -eq "") {
        Log-Warning "Script is being finished, but a remote session is still active. Remote session will be closed"
        Remove-PSSession -Session $RemoteSession
    }

    # Remove all async tasks, finished or not
    if($RamDumpCreationJob) {
        Remove-Job -Job $RamDumpCreationJob
    }
    if($ZippingAndHashingTask) {
        Remove-Job -Job $ZippingAndHashingTask
    }

    # Stop logging
    Log-Information "PowerTriage finished~ (Stopping Transcript)"
    Stop-Transcript

    # Restore the previous information preference
    $InformationPreference = $PreviousInfomationPreference

}
