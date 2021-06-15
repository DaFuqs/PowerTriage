# Overview
PowerTriage is a tool for SOCs and CERTs mainly used for Indicent Detection and Incodent Response.
PowerTriage can be used to back up and display lots of live data from systems. The intormation gathering process is designed to be as secure as possible to not expose any danger to the corporate network by logging onto a potentially infected machine.

Domain joined or not, authentication can be done via Local Accounts (automatic password retrieval from AD if using LAPS), or your usual domain analyst accounts.


# Featues

## Collectors
PowerTriage supports capturing the following data. Each collector can be turned on or off separately.

- Autostarts: Captures all autostarts using Sysinternals autorunsc64.exe (download separately)
- Networking: Captures active TCP connections, UDP data, routing information and ARP cache
- FileHandles: Captures all open file handles using Sysinternals handle.exe (download separately)
- RamDump: Creates a memory image using Belkasoft RAM Capturer
- ComputerInfo: Captures general system information, like computer name, windows edition, ...
- Processes: Captures all active processes
- Bitlocker: Captures bitlocker keys for all active volumes. (will not get displayed, just backed up)
- LocalUsers: Captures all local users
- Environmental Variables: Calputes environmental variables of the system and all active users
- EventLogs: Creates backups of all event log files

## Additional checks and reports
- TimeDriftCheck: Checks the time difference between source and target system and alerts if the difference is significant
- EventLogReports: Uses backed up event log files to generate a list of reports
	- All User logons
	- Interactive User Logons
	- User Creations, Deletions and Modifications
	- Ran PowerShell scripts
- HashAndCompress: Calculates hashes for all captured files and stores them as a zip file

# Usage

## Setup
Since it's a script you just have to download an run it. For the Autostarts, FileHandles and RamDump to work you have to supply some additional tools, which are:
- Sysinternals autorunsc.exe
- Sysinternals handle.exe
- Belkasoft RAM Capturer
Put the Sysinternals tools and Ram Capturer directory in the subfolder "HelpFiles", like shown in this repository

## Parameters

### -ComputerName
The Computer to target

### -LAPSUserName
The name of a local / LAPS account. If not set remote authentication will be attempted with the current user credentials. Since that is not a local account password hashes will be transmitted to the destination computer - it's therefore less safe than using a local / LAPS account though

### -LAPSPassword
The password for the local / LAPS account. If -LAPSUserName is set but password is not the script will automatically try to query the password of the user from Active Directory instead

### -Options
Define the algorithms that the script should run against the target machine to save and capture. Possible Values (As described in #Collectors): Autostarts, Networking, FileHandles, RamDump, ComputerInfo, Processes, Bitlocker, TimeDriftCheck, LocalUsers, EnvironmentalVariables, EventLogs, EventLogReports, HashAndCompress

### -ResultsFolder
The folder where all capture output should be saved to
