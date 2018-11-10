$ProVersion = "v3.1.2"

<#
PowerShell Profile $ProVersion

Author: Jeremy DeWitt aka JBear

Update Notes:
Version 3.1.2:
	-Added GetSize function to measure child directory sizes for troubleshooting purposes.

Version 3.1.1:
	-Added STIGViewer function.

Version 3.1.0:
	-Added ScanSubnet function to scan a range of IP addresses.
	-Adjusted how job progress is shown within each function.

Version 3.0.5:
	-Added job(s) remaining counter to appropriate functions.

Version 3.0.4:
	-Added new profile version detection.

Version 3.0.3:
	-Added Windows Explorer selection to InstallPackage for ease of use.

Version 3.0.2:
	-Renamed NewADUser to CreateNewUser.
	-Added GUI to CreateNewUser process.	

Version 3.0.1:
	-Added PatchSearch function to report specific patches and install times.

Version 2.9:
	- Removed InstallEXE and InstallMSI; created and added InstallPackage to handle EXE, MSI, and MSP files within the same command.
	- Corrected syntax errors within InstallPackage function.

Version 2.8:
	- Added Windows 7 and MSOffice 2013 activation functions to repo.
	- Added ANG filter to GetSAM function to broaden it's search results and granular search abilities.

Version 2.7:
	- Added a progress bar to each feasible function.
	- Fixed bug in CrossCertRm.

Version 2.6:
	- Fixed bug in LastBoot function.
	- Modified GetSAM and HuntUser functions to accept multiple values per search.


Version 2.5: 
	- Updated SYS function to operate with jobs to allow Asynchronous/parallel commands.
	- Will add job functionality to all possible functions to save time. 
	- Fixed RmPrint function. Also, added job functionality.
	- Added job functionality to JavaCache function.
	- Added job functionality to NetMSG function.
	- Tweaked RmUserProf function.

Version 2.4: 
	- Introduced DelProf2.exe to the environment for User Profile deletion and Account Unknown cleaning abilities.
	- Wrote function including DelProf2.exe.

Version 2.3:
	- Upgraded GUI to XAML as opposed to WinForms.
	- Added CSV output functionality to reports when Export-CSV checkbox is checked.
	- Added test code for Create New User GUI. This is NOT functioning as currently intended.

Version 2.2:
	- Fixed bug in HotFix GUI button.
	- Adding checkbox to output to CSV file.

Version 2.1:
	- Tweaked several function outputs to GridView instead of writing to the shell; allows for searching, filtering, etc. of all outputs.
	- Added command completion pop-up messages for some functions.
	- Added confirmation prompt to Reboot button in GUI.
	- Added Windows Forms GUI capabilities to several functions; will continue to add.

Version 2.0:
	- Completed CreateNewUser function for automating User account creations and all helper functions.
	- Fixed Nithins Test-Path to look for the .HTA file; issue would arise if you had used SCCM function prior to Nithins.
	- Added .CSV removal from SAARConverter output folder to allow new files to pass through.
	- Tweaked UpdateProfile function to push to PowerShell and PowerShell ISE.

Version 1.9:
	- Fixed syntax error in installEXE that was causing a $Variable to be null.

Version 1.8:
	- Added specific Home Path to 'cd' command; set location to \\Server01\it\PowerShell\Scripts.

Version 1.7:
	- Moved repository to permanent location. Changed file references to reflect changes.

Version 1.6:
	- Added ability to enter only number portion of property numbers to RDP and Ghost.
		(i.e. RDP 123456 or RDP SMDCKWKPN123456; Ghost 123456 or Ghost SMDCKWKPN123456)
	- Updated Get-Help for all functions included in this repository.

Version 1.5:
	- Fixed bugs for InstallEXE and InstallMSI that were catching due to first if(!()  statement.	
	- Added custom MMC for SCCM Console.

Version 1.4:
	- Added remote GPupdate to interaction file | Commented out - processing issues.
	- Working on bug fixes for 

Version 1.3:
	- Added ADcleanup function to interaction file.
	- Added Nithins function, includes bringing down a local copy on current workstation.

Version 1.2:

	-Added Certificate removal function to list.

Version 1.1:
	- Removed InstallDate and Vendor from SWcheck function.
	- Added version notes to file updating process.
	- Changed Set-Location to my scripts folder "\\null\transfer\JBear\Scripts".
	- Bug fixes.

	- Need to fix bugs in Create in SAARNewUser section.	
#>
function UpdateProfile {
<# 
.SYNOPSIS 
    Update PowerShell profile to current repository content

.EXAMPLE 
    UpdateProfile 
#> 

    $NetworkLocation = "\\Server01\IT\PowerShell\Profile Repository\DevOps\TechProfile.txt"
    $MyDocuments = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
    $MyDocuments2 = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Profile.ps1"

    #Overwrite current $Profile for PowerShell and PowerShell ISE
    Copy-Item -Path "$NetworkLocation" -Destination "$MyDocuments" -Force
    Copy-Item -Path "$NetworkLocation" -Destination "$MyDocuments2" -Force	

    #Reload PowerShell
    Powershell
}#End UpdateProfile

$NetworkProfile = '\\Server01\IT\PowerShell\Profile Repository\DevOps\TechProfile.txt'
$WriteTimeLocal = (Get-ItemProperty $Profile).LastWriteTime
$WriteTimeNetwork = (Get-ItemProperty $NetworkProfile).LastWriteTime

if($WriteTimeLocal -lt $WriteTimeNetwork) {

    Add-Type -AssemblyName PresentationFramework | Out-Null
    $msgBoxInput = [System.Windows.MessageBox]::Show('PowerShell Profile Version Update is available. Update now?','PowerShell Profile Update','YesNo')

    switch($msgBoxInput) {

        'No' {

            Continue
        }

        'Yes' {

            UpdateProfile
        }
    }
}

#Shell Window Setup
#$Shell = $Host.UI.RawUI
#$size = $Shell.BufferSize
#$size.width=150
#$size.height=5000
#$Shell.BufferSize = $size
#$size = $Shell.WindowSize
#$Shell.WindowSize = $size
#$shell.BackgroundColor = “Black”
#$shell.ForegroundColor = “White”

#net use Q: "\\Server01\it\PowerShell"

#Set-Location "\\Server01\it\PowerShell\Scripts"

#Update-Help

#Custom menu that lists currently available functions within the shell repository
function PrintMenu {

	Write-Host(" ------------------------- ")
	Write-Host("| Bear Necessities $ProVersion |")
	Write-Host(" ------------------------- ")
	Write-Host('Type "GUI" to launch GUI interface!')
	Write-Host("")
	Write-Host("Command           Function")
	Write-Host("-------           --------")
	Write-Host("cl                Clear Shell and Reprint Command Menu")
	Write-Host("CheckProcess      Retrieve System Process Information")
	Write-Host("CreateNewUser     Create New Active Directory Users From SAAR Forms")
	Write-Host("GetSAM            Search For SAM Account Name By Name")
        Write-Host("GetSize           Retrieve size information from child items of specified path(s)")
	Write-Host("Ghost             Opens SCCM Ghost Session")
	Write-Host("GodMode           Access God Mode")
	Write-Host("GPR               Group Policy (Remote)")
	Write-Host("HuntUser          Query SCCM For Last System Logged On By Specified User")
	Write-Host("InstallPackage    Silent Install EXE, MSI, or MSP files")
	Write-Host("JavaCache         Clear Java Cache")
	Write-Host("KeePass           KeePass - System Operations Master Database")
	Write-Host("NetMSG            On-screen Message For Specified Workstation(s)")
	Write-Host("Nithins           Opens Nithin's SCCM Client Tool")
	Write-Host("PatchSearch       Retrieve machine uptime and search for specific patches")
	Write-Host("Putty             SSH Console")
	Write-Host("RDP               Remote Desktop")
	Write-Host("Reboot            Force Restart")
	Write-Host("RmUserProf        Clear User Profiles")
	Write-Host("ScanSubnet        Detect all available hosts within a given subnet")
	Write-Host("STIGViewer        STIG Viewer Console")
	Write-Host("SCCM              Active Directory/SCCM Console")	
	Write-Host("SWcheck           Check Installed Software")
	Write-Host("SYS               All Remote System Info")
	Write-Host("")
	Write-Host("")
}#End PrintMenu

Clear-Host
PrintMenu

Remove-Item Alias:cd

#Rebuild cd command
function cd {

	if($args[0] -eq '-') {

	    $PWD =$OLDPWD;
    } 
    
    else {

	    $PWD = $Args[0];
    }

	$TMP = pwd

	if($PWD) {

	    #Enter Previous Working Directory when using cd - 
	    Set-Location $pwd
    }

	Set-Variable -Name OLDPWD -Value $tmp -Scope global;
}#End CD

#Set Home Path
#(Get-PSProvider 'FileSystem').Home = "Q:\Scripts"
#Pulls latest howtogeek.com link titles from their main page	

function cl {
<# 
.SYNOPSIS 
    Used to clear current PowerShell window

.DESCRIPTION 
    Clears screen (same as clear) but, writes created 'PrintMenu' back onto the main shell for function reference

.EXAMPLE 
    cl 
#> 
	Clear-Host
	PrintMenu
}#End cl

function GodMode {
<# 
.SYNOPSIS 
    Access GodMode tools
 
.EXAMPLE 
    GodMode
#> 
	
    #GodMode path based on current $env and current user
    $GodPath = "$([Environment]::GetFolderPath("Desktop"))\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"

    if(!(Test-Path -Path $GodPath)) {

	    #Creates GodMode path for current user
	    New-Item -Type directory -Path $GodPath -Force | Out-Null
    }

    #Opens GodMode path
    Start-Process "$GodPath"
}#End GodMode

function UpdateProfile {
<# 
.SYNOPSIS 
    Update PowerShell profile to current repository content

.EXAMPLE 
    UpdateProfile 
#> 

    $NetworkLocation = "\\Server01\it\PowerShell\Profile Repository\DevOps\TechProfile.txt"

    $MyDocuments = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
    $MyDocuments2 = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Profile.ps1"

    #Overwrite current $Profile for PowerShell and PowerShell ISE
    Copy-Item -Path "$NetworkLocation" -Destination "$MyDocuments" -Force
    Copy-Item -Path "$NetworkLocation" -Destination "$MyDocuments2" -Force	

    #Reload PowerShell
    Powershell	
}#End UpdateProfile

function SCCM {
<# 
.SYNOPSIS 
    Opens pre-generated Active Directory and SCCM mmc

.EXAMPLE 
    SCCM  
#> 

    $pat1 = "\\Server01\it\PowerShell\Profile Repository\Admin Console.msc"
    $dir1 = "C:\Program Files (x86)\SCCM Tools"
    $des1 = $dir1 + "\Admin Console.msc"

    if(!(Test-Path -Path $dir1)) {

	    #Creates SCCM Console path
	    New-Item -Type directory -Path $dir1 -Force | Out-Null
	    Copy-Item $pat1 $des1 -Force
    }

    if(Test-Path -Path $dir1) {

	    Copy-Item $pat1 $des1
    }

    #Opens SCCM Admin Console
    Start-Process "$des1"
}#End SCCM

function Putty {
<# 
.SYNOPSIS 
    Opens Putty SSH console including stored connections to Brewhaus and Microbrew.

.EXAMPLE 
    Putty  
#>
 
    $pat1 = "\\Server01\it\PowerShell\PowerShellTools\Putty\putty.exe"
    $dir1 = "C:\Program Files (x86)\SCCM Tools"
    $des1 = $dir1 + "\putty.exe"
    $Args = @(

        "/s",
        "\\Server01\it\PowerShell\PowerShellTools\Putty\putty.reg"
    )

    if(!(Test-Path -Path $dir1)) {

	    #Creates SCCM Console path
	    New-Item -Type directory -Path $dir1 -Force | Out-Null
	    Copy-Item $pat1 $des1 -Force
	    Regedit $Args
    }

    if(Test-Path -Path $dir1) {

        if(!(Test-Path -Path $des1)) {

	        Copy-Item $pat1 $des1
	        Regedit $Args
        }
    }

    #Opens SSH Console
    Start-Process "$des1"
}#End Putty

function KeePass {
<# 
.SYNOPSIS 
    Opens Enterprise Services KeePass application

.EXAMPLE 
    KeePass 
#>
 
    $pat1 = "\\Server01\it\Applications\Keepass\*"
    $dir1 = "C:\Program Files (x86)\KeePass\"
    $des1 = $dir1 + "\KeePass.exe"
    $Args = @(

        'C:\Program Files (x86)\KeePass\SysOps.kdbx'
    )

    if (!(Test-Path -Path $dir1)) {

	    #Creates SCCM Console path
	    New-Item -Type directory -Path $dir1 -Force | Out-Null
	    Copy-Item $pat1 $dir1 -Recurse -Force
    }

    Copy-Item -Path "\\Server01\it\Applications\Keepass\SysOpsMaster.kdbx" -Destination "C:\Program Files (x86)\KeePass\SysOps.kdbx" -Force	

    #Opens KeePass
    & $des1 $Args
}#End KeePass

function STIGViewer {
<# 
.SYNOPSIS 
    Retrieve and open current STIGViewer.

.DESCRIPTION 
    Retrieve and open current STIGViewer.

.EXAMPLE 
    STIGViewer

.NOTES
    Author: JBear
    Date: 4/7/2018
#>

    $Pat1 = "\\Server01\it\PowerShell\PowerShellTools\STIGViewer\STIGViewer.jar"
    $Dir1 = "C:\Program Files (x86)\SCCM Tools"
    $Des1 = $Dir1 + "\STIGViewer.jar"

    if(!(Test-Path -Path $Dir1)) {

	    #Creates SCCM Console path
	    New-Item -Type directory -Path $Dir1 -Force | Out-Null
	    Copy-Item $Pat1 $Des1 -Force
    }

    if(Test-Path -Path $Dir1) {

        if(!(Test-Path -Path $Des1)) {

	        Copy-Item $Pat1 $Des1
        }
    }

    Write-Host -ForegroundColor Yellow "If STIGViewer doesn't load properly, install Java."

    #Opens STIGViewer
    Start-Process $Des1 -ErrorAction Stop
}#End STIGViewer

function GetSAM {
<# 
.SYNOPSIS
Retrieve users' account usernames based on full or partial name search. 

.Parameter NameValue
The full or partial name of the user or users.

.Parameter FilterAttribute
Specify a single attribute to query.  Default value uses Ambiguous Name Resolution (ANR) which searches up to 17 name related attributes in Active Directory.

.DESCRIPTION
The Get-MDSUserName function uses the Get-ADUser cmdlet to query Active Directory for all users 

.EXAMPLE
GetSAM Davis

.EXAMPLE
GetSAM Dav 

.EXAMPLE
GetSAM Dav -FilterAttribute Surname

.EXAMPLE
GetSAM 12345 -FilterAttribute EmployeeID
#>

Param(

    [Parameter(Mandatory=$true)] 
    [String[]]$NameValue,
    [String]$FilterAttribute='ANR'
)

$i=0
$j=0

    foreach ($User in $NameValue) {

    Write-Progress -Activity "Retrieving SAM Account Names..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $NameValue.count) * 100) + "%") -CurrentOperation "Processing $($User)..." -PercentComplete ((($j++) / $NameValue.count) * 100)


        #Get SAM Account Name for specified user
        Get-ADUser -Filter "$FilterAttribute -like '$User*'" | FT GivenName, SurName, SamAccountName, UserPrincipalName
    }	
}#End GetSAM

function HuntUser {
<# 
.SYNOPSIS 
    Retrieve workstation(s) last logged on by user (SAM Account Name)

.DESCRIPTION 
    The HuntUser function will retrieve workstation(s) by the last logged on user (SAM Account Name). 
    Accuracy will depend on the last time each workstation has communicated with SCCM.

.EXAMPLE 
    HuntUser dewittj 
#>
 
Param( 
        
    [parameter(Mandatory = $true)]
    $SamAccountName,

    #SCCM Site Name
    $SiteName="PAC",

    #SCCM Server Name
    $SCCMServer="Server7100",

    #SCCM Namespace
    $SCCMNameSpace="root\sms\site_$SiteName"
)

    function Query {

	$i=0
	$j=0

        foreach ($User in $SamAccountName) {

            Write-Progress -Activity "Retrieving Last Logged On Computers By SAM Account Name..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $SAMAccountName.count) * 100) + "%") -CurrentOperation "Processing $($User)..." -PercentComplete ((($j++) / $SAMAccountName.count) * 100)

            $ComputerName =(Get-CIMInstance -Namespace $SCCMNameSpace -Computername $SCCMServer -Query "select Name from sms_r_system where LastLogonUserName='$User'").Name

            foreach ($Computer in $ComputerName) {

                [pscustomobject] @{
            
                        SAMAccountName = "$User"  
                    "Last Computer" = "$Computer"                    
                }
            }
        }
    }

    Query

}#End HuntUser

function LoggedUser {
<# 
.SYNOPSIS 
    Retrieve current user logged into specified workstations(s) 

.EXAMPLE 
    LoggedUser Computer123456 

.EXAMPLE 
    LoggedUser 123456 
#> 
Param(

    [Parameter(Mandatory=$true)]
    [String[]] $ComputerName
)

    $i=0
    $j=0

    foreach($Computer in $ComputerName) {

        Write-Progress -Activity "Retrieving Last Logged On User..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $ComputerName.count) * 100) + "%") -CurrentOperation "Processing $($Computer)..." -PercentComplete ((($j++) / $ComputerName.count) * 100)

        $ComputerSystem = Get-CimInstance CIM_ComputerSystem -Computer $Computer
        Write-Host "User Logged In: " $ComputerSystem.UserName "`n"
    }
}#End LoggedUser

function PatchSearch {

<# 
.SYNOPSIS
    Reports uptimes of specified workstations.

.EXAMPLE
    .\Script.ps1 -Computername Server01, Server02 -KB 123456, KB4938717
    Reports uptimes for Server01, Server02

.PARAMETER Computername
    Hostname(s) of target computers.

.PARAMETER KB
    Reference KB article/patch number(s). 

.NOTES
    Author: JBear 5/19/16
    Edited: JBear 3/20/18
#>

Param (

    [Parameter(Mandatory=$true,position=0)]
    [String[]]$ComputerName,

    [Parameter(ValueFromPipeline=$true)]
    [String[]]$KB=@()
)

$LogDate = (Get-Date -format yyyyMMdd)
$OutFile = [Environment]::GetFolderPath("MyDocuments") + "\" + $LogDate + "-UpTime\KBReport.csv"

$i=0
$j=0
			
    function PatchReport {

        foreach($Computer in $ComputerName) {

            if(!([String]::IsNullOrWhiteSpace($Computer))) {

                if(Test-Connection -ComputerName $Computer -Count 1 -Quiet) {

                    Invoke-Command -ComputerName $Computer { param ($Computer, $KB)

                        $ComputerOS = Get-CimInstance CIM_OperatingSystem -Computer $Computer
                        $BootTime = $computerOS.LastBootUpTime
                        $ElapsedTime = (Get-Date) - $BootTime

                        $HotFix = @(
                                    
                            if($KB) {

                                $List = foreach($item in $KB) {
                                
                                    if($item -like "KB*") {

                                        $item
                                    }

                                    else {
                                            
                                        $item = 'KB' + $item
                                        $item
                                    }
                                }
                                        
                                Get-HotFix -Id $List -ErrorAction SilentlyContinue
                            }

                            else {
                                    
                                Get-HotFix -ErrorAction SilentlyContinue
                            }
                                
                        )

                        foreach($L in $List) {

                            if(!($hotfix.HotFixID -like "$L*")) {
                                        
                                [PSCustomObject] @{

                                    ComputerName = $Computer
                                    LastBootTime = $bootTime
                                    ElapsedTime = '{0:00} Days, {1:00} Hours, {2:00} Minutes, {3:00} Seconds' -f $elapsedTime.Days, $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds
                                    HotFix = $L
                                    HFInstallDate = 'Not Installed'
                                }
                            }

                            else {

                                [PSCustomObject] @{

                                    ComputerName = $Computer
                                    LastBootTime = $bootTime
                                    ElapsedTime = '{0:00} Days, {1:00} Hours, {2:00} Minutes, {3:00} Seconds' -f $elapsedTime.Days, $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds
                                    HotFix = $L
                                    HFInstallDate = ($HotFix | Where { $_.HotFixID -eq $L }).InstalledOn.ToString("MM/dd/yyyy")
                                }
                            }
                        }
                    } -AsJob -ArgumentList $Computer, $KB
                }

                else {

                    Start-Job { param ($Computer)

                        [PSCustomObject] @{

                            ComputerName = $Computer
                            LastBootTime = 'Ping failed'
                            ElapsedTime = 'N/A'
                            HotFix='N/A'
                            HFInstallDate=$null
                        }
                    } -Name "PING Failed" -ArgumentList $Computer
                }
            }
        }

        $Jobs = Get-Job | Where { $_.State -eq "Running" }
        $Total = $Jobs.Count
        $Running = $Jobs.Count

        While($Running -gt 0){

            Write-Progress -Activity "Retrieving HotFix results (Awaiting Results: $(($Running)))..." -Status ("Percent Complete:" + "{0:N0}" -f ((($Total - $Running) / $Total) * 100) + "%") -PercentComplete ((($Total - $Running) / $Total) * 100) -ErrorAction SilentlyContinue

            $Running = (Get-Job | Where { $_.State -eq "Running" }).Count
        }
    } 

    PatchReport | Receive-Job -Wait -AutoRemoveJob | Sort ComputerName | Select ComputerName, HotFix, HFInstallDate, LastBootTime, ElapsedTime  | Out-GridView -Title "KB Information"
    
}#End PatchSearch

function ScanSubnet {
<#
.SYNOPSIS
    Detect all available hosts within a given subnet.

.DESCRIPTION
    Detect all available hosts within a given subnet.

.PARAMETER SubnetIP
    IP within desired subnet or, first three octets (i.e. 192.168.0, 192.168.0.122).

.PARAMETER IPRangeStart
    Starting IP address.
    Default 0.

.PARAMETER IPRangeEnd
    Ending IP address.
    Default 255.

.NOTES
    Author: JBear
    Date: 10/29/2017
#>

param(

    [Parameter(Mandatory=$true,HelpMessage="Enter an IP within desired subnet or, first three octets (i.e. 192.168.0, 192.168.0.122)")]
    [ValidateNotNullOrEmpty()] 
    [String[]]$SubnetIP,

    [Parameter(ValueFromPipeline=$true,HelpMessage="Enter starting IP range (fourth octet)")]
    [ValidateRange(0,255)] 
    [Int]$IPRangeStart = "0",

    [Parameter(ValueFromPipeline=$true,HelpMessage="Enter ending IP range (fourth octet)")]
    [ValidateRange(0,255)] 
    [Int]$IPRangeEnd = "255"
)

    function Scan-IPRange {

        foreach($Sub in $SubnetIP) {

            [String[]]$SplitIP = $Sub.Split(".")
            [String]$OctetOne = $SplitIP[0]
            [String]$OctetTwo = $SplitIP[1]
            [String]$OctetThree = $SplitIP[2]
            [String]$Subnet = "$OctetOne.$OctetTwo.$OctetThree"
            $Range = $IPRangeStart..$IPRangeEnd 

            Start-Job { param($Subnet, $Range)

                foreach($R in $Range) {

                    $IP = "$Subnet.$R"
                    $DNS = @(

                        Try {
             
                            [Net.Dns]::GetHostEntry($IP) 
                        }

                        Catch {
            
                            $null
                        }
                    )

                    if($DNS) {

                        $Hostname = @(
         
                            if($DNS.HostName) {
                
                                $DNS.HostName
                            }
                                          
                            elseif(!($DNS.HostName)) {
                
                                $IP
                            }             
                        )          

                        [PSCustomObject] @{
                    
                            IP="$IP"
                            Hostname="$Hostname".Split(".")[0]
                            FQDN="$Hostname"
                        }         
                    }          
                }
            } -ArgumentList $Subnet, $Range
        }

        $Jobs = Get-Job | Where { $_.State -eq "Running"}
        $Total = $Jobs.Count
        $Running = $Jobs.Count

        While($Running -gt 0) {
    
            Write-Progress -Activity "Scanning IP Ranges (Awaiting Results: $(($Running)))..." -Status ("Percent Complete:" + "{0:N0}" -f ((($Total - $Running) / $Total) * 100) + "%") -PercentComplete ((($Total - $Running) / $Total) * 100) -ErrorAction SilentlyContinue

            $Running = (Get-Job | Where { $_.State -eq "Running"}).Count
        }

    }

    #Call function 
    Scan-IPRange | Receive-Job -Wait -AutoRemoveJob | Select IP, Hostname, FQDN  
}#End ScanSubnet
#Imports AD/SCCM console; Active Directory module needed
Import-Module ActiveDirectory

#Reboots specified workstation(s)
function Reboot {
<# 
.SYNOPSIS 
    Restarts specified workstation(s) 

.EXAMPLE 
    Reboot SMDCKWKPN123456 

.EXAMPLE
    Reboot (Get-Content C:\SomeDirectory\WhateverTextFileYouWant.txt)
#> 

param(

    [Parameter(Mandatory=$true)]
    [String[]] $ComputerName
)

    function RebootSystems {

        foreach ($Computer in $ComputerName) {

	        #Force reboot on specified workstation or array
	        Restart-Computer $Computer -Force -AsJob | Out-Null
	    }

        $Jobs = Get-Job | Where { $_.State -eq "Running" }
        $Total = $Jobs.Count
        $Running = $Jobs.Count

        While($Running -gt 0){

            Write-Progress -Activity "Rebooting remote computer (Awaiting Results: $(($Running)))..." -Status ("Percent Complete:" + "{0:N0}" -f ((($Total - $Running) / $Total) * 100) + "%") -PercentComplete ((($Total - $Running) / $Total) * 100) -ErrorAction SilentlyContinue

            $Running = (Get-Job | Where { $_.State -eq "Running" }).Count
        }
    }

    RebootSystems | Receive-Job -Wait -AutoRemoveJob

}#End Reboot

 
#ActiveDirectory module needed
function Ghost {
<# 
.SYNOPSIS 
    Opens Ghost session to specified workstation(s) 

.EXAMPLE 
    Ghost SMDCKWKPN123456 

#> 
param(

    [Parameter(Mandatory=$true)]
    [String]$ComputerName
)

    #Start 'Ghost' or interactive Remote Tools session with specified workstation 
    Start-Process 'C:\Program Files (x86)\Microsoft Configuration Manager Console\AdminUI\bin\i386\rc.exe' "1 $Computername"   

}#End Ghost

 
function RDP {
<# 
.SYNOPSIS 
    Remote Desktop Protocol to specified workstation(s) 

.EXAMPLE 
    RDP SMDCKWKPN123456  
#> 
param(
    
    [Parameter(Mandatory=$true)]
    [String]$ComputerName
)

	#Start Remote Desktop Protocol on specifed workstation
	& "C:\windows\system32\mstsc.exe" /v:$ComputerName /fullscreen
}#End RDP

function GPR {
<# 
.SYNOPSIS 
    Open Group Policy for specified workstation(s) 

.EXAMPLE 
    GPR SMDCKWKPN123456  
#> 

param(

    [Parameter(Mandatory=$true)]
    [String[]]$ComputerName
)

$i=0
$j=0

    foreach ($Computer in $ComputerName) {

        Write-Progress -Activity "Opening Remote Group Policy..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $ComputerName.count) * 100) + "%") -CurrentOperation "Processing $($computer)..." -PercentComplete ((($j++) / $ComputerName.count) * 100)
	    gpedit.msc /gpcomputer: $Computer
	}
}#End GPR

function Enable {
<# 
.SYNOPSIS 
    Enable User Account in AD; Requires proper permissions. Search by partial or full last name, manually enter SAM Account Name.
  
.EXAMPLE 
    Enable dewittj, smithw
#> 
param(

    [Parameter(Mandatory=$true)]
    [String[]] $SamAccountName
)

    foreach($SAM in $SamAccountName) {
        
	    Enable-ADAccount –Identity $SAM
    }
}#End Enable

function SYS {
<# 
.SYNOPSIS 
    Retrieve basic system information for specified workstation(s) 

.EXAMPLE 
    SYS Computer123456 

#> 
param(

    [Parameter(Mandatory=$true)]
    [String[]] $ComputerName
)

$Stamp = (Get-Date -Format G) + ":"

$i=0
$j=0

    function Systeminformation {
	
        foreach ($Computer in $ComputerName) {

            if(!([String]::IsNullOrWhiteSpace($Computer))) {

                If (Test-Connection -Quiet -Count 1 -Computer $Computer) {

                    $Location = (Get-ADComputer -Identity $Computer -Property Description).Description

	            Invoke-Command -Computername $Computer -ScriptBlock { param($Computer, $Location) 

                        #Gather specified workstation information; CimInstance only works on 64-bit
                        $computerSystem = Get-CimInstance CIM_ComputerSystem
                        $computerBIOS = Get-CimInstance CIM_BIOSElement -Computer $Computer
                        $computerOS = Get-CimInstance CIM_OperatingSystem -Computer $Computer
                        $computerCPU = Get-CimInstance CIM_Processor -Computer $Computer
                        $computerHDD = Get-CimInstance Win32_LogicalDisk -Computer $Computer -Filter "DeviceID = 'C:'"
                        $BootTime = $computerOS.LastBootUpTime
                        $ElapsedTime = (Get-Date) - $BootTime
    
                        [PSCustomObject]@{

                            ComputerName = $computerSystem.Name
                            LastReboot = $BootTime
                            ElapsedTime = '{0:00} Days, {1:00} Hours, {2:00} Minutes, {3:00} Seconds' -f $ElapsedTime.Days, $ElapsedTime.Hours, $ElapsedTime.Minutes, $ElapsedTime.Seconds
                            OperatingSystem = $computerOS.OSArchitecture + " " + $computerOS.caption
                            Model = $computerSystem.Model
                            RAM = "{0:N2}" -f [int]($computerSystem.TotalPhysicalMemory/1GB) + "GB"
                            DiskCapacity = "{0:N2}" -f ($computerHDD.Size/1GB) + "GB"
                            TotalDiskSpace = "{0:P2}" -f ($computerHDD.FreeSpace/$computerHDD.Size) + " Free (" + "{0:N2}" -f ($computerHDD.FreeSpace/1GB) + "GB)"
                            CurrentUser = $computerSystem.UserName
                            Location = $Location
                        }
                    } -Asjob -ArgumentList $Computer, $Location
                }

                else {

                    Start-Job -ScriptBlock { param($Computer, $Location)  

                        [PSCustomObject]@{

                            ComputerName=$Computer
                            LastReboot="Unable to PING."
                            ElapsedTime="Unable to PING."
                            OperatingSystem="Unable to PING."
                            Model="Unable to PING."
                            RAM="Unable to PING."
                            DiskCapacity="Unable to PING."
                            TotalDiskSpace="Unable to PING."
                            CurrentUser="Unable to PING."
                            Location = $Location
                        }
                    } -ArgumentList $Computer, $Location                     
                }
            }

            else {
                 
                Start-Job -ScriptBlock { param($Computer, $Location)  

                    [PSCustomObject]@{

                        ComputerName="VALUE IS NULL."
                        LastReboot="N/A"
                        ElapsedTime="N/A"
                        OperatingSystem="N/A"
                        Model="N/A"
                        RAM="$Null"
                        DiskCapacity="N/A"
                        TotalDiskSpace="N/A"
                        CurrentUser="N/A"
                        Location = $Location
                    }
                } -ArgumentList $Computer, $Location
            }
        }

        $Jobs = Get-Job | Where { $_.State -eq "Running" }
        $Total = $Jobs.Count
        $Running = $Jobs.Count

        While($Running -gt 0) {

            Write-Progress -Activity "Gathering System Information (Awaiting Results: $(($Running)))..." -Status ("Percent Complete:" + "{0:N0}" -f ((($Total - $Running) / $Total) * 100) + "%") -PercentComplete ((($Total - $Running) / $Total) * 100) -ErrorAction SilentlyContinue

            $Running = (Get-Job | Where { $_.State -eq "Running" }).Count
        }  
    }

    $SystemInformation = SystemInformation | Receive-Job -Wait -AutoRemoveJob | Select ComputerName, Location, CurrentUser, OperatingSystem, Model, RAM, DiskCapacity, TotalDiskSpace, LastReboot, ElapsedTime
    $DocPath = [Environment]::GetFolderPath("MyDocuments") + "\SystemInformation-Report.csv"

    Switch ($CheckBox.IsChecked){

	    $true { 

            $SystemInformation | Export-Csv $DocPath -NoTypeInformation -Force
        }

	    default { 

            $SystemInformation | Out-GridView -Title "System Information" 
        }	
    }

    if ($CheckBox.IsChecked -eq $true) {

	    Try { 

		    $listBox.Items.Add("$stamp Export-CSV to $DocPath!`n")
	    } 

	    Catch {

		    #Do Nothing 
	    }
    }
	
    else {

	    Try {

	        $listBox.Items.Add("$stamp System Information output processed!`n")
	    } 

	    Catch {

	        #Do Nothing 
	    }
    }
}#End SYS

function RmPrint {
<# 
.SYNOPSIS 
    Remove printer drivers from registry of specified workstation(s) 

.EXAMPLE 
    RmPrint SMDCKWKPN123456  
#> 
param(

    [Parameter(Mandatory=$true)]
    [String[]]$computername
)

    function RemovePrintDrivers {
 	
        foreach ($Computer in $ComputerName) { 

            Write-Progress -Activity "Clearing printer drivers..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $ComputerName.count) * 100) + "%") -CurrentOperation "Processing $($computer)..." -PercentComplete ((($j++) / $ComputerName.count) * 100)

	        Try {

		        $RemoteSession = New-PSSession -ComputerName $Computer
            }

	        Catch {

		        "Something went wrong. Unable to connect to $Computer"
		        Break
            }

	        Invoke-Command -Session $RemoteSession -ScriptBlock {

                #Removes print drivers, other than default image drivers
		        if ((Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\') -eq $true) {

			        Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3\*' -EXCLUDE "*ADOBE*", "*MICROSOFT*", "*XPS*", "*REMOTE*", "*FAX*", "*ONENOTE*" -recurse
			        Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers\*' -EXCLUDE "*ADOBE*", "*MICROSOFT*", "*XPS*", "*REMOTE*", "*FAX*", "*ONENOTE*" -recurse

		            Set-Service Spooler -StartupType manual
		            Restart-Service Spooler
		            Set-Service Spooler -StartupType automatic
			    }
		    } -AsJob -JobName "ClearPrintDrivers"
	    } 
    } 
    
    RemovePrintDrivers | Wait-Job | Remove-Job

    Remove-PSSession *
}#End RmPrint

#Removes botched Office 2013 installations due to Programs and Features removal not working
#This function is commented out; due to specifics of function, keeping code for future reference
<#function rmOffice {
$ErrorActionPreference= 'silentlycontinue'
$Workstation = (Read-Host -Prompt "Enter Workstation")

Try {
    $RemoteSession = New-PSSession -ComputerName $Workstation
}
Catch {
    "Something went wrong. Unable to connect to $Workstation"
    Break
}
Invoke-Command -Session $RemoteSession -ScriptBlock {

	New-PSDrive -PSProvider registry -root HKEY_CLASSES_ROOT -Name HKCR
	write-host ""
	write-host "Removing Microsoft Office 2013 registry and file components... Please Wait..."
	New-PSDrive -PSProvider registry -root HKEY_CURRENT_USER -Name HKCU | Out-Null
	remove-item -Path 'C:\Program Files (x86)\Common Files\microsoft shared\OFFICE15' -Force -recurse | Out-Null
	remove-item -Path 'C:\Program Files (x86)\Common Files\microsoft shared\Source Engine' -Force -recurse | Out-Null
	remove-item -Path 'C:\Program Files (x86)\Microsoft Office\Office15' -Force -recurse | Out-Null
	remove-item -Path 'C:\MSOCache\All Users\*0FF1CE}*' -Force -recurse | Out-Null
	remove-item -Path '*\AppData\Roaming\Microsoft\Templates\*.dotm' -Force -recurse | Out-Null
	remove-item -Path '*\AppData\Roaming\Microsoft\Templates\*.dotx' -Force -recurse | Out-Null
	remove-item -Path '*\AppData\microsoft\document building blocks\*.dotx' -Force -recurse | Out-Null
	remove-item -Path 'HKCU:\Software\Microsoft\Office\15.0' -recurse | Out-Null
	remove-item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\15.0' -recurse | Out-Null
	remove-item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\Delivery\SourceEngine\Downloads\*0FF1CE}-*' -recurse | Out-Null
	remove-item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*0FF1CE*' -recurse | Out-Null
	remove-item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\ose' -recurse | Out-Null
	remove-item -Path 'HKCR:\Installer\Features\*F01FEC' -recurse | Out-Null
	remove-item -Path 'HKCR:\Installer\Products\*F01FEC' -recurse | Out-Null
	remove-item -Path 'HKCR:\Installer\UpgradeCodes\*F01FEC' -recurse | Out-Null
	remove-item -Path 'HKCR:\Installer\Win32Asemblies\*Office15*' -recurse | Out-Null
	Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*Office15*' -recurse | Out-Null
	write-host ""
	write-host "Object removal complete..."}
Remove-PSSession *
}#>#End RmOffice


function NetMSG {
<# 
.SYNOPSIS 
    Generate a pop-up window on specified workstation(s) with desired message 

.EXAMPLE 
    NetMSG Computer123456 
#> 

param(

    [Parameter(Mandatory=$true)]
    [String[]]$ComputerName
)

	$ReadMe = Read-Host -prompt("Enter desired message")
	$User = [Environment]::UserName
	$UserInfo = Get-ADUser $User -Property Title | Select Title
	$UserJob = $UserInfo.Title

    Function SendMessage {
 	
        foreach($Computer in $ComputerName) {

            $g = "$ReadMe"
            $CallBack = "$User | 5-2444 | $UserJob"

            #Invoke local MSG command on specified workstation - will generate pop-up message for any user logged onto that workstation - *Also shows on Login screen, stays there for 100,000 seconds or until interacted with
            Invoke-Command -computername $Computer {

	        param($g, $CallBack, $User, $UserInfo, $UserJob)
 
                msg /time:100000 * /v "$g {$CallBack}"
            } -ArgumentList $g, $CallBack, $User, $UserInfo, $UserJob -AsJob
        }

        $Jobs = Get-Job | Where { $_.State -eq "Running" }
        $Total = $Jobs.Count
        $Running = $Jobs.Count

        While($Running -gt 0){

            Write-Progress -Activity "Sending Messages (Awaiting Results: $(($Running)))..." -Status ("Percent Complete:" + "{0:N0}" -f ((($Total - $Running) / $Total) * 100) + "%") -PercentComplete ((($Total - $Running) / $Total) * 100) -ErrorAction SilentlyContinue

            $Running = (Get-Job | Where { $_.State -eq "Running" }).Count
        }
    }

SendMessage | Receive-Job -Wait -AutoRemoveJob

}#End NetMSG

function SWcheck {
<# 
.SYNOPSIS 
    Grabs all installed Software on specified workstation(s) 

.EXAMPLE 
    SWcheck Computer123456 
#> 
param(

    [Parameter(Mandatory=$true)]
    [String[]]$ComputerName,
    [String]$NameRegex = ''
)

$Stamp = (Get-Date -Format G) + ":"

    function SoftwareCheck {

        foreach ($Computer in $ComputerName) {

            if(!([String]::IsNullOrWhiteSpace($Computer))) {

                if(Test-Connection -Quiet -Count 1 -Computer $Computer) {

                    Start-Job -ScriptBlock { param($Computer,$NameRegex)    

                        $Keys = '','\Wow6432Node'

                        foreach ($Key in $keys) {

                            try {

                                $Apps = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$Computer).OpenSubKey("SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
                            } 
            
                            catch {

                                Continue
                            }

                            foreach ($App in $Apps) {

                                $Program = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$Computer).OpenSubKey("SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall\$app")
                                $Name = $Program.GetValue('DisplayName')

                                if ($Name -and $Name -match $NameRegex) {

                                    [pscustomobject]@{

                                        "Computer Name" = $Computer
                                        Software = $Name
                                        Version = $Program.GetValue('DisplayVersion')
                                        Publisher = $Program.GetValue('Publisher')
                                        "Install Date" = $Program.GetValue('InstallDate')
                                        "Uninstall String" = $Program.GetValue('UninstallString')
                                        Bits = $(if ($Key -eq '\Wow6432Node') {'64'} else {'32'})
                                        Path = $Program.name
                                    }
                                }
                            }
                        }
                    } -Name "Software Check" -ArgumentList $Computer, $NameRegex 
                }

                else {

                    Start-Job -ScriptBlock { param($Computer)  
                     
                        [pscustomobject]@{

                            "Computer Name" = $Computer
                            Software = "Unable to PING"
                            Version = "N/A"
                            Publisher = "N/A"
                            "Install Date" = "N/A"
                            "Uninstall String" = "N/A"
                            Bits = "N/A"
                            Path = "N/A"
                        }
                    } -ArgumentList $Computer                       
                }
            }

            else {
                 
                Start-Job -ScriptBlock { param($Computer)  
                     
                    [pscustomobject]@{

                        "Computer Name" = "NULL"
                        Software = "NULL"
                        Version = "NULL"
                        Publisher = "NULL"
                        "Install Date" = "NULL"
                        "Uninstall String" = "NULL"
                        Bits = "NULL"
                        Path = "NULL"
                    }
                } -ArgumentList $Computer
            }
        }

        $Jobs = Get-Job | Where { $_.State -eq "Running" }
        $Total = $Jobs.Count
        $Running = $Jobs.Count

        While($Running -gt 0){

            Write-Progress -Activity "Gathering Installed Software (Awaiting Results: $(($Running)))..." -Status ("Percent Complete:" + "{0:N0}" -f ((($Total - $Running) / $Total) * 100) + "%") -PercentComplete ((($Total - $Running) / $Total) * 100) -ErrorAction SilentlyContinue

            $Running = (Get-Job | Where { $_.State -eq "Running" }).Count
        }
    }	

    $SoftwareCheck = SoftwareCheck | Receive-Job -Wait -AutoRemoveJob | Select "Computer Name", Software, Version, Publisher, "Install Date", "Uninstall String", Bits, Path
    $DocPath = [Environment]::GetFolderPath("MyDocuments") + "\Software-Report.csv"

    Switch ($CheckBox.IsChecked){

    	$true { $SoftwareCheck | Export-Csv $DocPath -NoTypeInformation -Force; }
    	default { $SoftwareCheck | Out-GridView -Title "Software"; }
	}
		
	if ($CheckBox.IsChecked -eq $true) {

	    Try { 

    		$listBox.Items.Add("$stamp Export-CSV to $DocPath!`n")
	    } 

	    Catch {

    		 #Do Nothing 
	    }
	}
	
	else {

	    Try {

	        $listBox.Items.Add("$stamp Software output processed!`n")
	    } 

	    Catch {

	        #Do Nothing 
	    }
	}
}#End SWcheck


function JavaCache {
<# 
.SYNOPSIS 
    Clear Java cache on specified workstation(s) 

.EXAMPLE 
    JavaCache Computer123456 
#> 
[cmdletbinding()]
Param ( #Define a Mandatory name input
[Parameter(
ValueFromPipeline=$true,
ValueFromPipelinebyPropertyName=$true, 
Position=0)]
[Alias('Computer', 'ComputerName', 'Server', '__ServerName')]
	[String[]]$name = $ENV:Computername,
[Parameter(Position=1)]
	[String]$progress = "Yes"
)

    function ClearJava {

    $i=0
    $j=0

        ForEach ($computer in $name){

            Write-Progress -Activity "Clearing Java Cache..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $Name.count) * 100) + "%") -CurrentOperation "Processing $($computer)..." -PercentComplete ((($j++) / $Name.count) * 100)


            Try {

	            $RemoteSession = New-PSSession -ComputerName $computer

	            Invoke-Command -Session $RemoteSession -ScriptBlock {&"javaws" '-uninstall'} -AsJob 
	            Remove-PSSession *
            }

            Catch {

	            "Something went wrong. Can't connect to $computer. Sorry!"

	            Remove-PSSession *
	            Break
		    } 
        }

        $Jobs = Get-Job | Where { $_.State -eq "Running" }
        $Total = $Jobs.Count
        $Running = $Jobs.Count

        While($Running -gt 0){

            Write-Progress -Activity "Clearing Java Cache (Awaiting Results: $(($Running)))..." -Status ("Percent Complete:" + "{0:N0}" -f ((($Total - $Running) / $Total) * 100) + "%") -PercentComplete ((($Total - $Running) / $Total) * 100) -ErrorAction SilentlyContinue

            $Running = (Get-Job | Where { $_.State -eq "Running" }).Count
        }
    }

    ClearJava | Wait-Job | Remove-Job
}#End JavaCache



function ADcleanup {
<# 
.SYNOPSIS 
    Removes workstation(s) from Active Directory and SCCM 

.EXAMPLE 
    ADcleanup Computer123456 
#> 
Param(

    [Parameter(Mandatory = $true)] 
    [String[]]$ComputerName,

    #SCCM Site Name
    $SiteName="PAC",

    #SCCM Server Name
    $SCCMServer="SMDCKV7100"
)

#SCCM Namespace
$SCCMNameSpace="root\sms\site_$SiteName"

    foreach ($Computer in $computerName) {
	
	    #Find and delete specified workstation(s) from Active Directory
	    $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
	    $root = $dom.GetDirectoryEntry()
	    $search = [System.DirectoryServices.DirectorySearcher]$root
	    $search.filter = "(&(objectclass=computer)(name=$Computer))"
	    $search.findall() | %{$_.GetDirectoryEntry() } | %{$_.DeleteObject(0)}

	    #Find and delete specified workstation(s) from SCCM
	    $comp = Get-WmiObject -query "select * from sms_r_system where Name='$Computer'" -computer $SCCMServer -namespace $SCCMNameSpace
	    $comp.psbase.delete()
    }
}#End ADcleanup


function Nithins {  
<# 
.SYNOPSIS 
    Opens Nithin's SCCM Tools

.EXAMPLE 
    Nithins 
#> 
	$pat1 = "\\Server01\it\PowerShell\Profile Repository\ClientActionsTool.hta"
	$dir1 = "C:\Program Files (x86)\SCCM Tools"
	$des1 = $dir1 + "\ClientActionsTool.hta"

    if (!(Test-Path -Path $des1)) {

	    #Creates Nithin's path
	    New-Item -Type directory -Path $dir1 -Force | Out-Null
	    Copy-Item $pat1 $des1 -Force
    }
    	
	#Opens Nithin's Client
	Start-Process "$des1"
}#End Nithins

function CheckProcess {
<# 
.SYNOPSIS 
    Grabs all processes on specified workstation(s).

.EXAMPLE 
    CheckProcess Computer123456 
#> 
param (

    [Parameter(ValueFromPipeline=$true)]
    [String[]]$ComputerName = $env:COMPUTERNAME,
    [String]$NameRegex = ''
)

$Stamp = (Get-Date -Format G) + ":"

    function ChkProcess {

    $i=0
    $j=0

        foreach ($computer in $ComputerArray) {

            $getProcess = Get-Process -ComputerName $computer

            foreach ($Process in $getProcess) {
                
                 [PSCustomObject] @{

		            "Computer Name" = $computer
                    "Process Name" = $Process.ProcessName
                    PID = '{0:f0}' -f $Process.ID
                    Company = $Process.Company
                    "CPU(s)" = $Process.CPU
                    Description = $Process.Description
                 }           
             }
         }

        $Jobs = Get-Job | Where { $_.State -eq "Running" }
        $Total = $Jobs.Count
        $Running = $Jobs.Count

        While($Running -gt 0) {

            Write-Progress -Activity "Retrieving System Processes (Awaiting Results: $(($Running)))..." -Status ("Percent Complete:" + "{0:N0}" -f ((($Total - $Running) / $Total) * 100) + "%") -PercentComplete ((($Total - $Running) / $Total) * 100) -ErrorAction SilentlyContinue

            $Running = (Get-Job | Where { $_.State -eq "Running" }).Count
        } 
    }
	
    foreach ($computer in $ComputerName) {	
     
        If (Test-Connection -quiet -count 1 -Computer $Computer) {
		    
            $ComputerArray += $Computer
        }	
    }

	$chkProcess = ChkProcess | Sort "Computer Name" | Select "Computer Name","Process Name", PID, Company, "CPU(s)", Description
    $DocPath = [Environment]::GetFolderPath("MyDocuments") + "\Process-Report.csv"

    Switch ($CheckBox.IsChecked) {
    	$true { $chkProcess | Export-Csv $DocPath -NoTypeInformation -Force; }
    	default { $chkProcess | Out-GridView -Title "Processes";  }
    }

	if($CheckBox.IsChecked -eq $true) {
	    
        Try { 

		    $listBox.Items.Add("$stamp Export-CSV to $DocPath!`n")
	    } 

	    Catch {

		    #Do Nothing 
	    }
	}
	
	else {

	    Try {

	        $listBox.Items.Add("$stamp Check Process output processed!`n")
	    }
 
	    Catch {

	        #Do Nothing 
	    }
	}
    
}#End CheckProcess


function FindHotFixes {
  <# 
  .SYNOPSIS 
  Grabs all processes on specified workstation(s).

  .EXAMPLE 
  FindHotFixes Computer123456 

  .EXAMPLE 
  FindHotFixes 123456 
  #> 
param (

    [Parameter(ValueFromPipeline=$true)]
    [String[]]$ComputerName = $env:COMPUTERNAME,
    [String]$NameRegex = ''
)


$Stamp = (Get-Date -Format G) + ":"

    function HotFix {

        foreach ($Computer in $ComputerArray) {

            Get-HotFix -Computername $Computer 
        }
    
        $Jobs = Get-Job | Where { $_.State -eq "Running" }
        $Total = $Jobs.Count
        $Running = $Jobs.Count

        While($Running -gt 0){

            Write-Progress -Activity "Retrieving HotFix Information (Awaiting Results: $(($Running)))..." -Status ("Percent Complete:" + "{0:N0}" -f ((($Total - $Running) / $Total) * 100) + "%") -PercentComplete ((($Total - $Running) / $Total) * 100) -ErrorAction SilentlyContinue

            $Running = (Get-Job | Where { $_.State -eq "Running" }).Count
        }    
    }

    foreach ($Computer in $ComputerName) {
	     
        If(Test-Connection -quiet -count 1 -Computer $Computer) {
		    
            $ComputerArray += $Computer
        }	
    }

    $HotFix = HotFix
    $DocPath = [Environment]::GetFolderPath("MyDocuments") + "\HotFix-Report.csv"

    Switch($CheckBox.IsChecked) {

    	$true { $HotFix | Export-Csv $DocPath -NoTypeInformation -Force; }
    	default { $HotFix | Out-GridView -Title "HotFix Report"; }
    }

	if($CheckBox.IsChecked -eq $true) {

	    Try { 

		    $listBox.Items.Add("$stamp Export-CSV to $DocPath!`n")
	    } 

	    Catch {

		    #Do Nothing 
	    }
	}
	
	else {

	    Try {

	        $listBox.Items.Add("$stamp HotFixes output processed!`n")
	    } 

	    Catch {

	        #Do Nothing 
	    }
	}
}#End FindHotFixes


function RmUserProf {

<#
.SYNOPSIS
    Written by: JBear 1/31/2017
	
    Remove user profiles from a specified system.

.DESCRIPTION
    Remove user profiles from a specified system with the use of DelProf2.exe.

.EXAMPLE
    RmUserProf Computer123456

        Note: Follow instructions and prompts to completetion.

#>

param(

    [Parameter(mandatory=$true)]
    [String[]]$Computername
)

    function UseDelProf2 { 
               
        #Set parameters for remote computer and -WhatIf (/l)
        $WhatIf = @(

            "/l",
            "/c:$computer" 
        )
           
        #Runs DelProf2.exe with the /l parameter (or -WhatIf) to list potential User Profiles tagged for potential deletion
        & "\\Server01\it\PowerShell\PowerShellTools\Delprof2 1.6.0\DelProf2.exe" $WhatIf

        #Display instructions on console
        Write-Host "`n`nPLEASE ENSURE YOU FULLY UNDERSTAND THIS COMMAND BEFORE USE `nTHIS WILL DELETE ALL USER PROFILE INFORMATION FOR SPECIFIED USER(S) ON THE SPECIFIED WORKSTATION!`n"

        #Prompt User for input
        $DeleteUsers = Read-Host -Prompt "To delete User Profiles, please use the following syntax ; Wildcards (*) are accepted. `nExample: /id:user1 /id:smith* /id:*john*`n `nEnter proper syntax to remove specific users" 

        #If only whitespace or a $null entry is entered, command is not run
        if([String]::IsNullOrWhiteSpace($DeleteUsers)) {

            Write-Host "`nImproper value entered, excluding all users from deletion. You will need to re-run the command on $computer, if you wish to try again...`n"
        }

        #If Read-Host contains proper syntax (Starts with /id:) run command to delete specified user; DelProf will give a confirmation prompt
        elseif($DeleteUsers -like "/id:*") {

            #Set parameters for remote computer
            $UserArgs = @(

                "/c:$computer"
            )

            #Split $DeleteUsers entries and add to $UserArgs array
            $UserArgs += $DeleteUsers.Split("")

            #Runs DelProf2.exe with $UserArgs parameters (i.e. & "C:\DelProf2.exe" /c:Computer1 /id:User1* /id:User7)
            & "\\Server01\it\PowerShell\PowerShellTools\Delprof2 1.6.0\DelProf2.exe" $UserArgs
        }

        #If Read-Host doesn't begin with the input /id:, command is not run
        else {

            Write-Host "`nImproper value entered, excluding all users from deletion. You will need to re-run the command on $computer, if you wish to try again...`n"
        }
    }

    foreach($Computer in $ComputerName) {

        if(Test-Connection -Quiet -Count 1 -Computer $Computer) { 

            UseDelProf2 
        }

        else {
            
            Write-Host "`nUnable to connect to $Computer. Please try again..." -ForegroundColor Red
        }

    }
}#End RmUserProf

function GetSize {
<#
.SYNOPSIS
    Retrieve size information from child items of specified path(s).

.DESCRIPTION
    Retrieve size information from child items of specified path(s).

.Parameter Directory
    "C:\Test\Directory"

.NOTES
    Author: JBear 6/1/2018
#>

    param(

        [Parameter(ValueFromPipeline=$true)]
        [String[]]$Directory = $null,

        [Parameter(ValueFroMPipeline=$true)]
        [String[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter(DontShow)]
        [String]$JobThrottleCount = 10
    )

    if($Directory -eq $null) {

        Add-Type -AssemblyName System.Windows.Forms

        $Dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $Result = $Dialog.ShowDialog((New-Object System.Windows.Forms.Form -Property @{ TopMost = $true }))

        if($Result -eq 'OK') {

            Try {
      
                $Directory = $Dialog.SelectedPath
            }

            Catch {

                $Directory = $null
	            Break
            }
        }

        else {

            #Shows upon cancellation of Save Menu
            Write-Host -ForegroundColor Yellow "Notice: No file(s) selected."
            Break
        }
    }

    function MeasureSize {

        foreach($Computer in $ComputerName) {

            $i=0
            $j=0

            foreach($Dir in $Directory) {

                    $DirMod = "\\$Computer\$(($Dir).Replace(':','$'))"

                    #Retrieve object 'name' from each $Computer path
                    $Names = Get-ChildItem -LiteralPath $DirMod -Directory | Select-Object Name

                ForEach($Name in $Names) {

                    While(@(Get-Job -State Running).Count -ge $JobThrottleCount) {
        
                        Start-Sleep 1
                    }

                    Write-Progress -Activity "Begin Measuring Processes..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $Names.count) * 100) + "%") -CurrentOperation "Processing $((Split-Path -Path $Name.Name -Leaf))..." -PercentComplete ((($j++) / $Names.count) * 100)

                    Start-Job {

	                    $Drive = "$using:DirMod\" + $using:Name.Name

                        #Measure file lengths (bytes) for each $ServerShare recursively to retrieve full directory size
	                    $DirSize = (Get-ChildItem $Drive -Recurse -ErrorAction "SilentlyContinue" -Force | Where {-NOT $_.PSIscontainer}  | Measure-Object -Property Length -Sum)

                        [PSCustomObject] @{

                            Drive = $Drive
                            MB = "{0:N2}" -f $($DirSize.Sum/1MB) + " MB"
                            GB = "{0:N2}" -f $($DirSize.Sum/1GB) + " GB"
                        }     
                    } -Name 'Measure Directory'
                }
                
                $Jobs = Get-Job | Where { $_.State -eq "Running" }
                $Total = $Jobs.Count
                $Running = $Jobs.Count

                While($Running -gt 0) {

                    Write-Progress -Activity "Retrieving Metrics Data... (Awaiting Results: $(($Running)))..." -Status ("Percent Complete:" + "{0:N0}" -f ((($Total - $Running) / $Total) * 100) + "%") -PercentComplete ((($Total - $Running) / $Total) * 100) -ErrorAction SilentlyContinue

                    $Running = (Get-Job | Where { $_.State -eq "Running" }).Count
                }  
            }
        }
    }

    #Call main function
    MeasureSize | Receive-Job -Wait -AutoRemoveJob | Select Drive, MB, GB
}#End GetSize

function ResetIDSM {

<#
.SYNOPSIS
    Reset PDU(s) for Instrusion Detection System. Requires local administrator rights on IDSM server(s).

.DESCRIPTION
    Reset PDU(s) for Instrusion Detection System. Requires local administrator rights on IDSM server(s).
    Kills IDSM_Software python process and restarts the IDSM_Software python process.

.PARAMETER Location
    Gagan or Legan (can accept both entries).

.NOTES
    Author: JBear
    Date: 8/14/2018
#>

param(

    [Parameter(Mandatory=$true, HelpMessage="Legan or Gagan")]
    [ValidateSet("IDSM1","IDSM2")]
    [String[]]$Location
)

    [String]$SSHModuleDir = "\\Server01\it\PowerShell\Modules\Posh-SSH"
    [String]$LocalModule = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Posh-SSH"
    [String]$IDSM1 = "192.168.0.5"
    [String]$IDSM2 = "192.168.0.10"
    $Commands = @(
    
        "sudo pkill python26",
        "sudo /var/IDSM/idsm_script.sh"
    )

    if(!(Test-Path $LocalModule)) {
    
        Copy-Item "\\Server01\IT\PowerShell\Modules\Posh-SSH" "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\" -Recurse -Force
    }

    Try {

        Import-Module POSH-SSH -ErrorAction Stop
    }

    Catch {

        Write-Host -ForegroundColor Yellow "`nUnable to find POSH-SSH Module."
        Break
    }

    $SSHSessions = (New-Object System.Collections.ArrayList)

    if($Location -contains 'IDSM1') {
        
        $SSHSessions.Add("$IDSM1")
    }

    if($Location -contains 'IDSM2') {
        
        $SSHSessions.Add("$IDSM2")
    }
    
    New-SSHSession -ComputerName $SSHSessions -AcceptKey -Force -Verbose | Out-Null
    
    foreach($Open in Get-SSHSession) {

        foreach($Command in $Commands) {

            Invoke-SSHCommandStream -Command $Command -SSHSession $Open
        }
    }

    Get-SSHSession | Remove-SSHSession
} #End ResetIDSM
function InstallPackage {

<#     
.SYNOPSIS     
    Copies and installs specifed filepath ($Path). This serves as a template for the following filetypes: .EXE, .MSI, & .MSP 

.DESCRIPTION     
    Copies and installs specifed filepath ($Path). This serves as a template for the following filetypes: .EXE, .MSI, & .MSP

.EXAMPLE    
    .\InstallAsJob (Get-Content C:\ComputerList.txt)

.EXAMPLE    
    .\InstallAsJob Computer1, Computer2, Computer3   

.NOTES   
    Written by: JBear 
    Date: 2/9/2017 
   
    Edited by: JBear
    Date: 10/13/2017 

#> 

param(

    [Parameter(Mandatory=$true,HelpMessage="Enter Computername(s)")]
    [String[]]$Computername,
    [Parameter(ValueFromPipeline=$true,HelpMessage="Enter installer path(s)")]
    [String[]]$Path = $null,
    [Parameter(ValueFromPipeline=$true,HelpMessage="Enter remote destination: C$\Directory")]
    $Destination = "C$\TempApplications"
)

    if($Path -eq $null) {

        Add-Type -AssemblyName System.Windows.Forms

        $Dialog = New-Object System.Windows.Forms.OpenFileDialog
        $Dialog.InitialDirectory = "\\Server01\IT\Applications"
        $Dialog.Title = "Select Installation File(s)"
        $Dialog.Filter = "Installation Files (*.exe,*.msi,*.msp)|*.exe; *.msi; *.msp"        
        $Dialog.Multiselect=$true
        $Result = $Dialog.ShowDialog()

        if($Result -eq 'OK') {

            Try {
      
                $Path = $Dialog.FileNames
            }

            Catch {

                $Path = $null
	            Break
            }
        }

        else {

            #Shows upon cancellation of Save Menu
            Write-Host -ForegroundColor Yellow "Notice: No file(s) selected."
            Break
        }
    }

    #Create function    
    function InstallAsJob {

        #Each item in $Computernam variable        
        foreach($Computer in $Computername) {

            #If $Computer IS NOT null or only whitespace
            if(!([String]::IsNullOrWhiteSpace($Computer))) {

                #Test-Connection to $Computer
                if(Test-Connection -Quiet -Count 1 $Computer) {                                               
                    
                    #Create job on localhost
                    Start-Job { param($Computer, $Path, $Destination)

                        foreach($P in $Path) {
                         
                            #Static Temp location
                            $TempDir = "\\$Computer\$Destination"

                            #Create $TempDir directory
                            if(!(Test-Path $TempDir)) {

                                New-Item -Type Directory $TempDir | Out-Null
                            }
                    
                            #Retrieve Leaf object from $Path
                            $FileName = (Split-Path -Path $P -Leaf)

                            #New Executable Path
                            $Executable = "C:\$(Split-Path -Path $Destination -Leaf)\$FileName"

                            #Copy needed installer files to remote machine
                            Copy-Item -Path $P -Destination $TempDir

                            #Install .EXE
                            if($FileName -like "*.exe") {

                                function InvokeEXE {

                                    Invoke-Command -ComputerName $Computer { param($TempDir, $FileName, $Executable)
                                   
                                        Try {

                                            #Start EXE file
                                            Start-Process $Executable -ArgumentList "/s" -Wait -NoNewWindow   
                                            Write-Output "`n$FileName installation complete on $env:computername."
                                        }

                                        Catch {
                                        
                                            Write-Output "`n$FileName installation failed on $env:computername."
                                        }

                                        Try {
                                   
                                            #Remove $TempDir location from remote machine
                                            Remove-Item -Path $Executable -Recurse -Force
                                            Write-Output "`n$FileName source file successfully removed on $env:computername."
                                        }

                                        Catch {
                                        
                                            Write-Output "`n$FileName source file removal failed on $env:computername."    
                                        }  
                                    } -AsJob -JobName "Silent EXE Install" -ArgumentList $TempDir, $FileName, $Executable
                                }

                                InvokeEXE | Receive-Job -Wait
                            }
                               
                            #Install .MSI                                        
                            elseif($FileName -like "*.msi") {

                                function InvokeMSI {

                                    Invoke-Command -ComputerName $Computer { param($TempDir, $FileName, $Executable)

                                        Try {
                                       
                                            #Start MSI file                                    
                                            Start-Process 'msiexec.exe' "/i $Executable /qn" -Wait -ErrorAction Stop
                                            Write-Output "`n$FileName installation complete on $env:computername."
                                        }

                                        Catch {
                                       
                                            Write-Output "`n$FileName installation failed on $env:computername."
                                        }

                                        Try {
                                   
                                            #Remove $TempDir location from remote machine
                                            Remove-Item -Path $Executable -Recurse -Force
                                            Write-Output "`n$FileName source file successfully removed on $env:computername."
                                        }

                                        Catch {
                                       
                                            Write-Output "`n$FileName source file removal failed on $env:computername."    
                                        }                              
                                    } -AsJob -JobName "Silent MSI Install" -ArgumentList $TempDir, $FileName, $Executable                            
                                }

                                InvokeMSI | Receive-Job -Wait
                            }

                            #Install .MSP
                            elseif($FileName -like "*.msp") { 
                                                                     
                                function InvokeMSP {

                                    Invoke-Command -ComputerName $Computer { param($TempDir, $FileName, $Executable)

                                        Try {
                                                                              
                                            #Start MSP file                                    
                                            Start-Process 'msiexec.exe' "/p $Executable /qn" -Wait -ErrorAction Stop
                                            Write-Output "`n$FileName installation complete on $env:computername."
                                        }

                                        Catch {
                                      
                                            Write-Output "`n$FileName installation failed on $env:computername."
                                        }

                                        Try {
                                   
                                            #Remove $TempDir location from remote machine
                                            Remove-Item -Path $Executable -Recurse -Force
                                            Write-Output "`n$FileName source file successfully removed on $env:computername."
                                        }

                                        Catch {                                      

                                            Write-Output "`n$FileName source file removal failed on $env:computername."    
                                        }                             
                                    } -AsJob -JobName "Silent MSP Installer" -ArgumentList $TempDir, $FileName, $Executable
                                }

                                InvokeMSP | Receive-Job -Wait
                            }

                            else {

                                Write-Host "$Destination has an unsupported file extension. Please try again."                        
                            }
                        }                      
                    } -Name "Application Install" -Argumentlist $Computer, $Path, $Destination            
                }
                                           
                else {                                
                  
                    Write-Host "Unable to connect to $Computer."                
                }            
            }        
        }   
    }

    #Call main function
    InstallAsJob
}#End InstallApplication

function CrossCertRm {
<# 
.SYNOPSIS 
    Executes the Cross Certificate removal application on specified workstation(s) 

.EXAMPLE 
    CrossCertRm Computer123456 

.EXAMPLE
    CrossCertRm (Get-Content C:\SomeDirectory\WhateverTextFileYouWant.txt)
#> 
[cmdletbinding()]
Param ( 
	    
    [Parameter(Mandatory=$true)]
    [String[]]$ComputerName
)

    function RemoveCertificates {

    $i=0
    $j=0

        ForEach($Computer in $ComputerName) {

            Write-Progress -Activity "Removing Deprecated Certificates..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $Name.count) * 100) + "%") -CurrentOperation "Processing $($Computer)..." -PercentComplete ((($j++) / $Name.count) * 100)

            Try {
                
                $RemoteSession = New-PSSession -ComputerName $Computer
            }

            Catch {

	        "Can't connect. Bad Workstation name, User name or Password. Aborting run."
	        Break
            }

            New-Item "\\$Computer\C$\Program Files\CrossCertRemoverTemp" -type directory -Force | Out-Null
        }

        Copy-Item -Path "\\Server01\it\PowerShell\Profile Repository\FBCA_crosscert_remover_v114.exe" -Destination "\\$computer\C$\Program Files\CrossCertRemoverTemp\FBCA_crosscert_remover_v114.exe" -Force
        Copy-Item -Path "\\Server01\it\PowerShell\Profile Repository\FBCA_crosscert_remover_v114.config" -Destination "\\$computer\C$\Program Files\CrossCertRemoverTemp\FBCA_crosscert_remover_v114.config" -Force

        Invoke-Command -Session $RemoteSession -ScriptBlock {

            Start-Process "C:\Program Files\CrossCertRemoverTemp\FBCA_crosscert_remover_v114.exe" -ArgumentList "/s" -NoNewWindow -wait
        }

        Remove-Item "\\$Computer\C$\Program Files\CrossCertRemoverTemp" -recurse -Force
        Remove-PSSession *
	
    } 
    
    RemoveCertificates
}#End CrossCertRm

function REARMOffice { 

<# 
.SYNOPSIS 
    Copies and executes specifed filepath ($Path); AGM Office 2013 Activation Fix.

.DESCRIPTION
    Copies and executes specifed filepath ($Path); AGM Office 2013 Activation Fix.
#> 

param(

    [Parameter(Mandatory=$true)]
    [String[]]$Computername,
    
    #Change network path to desired file, replace String as needed
    $Path = "\\Server01\it\Applications\Microsoft (Multiple Items)\Office 2013 (AGM)\Office 2013 Fix\Office_ReArm 3-4-17\Office_2013_Rearm.exe",

    #Retrieve Leaf object from $Path
    $FileName = (Split-Path -Path $Path -Leaf)
)

    #Create function
    function InstallAsJob { 
    
        #Each item in $Computernam variable
        ForEach($Computer in $Computername) {
    
            Write-Progress -Activity "Creating Office 2013 Rearm Job..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $Computername.count) * 100) + "%") -CurrentOperation "Processing $($Computer)..." -PercentComplete ((($j++) / $Computername.count) * 100)

            #If $Computer IS NOT null or only whitespace
            if(!([String]::IsNullOrWhiteSpace($Computer))) {

                #Test-Connection to $Computer
                if(Test-Connection -Quiet -Count 1 $Computer) {
            
                    #Static Temp location
                    $TempDir = "\\$Computer\C$\TempPatchDir\"

                    #Final filepath 
                    $Executable = "$TempDir\$FileName" 

                    #Create job on localhost
                    Start-Job { 
                    param($Computer, $Computername, $TempDir, $FileName, $Executable, $Path)
                    
                        #Create $TempDir directory
                        New-Item -Type Directory $TempDir -Force | Out-Null

                        #Copy needed installer files to remote machine
                        Copy-Item -Path $Path -Destination $TempDir

                        #If file is an EXE
                        if($FileName -like "*.exe") {

                            Invoke-Command -ComputerName $Computer { 
                        
                                param($TempDir, $FileName, $Executable, $Computer)
                            
                                #Start EXE file
                                Start-Process $Executable -ArgumentList "/s" -Wait
                            
                                #Remove $TempDir location from remote machine
                                Remove-Item -Path $TempDir -Recurse -Force
                            } -AsJob -JobName "Rearm Office 2013" -ArgumentList $TempDir, $FileName, $Executable, $Computer
                        }
                    
                        elseif($FileName -like "*.msi") {
                    
                            Invoke-Command -ComputerName $Computer { 
                        
                                param($TempDir, $FileName, $Executable, $Computer)

                                #Start MSI file
                                Start-Process 'msiexec.exe' "/i $Executable /qn" -Wait

                                #Remove $TempDir location from remote machine
                                Remove-Item -Path $TempDir -Recurse -Force
                            } -AsJob -JobName "Silent MSI Install" -ArgumentList $TempDir, $FileName, $Executable, $Computer
                        }

                        elseif($FileName -like "*.msp") {
                    
                            Invoke-Command -ComputerName $Computer { 
                        
                                param($TempDir, $FileName, $Executable, $Computer)

                                #Start MSP file
                                Start-Process 'msiexec.exe' "/p $Executable /qn" -Wait

                                #Remove $TempDir location from remote machine
                                Remove-Item -Path $TempDir -Recurse -Force
                            } -AsJob -JobName "Silent MSP Installer" -ArgumentList $TempDir, $FileName, $Executable, $Computer
                        }

                        else {
                    
                            Write-Host "$Destination does not exist on $Computer, or has an incorrect file extension. Please try again."
                        }  
                    } -Name "$Computer Rearm Office2013" -ArgumentList $Computer, $Computername, $TempDir, $FileName, $Executable, $Path
                }
            
                else {
            
                    Write-Host "Unable to connect to $Computer. Please try again..."
                }
            }
        }
    }

    InstallAsJob

    Write-Host "`nJob creation complete. Please use the Get-Job cmdlet to check progress.`n"
    Write-Host "Once all jobs are complete, use Get-Job | Receive-Job to retrieve any output or, Get-Job | Remove-Job to clear jobs from the session cache."
}

function REARMWindows { 

<# 
.SYNOPSIS 
Written by JBear 3/7/2017

.DESCRIPTION
Copies and executes specifed filepath ($Path); AGM Office 2013 Activation Fix.

#> 

param([parameter(mandatory=$true)]
    [String[]]$Computername,
    
    #Change network path to desired file, replace String as needed
    $Path = "\\Server01\it\Applications\AGM (AGM)\Activation Fixes\Windows\AGM10SystemUpdate.exe",

    #Retrieve Leaf object from $Path
    $FileName = (Split-Path -Path $Path -Leaf)
)

    #Create function
    function InstallAsJob { 
    
        #Each item in $Computernam variable
        ForEach($Computer in $Computername) {
    
            Write-Progress -Activity "Creating Windows Activation Job..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $Computername.count) * 100) + "%") -CurrentOperation "Processing $($Computer)..." -PercentComplete ((($j++) / $Computername.count) * 100)

            #If $Computer IS NOT null or only whitespace
            if(!([String]::IsNullOrWhiteSpace($Computer))) {

                #Test-Connection to $Computer
                if(Test-Connection -Quiet -Count 1 $Computer) {

                    #Static Temp location
                    $TempDir = "\\$Computer\C$\TempPatchDir\"

                    #Final filepath 
                    $Executable = "$TempDir\$FileName" 

                    #Create job on localhost
                    Start-Job { 
                    param($Computer, $Computername, $TempDir, $FileName, $Executable, $Path)    
                        #Create $TempDir directory
                        New-Item -Type Directory $TempDir -Force | Out-Null

                        #Copy needed installer files to remote machine
                        Copy-Item -Path $Path -Destination $TempDir

                        #If file is an EXE
                        if($FileName -like "*.exe") {

                            Invoke-Command -ComputerName $Computer { 
                        
                                param($TempDir, $FileName, $Executable, $Computer)
                            
                                #Start EXE file
                                Start-Process $Executable -ArgumentList "/s" -Wait
                            
                                #Remove $TempDir location from remote machine
                                Remove-Item -Path $TempDir -Recurse -Force
                            } -AsJob -JobName "Rearm Windows 7" -ArgumentList $TempDir, $FileName, $Executable, $Computer
                        }
                    
                        elseif($FileName -like "*.msi") {
                    
                            Invoke-Command -ComputerName $Computer { 
                        
                                param($TempDir, $FileName, $Executable, $Computer)

                                #Start MSI file
                                Start-Process 'msiexec.exe' "/i $Executable /qn" -Wait

                                #Remove $TempDir location from remote machine
                                Remove-Item -Path $TempDir -Recurse -Force
                            } -AsJob -JobName "Silent MSI Install" -ArgumentList $TempDir, $FileName, $Executable, $Computer
                        }

                        elseif($FileName -like "*.msp") {
                    
                            Invoke-Command -ComputerName $Computer { 
                        
                                param($TempDir, $FileName, $Executable, $Computer)

                                #Start MSP file
                                Start-Process 'msiexec.exe' "/p $Executable /qn" -Wait

                                #Remove $TempDir location from remote machine
                                Remove-Item -Path $TempDir -Recurse -Force
                            } -AsJob -JobName "Silent MSP Installer" -ArgumentList $TempDir, $FileName, $Executable, $Computer
                        }

                        else {
                    
                            Write-Host "$Destination does not exist on $Computer, or has an incorrect file extension. Please try again."
                        }  
                    } -Name "$Computer Rearm WIN7" -ArgumentList $Computer, $Computername, $TempDir, $FileName, $Executable, $Path
                }
            
                else {
            
                    Write-Host "Unable to connect to $Computer. Please try again..."
                }
            }
        }
    }

    InstallAsJob

    Write-Host "`nJob creation complete. Please use the Get-Job cmdlet to check progress.`n"
    Write-Host "Once all jobs are complete, use Get-Job | Receive-Job to retrieve any output or, Get-Job | Remove-Job to clear jobs from the session cache."
}
function GUI {

    $Baloo = "\\Server01\it\PowerShell\Profile Repository\BalooTrooper.png"
    $MyDocuments = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\BalooTrooper.png"

    if(!(Test-Path $MyDocuments)){  
        Copy-Item "$Baloo" "$MyDocuments"
    }  

    Start-Process powershell.exe -argument '-NonInteractive -WindowStyle Hidden "CallGUI"'

}

function CallGUI { 

    $MyDocuments = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\BalooTrooper.png"

#XML code for GUI objects
$inputXML = @"
<Window x:Class="BearNecessities.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:BearNecessities"
        mc:Ignorable="d"
        Title="Bear Necessities | $ProVersion" Height="510" Width="750" BorderBrush="#FF211414" Background="#FF6C6B6B" WindowStartupLocation="CenterScreen">

<Viewbox HorizontalAlignment="Stretch" VerticalAlignment="Stretch">
    <Grid>

        <Image Height="256" HorizontalAlignment="Left" Name="image1" Stretch="Fill" VerticalAlignment="Top" Width="192" SnapsToDevicePixels="False" Source="$MyDocuments" />
        <TextBox Name="TextBox" Text="$env:ComputerName" Height="276" HorizontalAlignment="Left" Margin="584,27,0,0"  VerticalAlignment="Top" Width="132" Background="Black" Foreground="White" Cursor="IBeam" CharacterCasing="Upper" AcceptsReturn="True" TextWrapping="Wrap" AcceptsTab="True"/>
        <Label Content="**Separate with commas(,)" Height="28" HorizontalAlignment="Left" Margin="580,297,0,0" VerticalAlignment="Top" />
        <Label Content="Computer Name(s)**" Height="28" HorizontalAlignment="Left" Margin="580,5,0,0" VerticalAlignment="Top" />
        <ListView Name="ListBox" Height="197" HorizontalAlignment="Left" Margin="12,262,0,0" VerticalAlignment="Top" Width="375" Background="Black" Foreground="White" BorderBrush="White" />
        <Button Name="SysInfo" Background="Black" BorderBrush="Black" BorderThickness="2" Content="System Information" Foreground="White" Height="32" HorizontalAlignment="Left" Margin="395,324,0,0" VerticalAlignment="Top" Width="104" FontSize="10" FontWeight="Normal" FontFamily="Arial" />
        <Button Name="HotFixInfo" Background="Black" BorderBrush="Black" BorderThickness="2" Content="HotFix Information" FontFamily="Arial" FontSize="10" FontWeight="Normal" Foreground="White" Height="32" HorizontalAlignment="Left" Margin="615,324,0,0" VerticalAlignment="Top" Width="104" />
        <Button Name="SoftwareList" Background="Black" BorderBrush="Black" BorderThickness="2" Content="Software List" FontFamily="Arial" FontSize="10" FontWeight="Normal" Foreground="White" Height="32" HorizontalAlignment="Left" Margin="505,324,0,0" VerticalAlignment="Top" Width="104" />
        <Button Name="Ghost" Background="Black" BorderBrush="Black" BorderThickness="2" Content="Enter Ghost Session" FontFamily="Arial" FontSize="10" FontWeight="Normal" Foreground="White" Height="32" HorizontalAlignment="Left" Margin="615,420,0,0" VerticalAlignment="Top" Width="104" />
        <Button Name="ClearDrivers" Background="Black" BorderBrush="Black" BorderThickness="2" Content="Clear Printer Drivers" FontFamily="Arial" FontSize="10" FontWeight="Normal" Foreground="White" Height="32" HorizontalAlignment="Left" Margin="395,420,0,0" VerticalAlignment="Top" Width="104" />
        <Button Name="ClearCerts" Background="Black" BorderBrush="Black" BorderThickness="2" Content="Clear Invalid Certificates" FontFamily="Arial" FontSize="9" FontWeight="Normal" Foreground="White" Height="32" HorizontalAlignment="Left" Margin="505,420,0,0" VerticalAlignment="Top" Width="104" />
        <Button Name="Reboot" Background="#FFFF2424" BorderBrush="Black" BorderThickness="2" Content="Reboot Workstation(s)" FontFamily="Arial" FontSize="12" FontWeight="Bold" Foreground="White" Height="37" HorizontalAlignment="Left" Margin="198,27,0,0" VerticalAlignment="Top" Width="145" />
        <Button Name="Clear" Background="White" BorderBrush="Black" BorderThickness="2" Content="Clear" FontFamily="Arial" FontSize="12" FontWeight="Bold" Foreground="Black" Height="25" HorizontalAlignment="Left" Margin="175,235,0,0" VerticalAlignment="Top" Width="110" />
	<Button Name="Processes" Background="Black" BorderBrush="Black" BorderThickness="2" Content="Check Processes" FontFamily="Arial" FontSize="10" FontWeight="Normal" Foreground="White" Height="32" HorizontalAlignment="Left" Margin="395,372,0,0" VerticalAlignment="Top" Width="104" />
        <CheckBox Name="CheckBox" Content="Export-CSV" Height="16" HorizontalAlignment="Left" Margin="305,245,0,0" VerticalAlignment="Top" IsChecked="False" />

        
    </Grid>
</Viewbox>
</Window>               
 
"@       
 
    $inputXML = $inputXML -replace 'mc:Ignorable="d"','' -replace "x:N",'N'  -replace '^<Win.*', '<Window'
 
    [Void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
    [XML]$XAML = $inputXML
    
    #Read XAML
    $Reader=(New-Object System.Xml.XmlNodeReader $xaml)

    Try {

        $Form=[Windows.Markup.XamlReader]::Load( $reader )
    }

    Catch {

        Write-Output "Unable to load Windows.Markup.XamlReader. Double-check syntax and ensure .net is installed."
    }
 
    #===========================================================================
    # Store Form Objects In PowerShell
    #===========================================================================
 
    $xaml.SelectNodes("//*[@Name]") | %{Set-Variable -Name "WPF$($_.Name)" -Value $Form.FindName($_.Name)}

    #Connect to Controls
    $inputTextBox = $Form.FindName('TextBox')
    $sysinfoButton = $Form.FindName('SysInfo')
    $hotfixButton = $Form.FindName('HotFixInfo')
    $softwareButton = $Form.FindName('SoftwareList')
    $ghostButton = $Form.FindName('Ghost')
    $printdriversButton = $Form.FindName('ClearDrivers')
    $invalidcertsButton = $Form.FindName('ClearCerts')
    $rebootButton = $Form.FindName('Reboot')
    $checkBox = $Form.FindName('CheckBox')
    $listBox = $Form.FindName('ListBox')
    $clearButton = $Form.FindName('Clear')
    $processButton = $Form.FindName('Processes') 

    #===========================================================================
    # Actually make the objects work
    #===========================================================================

    #Clear Button 
    $clearButton.Add_Click({

        $listBox.Items.Clear()
    })

    #Reboot Button
    $rebootButton.Add_Click({

        $SplitString = $inputTextBox.Text.Split(",")
        $SplitString = $SplitString.Trim()

        #Confirmation variables; prompt user
        $Caption = "Are you sure?"
        $Message = "All workstations listed will be restarted. Do you want to continue?"

        $Yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Yes";
        $No = New-Object System.Management.Automation.Host.ChoiceDescription "&No","No";

        $Choices = ([System.Management.Automation.Host.ChoiceDescription[]](
                        $Yes,$No));

        $Answer = $host.ui.PromptForChoice($Caption,$Message,$Choices,1);

        $Stamp = (Get-Date -Format G) + ":"

        #If NO, do nothing
        if($Answer -eq 1) {

	        #Do nothing
 	        $listBox.Items.Add("$Stamp Reboot(s) aborted!`n")
        }

        #If YES, execute Reboot
        elseif(!($Answer -eq 1)) {

            Reboot $SplitString; $listBox.Items.Add("$Stamp Reboot initialized!`n")
	    }
    })

    #Ghost Button
    $ghostButton.Add_Click({

        $SplitString = $inputTextBox.Text.Split(",")
        $SplitString = $SplitString.Trim()

        Ghost $SplitString 

        $Stamp = (Get-Date -Format G) + ":"

        $listBox.Items.Add("$Stamp Ghost session opened!`n")

    })

    #HotFix Button
    $hotfixButton.Add_Click({

        $Stamp = (Get-Date -Format G) + ":"

        $listBox.Items.Add("Processing... please wait...`n")
        $SplitString = $inputTextBox.Text.Split(",")
        $SplitString = $SplitString.Trim()

        FindHotFixes $SplitString;
    })

    #Certificates Button
    $invalidcertsButton.Add_Click({

        $listBox.Items.Add("Processing... please wait...`n")

        $SplitString = $inputTextBox.Text.Split(",")
        $SplitString = $SplitString.Trim()

        CrossCertRm $SplitString; 

        $Stamp = (Get-Date -Format G) + ":"
        $listBox.Items.Add("$Stamp Invalid certificates removed!`n")

    })

    #Printer Drivers Button
    $printdriversButton.Add_Click({

        $SplitString = $inputTextBox.Text.Split(",")
        $SplitString = $SplitString.Trim()

        RmPrint $SplitString; 

        $Stamp = (Get-Date -Format G) + ":"
        $listBox.Items.Add("$Stamp Printer drivers removed!`n")

    })

    #Software Button
    $softwareButton.Add_Click({

        $Stamp = (Get-Date -Format G) + ":"

        $SplitString = $inputTextBox.Text.Split(",")
        $SplitString = $SplitString.Trim()

        SWcheck $SplitString

    })

    #System Information Button
    $sysinfoButton.Add_Click({

        $Stamp = (Get-Date -Format G) + ":"
    
        $SplitString = $inputTextBox.Text.Split(",")
        $SplitString = $SplitString.Trim()
  
        SYS $SplitString
    })

    #Process Button
    $processButton.Add_Click({

        $Stamp = (Get-Date -Format G) + ":"
    
        $SplitString = $inputTextBox.Text.Split(",")
        $SplitString = $SplitString.Trim()
  
        CheckProcess $SplitString
    })

    #Show Form
    $Form.ShowDialog() | out-null
}#EndGUI

function CreateNewUser {

    Start-Process powershell.exe -ArgumentList '-NonInteractive -WindowStyle Hidden "CallNewUserGUI"'
}

function CallNewUserGUI {

    $MyDocuments = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\BalooTrooper.png"

    Try {

        $Users = Import-Csv -Path "C:\Users\PrimeOptimus\Documents\Output.csv"
    }

    Catch {
        
        #Do Nothing    
    }

    function GenerateUser { 

    <#
    .SYNOPSIS 
        Creates a new active directory user from a template.

        Purpose of script to assist Help Desk with the creation of End-User accounts in Active Directory.

    .NOTES
        Written by:
        Greg & JBear 11/2/2016

        Last Edited: 
        JBear 12/24/2016 - Edited to interact with GUI.
        JBear 8/1/2017 - Fixed array looping issue.
	JBear 8/17/2017 - Fixed ListBoxItem selection issue.
      
        Requires: ActiveDirectory Module
                & PowerShell Version 3 or higher
    #>

        #Script requires ActiveDirectory Module to be loaded
        Import-Module ActiveDirectory

        #User account information variables
        $Template = ( $templatesListBox.items | where {$_.Isselected -eq $true} ).Name
        $UserFirstname = $firstnameTextBox.Text
        $UserInitial = $middleinTextBox.Text
        $UserLastname = $lastnameTextBox.Text 
        $UserCompany = $organizationTextBox.Text
        $UserDepartment =  $departmentTextBox.Text
        $UserJobTitle = $jobtitleTextBox.Text
        $OfficePhone = $phoneTextBox.Text
        $UserOU = @(

            if($Template -like "TemplatePAC*") {
      
                "PAC"
            }

            if($Template -like "TemplateHSV*") {
       
                "HSV"
            }

            if($Template -like "TemplateWOR*") {
      
                "WOR"
            }
        )

        $Description = "[$UserOU] $UserJobTitle - $UserDepartment - $UserCompany"                                                            
        $Displayname = $(
     
            If([String]::IsNullOrWhiteSpace($middleinTextBox.Text)) {

                $UserLastname + ", " + $UserFirstname
            }
        
            Else {

                $UserLastname + ", " + $UserFirstname + " " + $UserInitial
            }
        )
 
        $Info = $(

	    $Date = Get-Date
	    "Account Created: " + $Date.ToShortDateString() + " " + $Date.ToShortTimeString() + " - " +  [Environment]::UserName
        )

	$SamPrefix = $lastnameTextBox.Text.ToLower() + $firstnameTextBox.Text.Substring(0, 1).ToLower()
        <#$SamPrefix = @(

            if(($lastnameTextBox.Text | Measure-Object -Character).Characters -gt "7") {
        
                $lastnameTextBox.Text.SubString(0,7).ToLower() + $firstnameTextBox.Text.SubString(0, 1).ToLower()
            }

            else {
    
                $lastnameTextBox.Text.ToLower() + $firstnameTextBox.Text.SubString(0, 1).ToLower()
            }
        )#>

        $Index = 1

        Do {

            if($Index -eq "1") {

	            $script:SAMaccountname = "$SamPrefix"
            }

            else {
    
                $script:SAMaccountname = "$SamPrefix" + $Index
            }

	        Try {

		    If (Get-ADUser -LDAPFilter "(sAMAccountName=$SAMAccountName)" -ErrorAction Stop) {

                       $Index++
 	            } 

                    Else {

	                $SamOK = $True
                    }
	        }

	        Catch {

		        $SamOK = $false
	        }

        } Until ($SamOK -Or ($Index -ge 99))

        $Password = 'P@$$w00rD123456'
        #$Email = "$SAMAccountName@acme.com"
        <#$CredsFile = "\\Server01\IT\PowerShell\Profile Repository\SecureCreds\SecureCreds.txt"
        
        if(!(Test-Path $CredsFile)) {

            Read-Host -AsSecureString | ConvertFrom-SecureString | Out-File $CredsFile

            $Password = Get-Content $CredsFile | ConvertTo-SecureString
        }

        else {

            $Password = Get-Content $CredsFile | ConvertTo-SecureString
        }#>

        #Parameters from Template User Object
        $AddressPropertyNames = @("StreetAddress","State","PostalCode","POBox","Office","Country","City")
        $SchemaNamingContext = (Get-ADRootDSE).schemaNamingContext
        $PropertiesToCopy = Get-ADObject -Filter "objectCategory -eq 'CN=Attribute-Schema,$SchemaNamingContext' -and searchflags -eq '16'" -SearchBase $SchemaNamingContext -Properties * |  
                            Select -ExpandProperty lDAPDisplayname

        $PropertiesToCopy += $AddressPropertyNames
        $Password_SS = ConvertTo-SecureString -String $Password -AsPlainText -Force
        $Template_Obj = Get-ADUser -Identity $Template -Properties $PropertiesToCopy
        $OU = @(

            if($Template -like "TemplatePAC*") {
                
                "OU=PAC,OU=01_Users,DC=acme,DC=com"
            }

            if($Template -like "TemplateHSV*") {
       
                "OU=HSV,OU=01_Users,DC=acme,DC=com"
            }

            if($Template -like "TemplateWOR*") {
      
                "OU=WOR,OU=01_Users,DC=acme,DC=com"
            }
        )

        #Replace SAMAccountName of Template User with new account for properties like the HomeDrive that need to be dynamic
        $Template_Obj.PSObject.Properties | where {

            $_.Value -match ".*$($Template_Obj.SAMAccountName).*" -and
            $_.Name -ne "SAMAccountName" -and
            $_.IsSettable -eq $True
        } | ForEach {

            Try {

                $_.Value = $_.Value -replace "$($Template_Obj.SamAccountName)","$SAMAccountName"
            }

            Catch {

                #DoNothing
            }
        }

        #ADUser parameters
        $params = @{

            "Instance"=$Template_Obj
            "Name"=$DisplayName
            "DisplayName"=$DisplayName
            "GivenName"=$UserFirstname
            "SurName"=$UserLastname
            "Initials"=$UserInitial
            "AccountPassword"=$Password_SS
            "Enabled"=$false
            "ChangePasswordAtLogon"=$true
            "UserPrincipalName"=$UserPrincipalName
            "SAMAccountName"=$SAMAccountName
            "Path"="$OU"
            "OfficePhone"=$OfficePhone
            "EmailAddress"=$Email
            "Company"=$UserCompany
            "Department"=$UserDepartment
            "Description"=$Description   
            "Title"=$UserJobTitle 
            "SmartCardLogonRequired"=$true
        }

        $AddressPropertyNames | foreach {$params.Add("$_","$($Template_obj."$_")")}
        $DC = (Get-ADDomainController).Name

        New-ADUser -Server $DC @params
        Start-Sleep 5
        $TempMembership = Get-ADUser -Identity $Template -Properties MemberOf | 
                            Select -ExpandProperty MemberOf | 
                            Add-ADGroupMember -Members $SAMAccountName
        Set-ADUser $SAMAccountName -Server Server3100 -ChangePasswordAtLogon $true -Replace @{Info="$Info"}
    }#End GenerateUser

    #Pre-populated user information
    $Script:i = 0

    if(!([String]::IsNullOrWhiteSpace($Users))) {

        $User = $Users[$Script:i++]
    }
    
    #User account information variables
    $UserFirstname = $User.FirstName
    $UserInitial = $User.MiddleIn
    $UserLastname = $User.LastName
    $UserCompany = $User.Company
    $UserDepartment = $User.Department
    $UserJobTitle = $User.JobTitle
    $OfficePhone = $User.Phone

#XML code for GUI objects
$inputXML = @"
<Window x:Class="Bear.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:Bear"
        mc:Ignorable="d"
        Title="Bear Necessities | $ProVersion | Create New Users" Height="510" Width="800" BorderBrush="#FF211414" Background="#FF6C6B6B" WindowStartupLocation="CenterScreen">

    <Viewbox HorizontalAlignment="Stretch" VerticalAlignment="Stretch">
        <Grid>

            <Image Height="256" HorizontalAlignment="Left" Name="image1" Stretch="Fill" VerticalAlignment="Top" Width="192" SnapsToDevicePixels="False" Source="$MyDocuments" />
            <TextBox Name="FirstName" Text="$UserFirstname" Background="Black"  Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="12,284,0,0" VerticalAlignment="Top" Width="211" />
            <Label Content="(First Name)" Height="28" HorizontalAlignment="Left" Margin="12,262,0,0" VerticalAlignment="Top" FontWeight="Bold" Width="106" />

            <TextBox Name="MiddleIn" Text="$UserInitial" Background="Black"  Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="258,284,0,0" VerticalAlignment="Top" Width="211" />
            <Label Content="(Middle Initial)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="258,262,0,0" VerticalAlignment="Top" Width="97" />

            <TextBox Name="LastName" Text="$UserLastname" Background="Black"  Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="505,284,0,0" VerticalAlignment="Top" Width="211" />
            <Label Content="(Last Name)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="505,262,0,0" VerticalAlignment="Top" Width="97" />

            <TextBox Name="Organization" Text="$UserCompany" Background="Black"  Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="12,332,0,0" VerticalAlignment="Top" Width="211" />
            <Label Content="(Organization)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="12,310,0,0" VerticalAlignment="Top" Width="97" />

            <TextBox Name="Department" Text="$UserDepartment" Background="Black"  Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="258,332,0,0" VerticalAlignment="Top" Width="211" />
            <Label Content="(Department)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="258,310,0,0" VerticalAlignment="Top" Width="97" />

            <TextBox Name="Phone" Text="$OfficePhone" Background="Black"  Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="505,332,0,0" VerticalAlignment="Top" Width="211" />
            <Label Content="(Phone)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="505,310,0,0" VerticalAlignment="Top" Width="97" />
 
            <TextBox Name="JobTitle" Text="$UserJobTitle" Background="Black"  Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="12,380,0,0" VerticalAlignment="Top" Width="211" />
            <Label Content="(Job Title)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="12,358,0,0" VerticalAlignment="Top" Width="97" />

            <Button Name="NewUser" Background="Black" BorderBrush="Black" BorderThickness="2" Content="Create New User" Foreground="White" Height="30" HorizontalAlignment="Left" Margin="559,14,0,0" VerticalAlignment="Top" Width="144" FontSize="13" FontWeight="Bold" FontFamily="Arial" />

	        <Label Content="(User Template)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="198,65,0,0" VerticalAlignment="Top" Width="106" />
 	    
            <ListBox Name="Templates" AllowDrop="True" Background="Black" BorderBrush="Black" BorderThickness="2" Foreground="White" Height="167" HorizontalAlignment="Left" ItemsSource="{Binding}" Margin="198,0,0,215" VerticalAlignment="Bottom" Width="211">

                <ListBoxItem Name="TemplatePAC" Content="PAC User" />
                <ListBoxItem Name="TemplateHSV" Content="HSV User" />
		<ListBoxItem Name="TemplateWOR" Content="WOR User" />
            </ListBox>

        </Grid>
    </Viewbox>
</Window>               
 
"@ 
 
    $inputXML = $inputXML -replace 'mc:Ignorable="d"','' -replace "x:N",'N'  -replace '^<Win.*', '<Window'
 
    [Void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
    [XML]$XAML = $inputXML

    #Read XAML
    $Reader = (New-Object System.Xml.XmlNodeReader $XAML)

    Try {

        $Form=[Windows.Markup.XamlReader]::Load( $Reader )
    }

    Catch {

        Write-Host "Unable to load Windows.Markup.XamlReader. Double-check syntax and ensure .net is installed."
    }

    #Store Form Objects In PowerShell
    $xaml.SelectNodes("//*[@Name]") | %{Set-Variable -Name "WPF$($_.Name)" -Value $Form.FindName($_.Name)}

    #Connect to Controls
    $firstnameTextBox = $Form.FindName('FirstName')
    $middleinTextBox = $Form.FindName('MiddleIn')
    $lastnameTextBox = $Form.FindName('LastName')
    $organizationTextBox = $Form.FindName('Organization')
    $departmentTextBox = $Form.FindName('Department')
    $jobtitleTextBox = $Form.FindName('JobTitle')
    $phoneTextBox = $Form.FindName('Phone')
    $templatesListBox = $Form.FindName('Templates')
    $newuserButton = $Form.FindName('NewUser')

    #Create New User Button 
    $newuserButton.Add_Click({

        #Call user creation function
        GenerateUser

            $User = $Users[$script:i++]
        
                $firstnameTextBox.Text = $User.FirstName
                $middleinTextBox.Text = $User.MiddleIn
                $lastnameTextBox.Text = $User.LastName
                $organizationTextBox.Text = $User.Company
                $departmentTextBox.Text = $User.Department
                $jobtitleTextBox.Text = $User.JobTitle
                $phoneTextBox.Text = $User.Phone
    })

    #Show Form
    $Form.ShowDialog() | Out-Null
}
