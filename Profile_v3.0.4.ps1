$ProVersion = "v3.0.4"
<#
PowerShell Profile $ProVersion
Author: Jeremy DeWitt aka JBear

Update Notes:
Version 3.0.2:
	-Renamed NewADUser to CreateNewUser.
	-Added GUI to CreateNewUser process.
	-Fixed several GUI bugs.	
Version 3.0.1:
	-Added PatchSearch function to report specific patches and install times.
Version 2.9:
	- Added InstallPackage function to handle .EXE, .MSI, and .MSP installs in a single function.
        - Removed InstallEXE and InstallMSI functions.
	- Updated SYS function to report items that are null or unable to be reached via PING.
Version 2.8:
	- Added Windows 7 and MSOffice 2013 activation functions to repo.
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
	- Added specific Home Path to 'cd' command; set location to \\SERVER12345\IT\Documentation\PowerShell\Scripts.
Version 1.7:
	- Moved repository to permanent location. Changed file references to reflect changes.
Version 1.6:
	- Added ability to enter only number portion of property numbers to RDP and Ghost.
		(i.e. RDP 123456 or RDP Computer123456; Ghost 123456 or Ghost Computer123456)
	- Updated Get-Help for all functions included in this repository.
Version 1.5:
	- Fixed bugs for InstallEXE and InstallMSI that were catching due to first if(!() statement.	
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
	- Changed Set-Location to my scripts folder "\\SERVER12345\transfer\JBear\Scripts".
	- Bug fixes.
	- Need to fix bugs in Create in SAARNewUser section.	
#>

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

#net use Q: "\\SERVER12345\IT\Documentation\PowerShell"
#Set-Location "Q:\Scripts"

#Update-Help

#Custom menu that lists currently available functions within the shell repository
function PrintMenu {

	Write-Host(" ----------------------- ")
	Write-Host("| Bear Necessities $ProVersion |")
	Write-Host(" ----------------------- ")
	Write-Host('Type "GUI" to launch GUI interface!')
	Write-Host("")
	Write-Host("Command             Function")
	Write-Host("-------             --------")
	Write-Host("ADcleanup           Remove specified workstation(s) from AD and SCCM")
	Write-Host("ADgroup             Copy Specified User Groups to Clipboard")
	Write-Host("cl                  Clear Shell and Reprint Command Menu")
	Write-Host("CheckProcess        Retrieve System Process Information")
	Write-Host("CrossCertRm         Remove Inoperable Certificates")
	Write-Host("Enable              Enable User Account in AD")
	Write-Host("GetSAM              Search For SAM Account Name By Name")
	Write-Host("Ghost               Opens SCCM Ghost Session")
	Write-Host("GodMode             Access God Mode")
	Write-Host("GPR                 Group Policy (Remote)")
	Write-Host("HuntUser            Query SCCM For Last System Logged On By Specified User")
	Write-Host("InstallApplication  Silent Install EXE, MSI, or MSP files")
	Write-Host("JavaCache           Clear Java Cache")
	Write-Host("LastBoot            Get Last Reboot Time")
	Write-Host("NetMSG              On-screen Message For Specified Workstation(s)")
	Write-Host("NewADuser           Create New Active Directory Users From SAAR Forms")
	Write-Host("Nithins             Opens Nithin's SCCM Client Tool")
	Write-Host("RDP                 Remote Desktop")
    Write-Host("REARMOffice         Rearm Office 2013 Activation")
    Write-Host("REARMWindows        Rearm Windows 7 OS Activation")
	Write-Host("Reboot              Force Restart")
	Write-Host("RmPrint             Clear Printer Drivers")
	Write-Host("RmUserProf          Clear User Profiles")
	Write-Host("SCCM                Active Directory/SCCM Console")	
	Write-Host("SWcheck             Check Installed Software")
	Write-Host("SYS                 All Remote System Info")
	Write-Host("UpdateProfile       Update PowerShell Profile (Will Overwrite Current Version & Any Changes)")
	Write-Host("")
	Write-Host("")
}#End PrintMenu

Remove-Item Alias:cd
#Rebuild cd command
function cd {

    if ($args[0] -eq '-') {
	
        $pwd=$OLDPWD
    } 
    
    else {

        $pwd=$args[0]
    }
	
    $tmp=pwd

    if ($pwd) {

        #Enter Previous Working Directory when using cd - 
        Set-Location $pwd
    }

    Set-Variable -Name OLDPWD -Value $tmp -Scope global;
}#End CD

#Set Home Path
#(Get-PSProvider 'FileSystem').Home = "Q:\Scripts"

function cl {
<# 
.SYNOPSIS 
    Used to clear current PowerShell window

.DESCRIPTION 
    Clears screen (same as clear) but, writes created 'PrintMenu' back onto the main shell for function reference

.EXAMPLE 
    cl 
#> 
    
    #Clear Shell Prompt
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
    $userpath = [environment]::getfolderpath("desktop")
    $godpath = "\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
    $finalpath = $userpath + $godpath

    if (!(Test-Path -Path $finalpath)) {

        #Creates GodMode path for current user
        New-Item -Type directory -Path $finalpath -force | Out-Null
    }
	
    #Opens GodMode path
    Start-Process "$finalpath"
}#End GodMode

function ADgroup {
<# 
.SYNOPSIS 
    Copies specified users' AD Groups to clipboard - created for specific person who needed this information
 
.EXAMPLE 
    ADGroup User1
#>
 	
param(

    [Parameter(Mandatory=$true)]
    [string[]] $Username
)

    foreach ($Name in $UserName) {
	
        (Get-ADUser -Identity $name -Property MemberOf | select MemberOf).MemberOf | %{Get-ADGroup $_} | Select Name | Clip
    }
}#End ADgroup

function UpdateProfile {
<# 
.SYNOPSIS 
    Update PowerShell profile to current repository content.

.DESCRIPTION
    Update PowerShell profile to current repository content.

.EXAMPLE 
    UpdateProfile 
#> 

    $NetworkLocation = "\\SERVER12345\IT\Documentation\PowerShell\Profile Repository\DevOps\TechProfile.txt"
    $MyDocuments = [environment]::getfolderpath("mydocuments") + "\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
    $MyDocuments2 = [environment]::getfolderpath("mydocuments") + "\WindowsPowerShell\Profile.ps1"

    #Overwrite current $Profile for PowerShell and PowerShell ISE
    Copy-Item -path "$NetworkLocation" -destination "$MyDocuments" -Force
    Copy-Item -path "$NetworkLocation" -destination "$MyDocuments2" -Force	

    #Reload PowerShell
    Powershell
	
}#End UpdateProfile

#Opens SCCM Admin Console.msc
function SCCM {
<# 
.SYNOPSIS 
    Opens pre-generated Active Directory and SCCM MMC.

.EXAMPLE 
    SCCM  
#> 

    $pat1 = "\\SERVER12345\it\Applications\Microsoft (Multiple Items)\SCCM\Admin Console.msc"
    $dir1 = "C:\Program Files (x86)\SCCM Tools"
    $des1 = $dir1 + "\Admin Console.msc"

    if (!(Test-Path -Path $dir1)) {

        #Creates SCCM Console path
        New-Item -Type directory -Path $dir1 -force | Out-Null
        Copy-Item $pat1 $des1 -Force
    }

    if (Test-Path -Path $dir1) {
	
        Copy-Item $pat1 $des1
    }
    
    #Opens SCCM Admin Console
    Start-Process "$des1"
}#End SCCM

Clear-Host
PrintMenu

function GetSAM {
<# 
.SYNOPSIS 
    Retrieve users' SAM account name based on full or partial name search. 

.Parameter GivenName
    Search user by Given Name. Default search is by Surname.

.DESCRIPTION
    The GetSAM function uses the Get-ADUser cmdlet to query Active Directory for all users including the value entered (i.e. Users' first name (using -GivenName parameter), or users' last name (Default search Surname).
 
.EXAMPLE 
    GetSAM Smith

.EXAMPLE 
    GetSAM Smi 

.EXAMPLE 
    GetSAM -GivenName John

.EXAMPLE
    GetSAM -GivenName Jo
#>

Param(

    [Parameter(Mandatory=$true)] 
    [String[]]$NameValue,
    [Switch]$GivenName
)

    $name = switch ($GivenName.IsPresent) {
        $true { "GivenName" }
        default { "Surname" }
    }

    $i=0
    $j=0

    foreach ($User in $NameValue) {

        Write-Progress -Activity "Retrieving SAM Account Names..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $NameValue.count) * 100) + "%") -CurrentOperation "Processing $($User)..." -PercentComplete ((($j++) / $NameValue.count) * 100)

        #Get SAM Account Name for specified user
        Get-ADUser -Filter "$Name -like '$User*'" | FT GivenName, SurName, SamAccountName
    }	
}#End GetSAM

function HuntUser {
<# 
.SYNOPSIS 
    Retrieve workstation(s) last logged on by user (SAM Account Name)

.DESCRIPTION 
    The HuntUser function will retrieve workstation(s) by the last logged on user (SAM Account Name). This queries SCCM; accuracy will depend on the last time each workstation has communicated with SCCM.
  
.EXAMPLE 
    HuntUser dewittj 
#> 

Param( 
    
    [Parameter(Mandatory=$true)]
    [String[]]$SamAccountName,

    [Parameter(ValueFromPipeline=$true)]
    [String]$SiteName="ABC",

    [Parameter(ValueFromPipeline=$true)]
    [String]$SCCMServer="SERVER1234",

    [Parameter(ValueFromPipeline=$true)]
    [String]$SCCMNameSpace="root\sms\site_$SiteName",

    $i=0,
    $j=0
)

    function QuerySCCM {

        foreach ($User in $SamAccountName) {

            Write-Progress -Activity "Retrieving Last Logged On Computers By SAM Account Name..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $SAMAccountName.count) * 100) + "%") -CurrentOperation "Processing $($User)..." -PercentComplete ((($j++) / $SAMAccountName.count) * 100)

            $Computername = (Get-WmiObject -Namespace $SCCMNameSpace -Computername $SCCMServer -Query "select Name from sms_r_system where LastLogonUserName='$User'").Name
                
                foreach ($Computer in $Computername) {

                    [pscustomobject] @{
            
                        SAMAccountName = "$User"  
                        LastComputer = "$Computer"                    
                }
            }
        }
    }

    QuerySCCM

}#End HuntUser

function PatchSearch {
<# 
.SYNOPSIS
    Reports uptimes of specified workstations.

.EXAMPLE
    .\Script.ps1 Server01, Server02
    Reports uptimes for Server01, Server02

.EXAMPLE
    .\Script.ps1 -FindHotFix KB4019264, KB982018
    Reports uptimes for all servers in Default array and searched for specified HotFixes. Value(s) will only return if they are found.

.NOTES
    Written by JBear 5/19/16	
#>

[cmdletbinding()]

Param (

    [Parameter(Mandatory=$true,position=0)]
    $ComputerName, #= ((Get-ADComputer -Filter * -SearchBase "OU=05_Servers,DC=ACME,DC=COM").Name),

    #Format today's date
    $LogDate = (Get-Date -format yyyyMMdd),

    $OutFile = [environment]::getfolderpath("mydocuments") + "\" + $LogDate + "-UpTime\KBReport.csv",

    [Parameter(position=1)]
    [Switch]$FindHotFix,

    [Parameter(ValueFromPipeline=$true,Position=2)]
    [String[]]$KB=@(),

    $i=0,
    $j=0
)	
			
    function UptimeReport {

        foreach ($Computer in $ComputerName) {

            Write-Progress -Activity "Retrieving Uptime and HotFix results..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $ComputerName.count) * 100) + "%") -CurrentOperation "Processing $($Computer)..." -PercentComplete ((($j++) / $ComputerName.count) * 100)

            if(!([String]::IsNullOrWhiteSpace($Computer))) {

                if (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {

                    Start-Job { param($Computer, $ComputerName, $KB)

                        if($KB) {

                            Invoke-Command -ComputerName $Computer {param ($Computer, $KB)

                                $uptime = Get-WmiObject Win32_OperatingSystem -ComputerName $Computer
                                $bootTime = $uptime.ConvertToDateTime($uptime.LastBootUpTime)
                                $elapsedTime = (Get-Date) - $bootTime
                                $HotFixResults = Get-HotFix -Id $KB -ErrorAction SilentlyContinue

                                if($HotFixResults) {

                                    foreach($HotFix in $HotFixResults) {

                                        [pscustomobject] @{

                                            ComputerName = $Computer
                                            LastBootTime = $bootTime
                                            ElapsedTime = '{0:00} Days, {1:00} Hours, {2:00} Minutes, {3:00} Seconds' -f $elapsedTime.Days, $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds
                                            HotFix=$HotFix.HotFixID
                                            HFInstallDate=$HotFix.InstalledOn
                                        }
                                    }

                                    $KB | ForEach-Object {
                                            
                                        if(!($hotfixresults.HotFixID -contains $_)) {
                                        
                                            [pscustomobject] @{

                                                ComputerName = $Computer
                                                LastBootTime = $bootTime
                                                ElapsedTime = '{0:00} Days, {1:00} Hours, {2:00} Minutes, {3:00} Seconds' -f $elapsedTime.Days, $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds
                                                HotFix=$_
                                                HFInstallDate='Not Installed'
                                            }
                                        }
                                    }
                                }

                                else {

                                    $KB | ForEach-Object {
                                            
                                        if(!($hotfixresults.HotFixID -contains $_)) {

                                            [pscustomobject] @{

                                                ComputerName = $Computer
                                                LastBootTime = $bootTime
                                                ElapsedTime = '{0:00} Days, {1:00} Hours, {2:00} Minutes, {3:00} Seconds' -f $elapsedTime.Days, $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds
                                                HotFix=$_
                                                HFInstallDate='Not Installed'
                                            }    
                                        }
                                    }                                                  
                                }
                            } -ArgumentList $Computer, $KB
                        }

                        else {

                            $uptime = Get-WmiObject Win32_OperatingSystem -ComputerName $Computer
                            $bootTime = $uptime.ConvertToDateTime($uptime.LastBootUpTime)
                            $elapsedTime = (Get-Date) - $bootTime

                            [pscustomobject] @{

                                ComputerName = $Computer
                                LastBootTime = $bootTime
                                ElapsedTime = '{0:00} Days, {1:00} Hours, {2:00} Minutes, {3:00} Seconds' -f $elapsedTime.Days, $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds
                                HotFix=$null
                                HFInstallDate=$null
                            }
                        }
                    } -Name "Uptime Information" -ArgumentList $Computer, $ComputerName, $KB
                }

                else {

                    Start-Job {param ($Computer)

                        [pscustomobject] @{

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
    } 

    if(!($FindHotFix.IsPresent)) {

        UptimeReport | Receive-Job -Wait -AutoRemoveJob |  Sort ComputerName | Select ComputerName, LastBootTime, ElapsedTime | Out-GridView -Title "System Uptime" #| Export-Csv $OutFile -NoTypeInformation -Force
    }

    else {

        UptimeReport | Receive-Job -Wait -AutoRemoveJob |  Sort ComputerName | Select ComputerName, LastBootTime, ElapsedTime, HotFix, HFInstallDate | Out-GridView -Title "System Uptime and KB Information" #| Export-Csv $OutFile -NoTypeInformation -Force
    }
}#End PatchSearch
　
#Imports AD/SCCM console; Active Directory module needed
Import-Module ActiveDirectory

#Reboots specified workstation(s)
function Reboot {
<# 
.SYNOPSIS 
    Restarts specified workstation(s) 

.EXAMPLE 
    Reboot Computer123456 

.EXAMPLE
    Reboot (Get-Content C:\SomeDirectory\WhateverTextFileYouWant.txt)
#> 

param(
    
    [Parameter(Mandatory=$true)]
    [String[]]$ComputerName,
    
    $i=0,
    $j=0
)

    foreach ($Computer in $ComputerName) {

        Write-Progress -Activity "Rebooting computer..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $ComputerArray.count) * 100) + "%") -CurrentOperation "Processing $($computer)..." -PercentComplete ((($j++) / $ComputerArray.count) * 100)
　
        #Force reboot on specified workstation or array
        Restart-Computer $Computer -Force -AsJob | Out-Null
    }

    [Void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
    $RebootConfirmation = [Microsoft.VisualBasic.Interaction]::MsgBox("Reboot sequence has been started on workstation(s)!", "OKOnly,SystemModal,Information", "Success")
}#End Reboot
 
#ActiveDirectory module needed
function Ghost {
<# 
.SYNOPSIS 
    Opens Ghost session to specified workstation(s) 

.EXAMPLE 
    Ghost Computer123456 
#> 

param(

    [Parameter(Mandatory=$true)]
    [String]$Computername
)

    #Start interactive Remote Tools session with specified workstation 
    Start-Process 'C:\Program Files (x86)\Microsoft Configuration Manager Console\AdminUI\bin\i386\rc.exe' "1 $Computername"   
}#End Ghost

 
function RDP {
<# 
.SYNOPSIS 
    Remote Desktop Protocol to specified workstation(s) 

.EXAMPLE 
    RDP Computer123456 

.EXAMPLE 
    RDP 123456 
#> 

param(

    [Parameter(Mandatory=$true)]
    [String]$Computername
)

    #Start Remote Desktop Protocol on specifed workstation
    & "C:\windows\system32\mstsc.exe" /v:$computername /fullscreen
}#End RDP

function GPR {
<# 
.SYNOPSIS 
    Open Group Policy for specified workstation(s) 

.EXAMPLE 
    GPR Computer123456 
#> 

param(

    [Parameter(Mandatory=$true)]
    [String[]]$ComputerName,

    $i=0,
    $j=0
)

    foreach ($Computer in $ComputerName) {

        Write-Progress -Activity "Opening Remote Group Policy..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $ComputerName.count) * 100) + "%") -CurrentOperation "Processing $($computer)..." -PercentComplete ((($j++) / $ComputerName.count) * 100)

        #Opens (Remote) Group Policy for specified workstation
        GPedit.msc /gpcomputer: $Computer
    }
}#End GPR

function Enable {
<# 
.SYNOPSIS 
    Enable User Account in AD; Requires proper permissions. Search by partial or full last name, manually enter SAM Account Name.
  
.EXAMPLE 
    Enac Smith

.EXAMPLE 
    Enac Smi 
#> 

    $last = Read-Host -Prompt 'Search by Last Name'
	
    #Last Name search for Active Directory users - Returns First, Last, & SAM Account Name
    Get-ADUser -Filter "Surname -like '$last*'" | FT GivenName,Surname,SamAccountName

    #Enter desired SAM Account Name to enable user account, if disabled
    Enable-ADAccount –Identity (Read-Host “Enter Desired Username”)

    Write-Host("`nSpecified Account Unlocked!`n")

}#End Enac

function LastBoot {
<# 
.SYNOPSIS 
    Retrieve last restart time for specified workstation(s) 

.EXAMPLE 
    LastBoot Computer123456 

.EXAMPLE 
    LastBoot 123456 
#> 

param(

    [Parameter(Mandatory=$true)]
    [String[]]$ComputerName,

    $i=0,
    $j=0
)

    foreach($Computer in $ComputerName) {

        Write-Progress -Activity "Retrieving Last Reboot Time..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $ComputerName.count) * 100) + "%") -CurrentOperation "Processing $($computer)..." -PercentComplete ((($j++) / $ComputerName.count) * 100)
　
        $computerOS = Get-WmiObject Win32_OperatingSystem -Computer $Computer

        [pscustomobject] @{

            ComputerName = $Computer
            LastReboot = $computerOS.ConvertToDateTime($computerOS.LastBootUpTime)
        }
    }
}#End LastBoot

　
function SYS {
<# 
.SYNOPSIS 
  Retrieve basic system information for specified workstation(s) 

.EXAMPLE 
  SYS Computer123456 
#> 

param(

    [Parameter(Mandatory=$true)]
    [string[]] $ComputerName,
    
    $i=0,
    $j=0
)

$Stamp = (Get-Date -Format G) + ":"

    function Systeminformation {
	
        foreach ($Computer in $ComputerName) {

            if(!([String]::IsNullOrWhiteSpace($Computer))) {

                if(Test-Connection -Quiet -Count 1 -Computer $Computer) {

                    Write-Progress -Activity "Getting Sytem Information..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $ComputerName.count) * 100) + "%") -CurrentOperation "Processing $($Computer)..." -PercentComplete ((($j++) / $ComputerName.count) * 100)

	                Start-Job -ScriptBlock { param($Computer) 

	                    #Gather specified workstation information; CimInstance only works on 64-bit
	                    $computerSystem = Get-CimInstance CIM_ComputerSystem -Computer $Computer
	                    $computerBIOS = Get-CimInstance CIM_BIOSElement -Computer $Computer
	                    $computerOS = Get-CimInstance CIM_OperatingSystem -Computer $Computer
	                    $computerCPU = Get-CimInstance CIM_Processor -Computer $Computer
	                    $computerHDD = Get-CimInstance Win32_LogicalDisk -Computer $Computer -Filter "DeviceID = 'C:'"
    
                        [PSCustomObject] @{

                            ComputerName = $computerSystem.Name
                            LastReboot = $computerOS.LastBootUpTime
                            OperatingSystem = $computerOS.OSArchitecture + " " + $computerOS.caption
                            Model = $computerSystem.Model
                            RAM = "{0:N2}" -f [int]($computerSystem.TotalPhysicalMemory/1GB) + "GB"
                            DiskCapacity = "{0:N2}" -f ($computerHDD.Size/1GB) + "GB"
                            TotalDiskSpace = "{0:P2}" -f ($computerHDD.FreeSpace/$computerHDD.Size) + " Free (" + "{0:N2}" -f ($computerHDD.FreeSpace/1GB) + "GB)"
                            CurrentUser = $computerSystem.UserName
                        }
                    } -ArgumentList $Computer
                }

                else {

                    Start-Job -ScriptBlock { param($Computer)  
                     
                        [PSCustomObject] @{

                            ComputerName=$Computer
                            LastReboot="Unable to PING."
                            OperatingSystem="$Null"
                            Model="$Null"
                            RAM="$Null"
                            DiskCapacity="$Null"
                            TotalDiskSpace="$Null"
                            CurrentUser="$Null"
                        }
                    } -ArgumentList $Computer                       
                }
            }

            else {
                 
                Start-Job -ScriptBlock { param($Computer)  
                     
                    [PSCustomObject] @{

                        ComputerName = "Value is null."
                        LastReboot = "$Null"
                        OperatingSystem = "$Null"
                        Model = "$Null"
                        RAM = "$Null"
                        DiskCapacity = "$Null"
                        TotalDiskSpace = "$Null"
                        CurrentUser = "$Null"
                    }
                } -ArgumentList $Computer
            }
        } 
    }

    $SystemInformation = SystemInformation | Wait-Job | Receive-Job | Select "Computer Name", "Current User", "Operating System", Model, RAM, "Disk Capacity", "Total Disk Space", "Last Reboot"
    $DocPath = [environment]::getfolderpath("mydocuments") + "\SystemInformation-Report.csv"

	Switch($CheckBox.IsChecked) {

		$true { 
            
            $SystemInformation | Export-Csv $DocPath -NoTypeInformation -Force 
        }

		default { 
            
            $SystemInformation | Out-GridView -Title "System Information"
        }
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
    RmPrint Computer123456 

.EXAMPLE 
    RmPrint 123456 
#> 

param(
    
    [Parameter(Mandatory=$true)]
	[String[]]$Computername,

    $i=0,
    $j=0
)

    function RmPrintDrivers {
 	
        foreach ($Computer in $ComputerName) { 

            Write-Progress -Activity "Clearing printer drivers..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $ComputerName.count) * 100) + "%") -CurrentOperation "Processing $($computer)..." -PercentComplete ((($j++) / $ComputerName.count) * 100)

	        Invoke-Command -Computername $Computer -ScriptBlock {

                #Remove all print drivers, excluding default drivers
		        if((Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\') -eq $true) {

                    Remove-Item -PATH 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3\*' -EXCLUDE "*ADOBE*", "*MICROSOFT*", "*XPS*", "*REMOTE*", "*FAX*", "*ONENOTE*" -recurse
			        Remove-Item -PATH 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers\*' -EXCLUDE "*ADOBE*", "*MICROSOFT*", "*XPS*", "*REMOTE*", "*FAX*", "*ONENOTE*" -recurse
		    
                    Set-Service Spooler -startuptype manual
		            Restart-Service Spooler
		            Set-Service Spooler -startuptype automatic
	            }
	        } -AsJob -JobName "ClearPrintDrivers"
	    } 
    } 

    RmPrintDrivers
}#End RmPrint

#Removes botched Office 2013 installations due to Programs and Features removal not working
#This function is commented out; due to specifics of function, keeping code for future reference
<#function rmOffice {
param(

    [Parameter(Mandatory=$true)]
    [String[]]$Computername
)

    foreach($Computer in $Computername) {

        Invoke-Command -Computername $Computer -ScriptBlock {

	        New-PSDrive -PSProvider registry -root HKEY_CLASSES_ROOT -Name HKCR
	        New-PSDrive -PSProvider registry -root HKEY_CURRENT_USER -Name HKCU | Out-Null
	        Remove-Item -path 'C:\Program Files (x86)\Common Files\microsoft shared\OFFICE15' -force -recurse | Out-Null
	        Remove-Item -path 'C:\Program Files (x86)\Common Files\microsoft shared\Source Engine' -force -recurse | Out-Null
	        Remove-Item -path 'C:\Program Files (x86)\Microsoft Office\Office15' -force -recurse | Out-Null
	        Remove-Item -path 'C:\MSOCache\All Users\*0FF1CE}*' -force -recurse | Out-Null
	        Remove-Item -path '*\AppData\Roaming\Microsoft\Templates\*.dotm' -force -recurse | Out-Null
	        Remove-Item -path '*\AppData\Roaming\Microsoft\Templates\*.dotx' -force -recurse | Out-Null
	        Remove-Item -path '*\AppData\microsoft\document building blocks\*.dotx' -force -recurse | Out-Null
	        Remove-Item -path 'HKCU:\Software\Microsoft\Office\15.0' -recurse | Out-Null
	        Remove-Item -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\15.0' -recurse | Out-Null
	        Remove-Item -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\Delivery\SourceEngine\Downloads\*0FF1CE}-*' -recurse | Out-Null
	        Remove-Item -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*0FF1CE*' -recurse | Out-Null
	        Remove-Item -path 'HKLM:\SYSTEM\CurrentControlSet\Services\ose' -recurse | Out-Null
	        Remove-Item -path 'HKCR:\Installer\Features\*F01FEC' -recurse | Out-Null
	        Remove-Item -path 'HKCR:\Installer\Products\*F01FEC' -recurse | Out-Null
	        Remove-Item -path 'HKCR:\Installer\UpgradeCodes\*F01FEC' -recurse | Out-Null
	        Remove-Item -path 'HKCR:\Installer\Win32Asemblies\*Office15*' -recurse | Out-Null
	        Remove-Item -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*Office15*' -recurse | Out-Null
        }
    }
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
    [String[]] $ComputerName,

    [Parameter(Mandatory=$true,HelpMessage='Enter desired message')]
    [String]$MyMessage,

    [String]$User = [Environment]::UserName,

    [String]$UserJob = (Get-ADUser $User -Property Title).Title,
    
    [String]$CallBack = "$User | 5-2444 | $UserJob",

    $i=0,
    $j=0
)

    function SendMessage {

        foreach($Computer in $ComputerName) {

            Write-Progress -Activity "Sending messages..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $ComputerName.count) * 100) + "%") -CurrentOperation "Processing $($Computer)..." -PercentComplete ((($j++) / $ComputerName.count) * 100)         

            #Invoke local MSG command on specified workstation - will generate pop-up message for any user logged onto that workstation - *Also shows on Login screen, stays there for 100,000 seconds or until interacted with
            Invoke-Command -ComputerName $Computer { param($MyMessage, $CallBack, $User, $UserJob)
 
                MSG /time:100000 * /v "$MyMessage {$CallBack}"
            } -ArgumentList $MyMessage, $CallBack, $User, $UserJob -AsJob
        }
    }

    SendMessage | Wait-Job | Remove-Job

}#End NetMSG

function SWcheck {
<# 
.SYNOPSIS 
    Grabs all installed Software on specified workstation(s) 

.EXAMPLE 
    SWcheck Computer123456 

.EXAMPLE 
    SWcheck 123456 
#> 

param (

    [Parameter(Mandatory=$true)]
    [String[]]$ComputerName,

    [Parameter(ValueFromPipeline=$true)]
    [String]$NameRegex = '',

    $i=0,
    $j=0
)

    $Stamp = (Get-Date -Format G) + ":"

    function SoftwareCheck {

        foreach ($Computer in $ComputerName) {

            if(!([String]::IsNullOrWhiteSpace($Computer))) {

                if(Test-Connection -Quiet -Count 1 -Computer $Computer) {

                    Write-Progress -Activity "Retrieving Software Information..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $ComputerName.count) * 100) + "%") -CurrentOperation "Processing $($Computer)..." -PercentComplete ((($j++) / $ComputerName.count) * 100)

                    Start-Job -ScriptBlock { param($Computer,$NameRegex)    

                        $Keys = '','\Wow6432Node'

                        foreach ($Key in $keys) {

                            Try {

                                $Apps = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$Computer).OpenSubKey("SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
                            } 
            
                            Catch {

                                Continue
                            }

                            foreach ($App in $Apps) {

                                $Program = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$Computer).OpenSubKey("SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall\$app")
                                $Name = $Program.GetValue('DisplayName')

                                if($Name -and $Name -match $NameRegex) {

                                    [PSCustomObject]@{

                                        Computername = $Computer
                                        Software = $Name
                                        Version = $Program.GetValue('DisplayVersion')
                                        Publisher = $Program.GetValue('Publisher')
                                        InstallDate = $Program.GetValue('InstallDate')
                                        UninstallString = $Program.GetValue('UninstallString')
                                        Bits = $(
                                            
                                            if($Key -eq '\Wow6432Node') {
                                                '64'
                                            } 
                                            
                                            else {
                                                
                                                '32'
                                            }
                                        )

                                        Path = $Program.Name
                                    }
                                }
                            }
                        }
                    } -Name "Software Check" -ArgumentList $Computer, $NameRegex 
                }

                else {

                    Start-Job -ScriptBlock { param($Computer)  
                     
                        [PSCustomObject] @{

                            ComputerName = $Computer
                            Software = "Unable to PING"
                            Version = "N/A"
                            Publisher = "N/A"
                            InstallDate = "N/A"
                            UninstallString = "N/A"
                            Bits = "N/A"
                            Path = "N/A"
                        }
                    } -ArgumentList $Computer                       
                }
            }

            else {
                 
                Start-Job -ScriptBlock { param($Computer)  
                     
                    [PSCustomObject] @{

                        ComputerName = $Computer
                        Software = "Unable to PING"
                        Version = "N/A"
                        Publisher = "N/A"
                        InstallDate = "N/A"
                        UninstallString = "N/A"
                        Bits = "N/A"
                        Path = "N/A"
                    }
                } -ArgumentList $Computer
            }
        }
    }	

    $SoftwareCheck = SoftwareCheck | Receive-Job -Wait | Select ComputerName, Software, Version, Publisher, InstallDate, UninstallString, Bits, Path
    $DocPath = [environment]::getfolderpath("mydocuments") + "\Software-Report.csv"

    Switch ($CheckBox.IsChecked){

        $true { 
            
            $SoftwareCheck | Export-Csv $DocPath -NoTypeInformation -Force
        }

    	Default { 
            
            $SoftwareCheck | Out-GridView -Title "Software"
        }
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

Param ( 

	[Parameter(Mandatory=$true)]
    [String[]]$Computername,
    
    $i=0,
    $j=0
)

    function ClearJava {

        foreach($Computer in $Computername) {

            Write-Progress -Activity "Clearing Java Cache..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $Computer.count) * 100) + "%") -CurrentOperation "Processing $($Computer)..." -PercentComplete ((($j++) / $Computername.count) * 100)

	        Invoke-Command -Computername $Computer {
                
                &"javaws" '-uninstall'
            } -AsJob 	
        }
    }

    ClearJava | Wait-Job | Remove-Job
}#End JavaCache
　
function ADcleanup {
<# 
.SYNOPSIS 
    Removes workstation(s) from Active Directory and SCCM 
  
.EXAMPLE 
    ADcleanup Computer1, Computer2, Computer3
#> 

Param(

    [Parameter(Mandatory=$true)] 
    [String[]]$Computername,
	
    [Parameter(ValueFromPipeline=$true)] 
    [String]$SiteName = "ABC",

    [Parameter(ValueFromPipeline=$true)]     
    [String]$SCCMServer = "SERVER1234",

    [Parameter(ValueFromPipeline=$true)]     
    [String]$SCCMNameSpace = "root\sms\site_$SiteName",

    [Parameter(ValueFromPipeline=$true)]     
    $DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain(),
    
    [Parameter(ValueFromPipeline=$true)]     
    $RootObj = $DomainObj.GetDirectoryEntry(),

    [Parameter(ValueFromPipeline=$true)]     
	$Search = [System.DirectoryServices.DirectorySearcher]$RootObj
)

    foreach($Computer in $ComputerName) {
	
	    #Find and delete specified workstation(s) from Active Directory
	    $Search.Filter = "(&(objectclass=computer)(name=$Computer))"
	    $Search.FindAll() | %{$_.GetDirectoryEntry() } | %{$_.DeleteObject(0)}

	    #Find and delete specified workstation(s) from SCCM
	    $ComputerObj = Get-WMIObject -Query "select * from sms_r_system where Name='$Computer'" -ComputerName $SCCMServer -Namespace $SCCMNameSpace
	    $ComputerObj.PSBase.Delete()
        Write-Host -Foregroundcolor Yellow "`nRemoved $Computer from Active Directory and SCCM."
	}
}#End ADcleanup
　
function Nithins {  
<# 
.SYNOPSIS 
    Opens Nithin's SCCM Tools
  
.EXAMPLE 
    Nithins 
#> 

param(	

    $Path = "\\SERVER12345\it\Applications\Microsoft (Multiple Items)\SCCM\ClientActionsTool.hta",
	$Dir = "C:\Program Files (x86)\SCCM Tools",
	$Destination = $Dir + "\ClientActionsTool.hta"
)

    if (!(Test-Path -Path $Destination)) {

	    #Creates Nithin's path
	    New-Item -Type Directory -Path $Dir -Force | Out-Null
	    Copy-Item -Path $Path -Destination $Destination -Force
    }
    	
	#Opens Nithin's Client
	Start-Process "$Destination"
}#End Nithins

function CheckProcess {
<# 
.SYNOPSIS 
    Grabs all processes on specified workstation(s).

.EXAMPLE 
    CheckProcess Computer123456 

.EXAMPLE 
    CheckProcess 123456 
#> 

param(

    [Parameter(ValueFromPipeline=$true)]
    [String[]]$ComputerName,

    [String]$Stamp = (Get-Date -Format G) + ":",
    
    $i=0,
    $j=0
)

　
    function GetProcess {

        foreach($Computer in $ComputerName) {

            if(!([String]::IsNullOrWhiteSpace($Computer))) {

                if(Test-Connection -Quiet -Count 1 -Computer $Computer) {

                    Write-Progress -Activity "Retrieving System Processes..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $ComputerName.count) * 100) + "%") -CurrentOperation "Processing $($Computer)..." -PercentComplete ((($j++) / $ComputerName.count) * 100)

                    $getProcess = Get-Process -ComputerName $computer

                    foreach ($Process in $getProcess) {
                
                         [PSCustomObject] @{

		                    ComputerName = $Computer
                            Process = $Process.ProcessName
                            PID = '{0:f0}' -f $Process.ID
                            Company = $Process.Company
                            CPU = $Process.CPU
                            Description = $Process.Description
                         }           
                    }
                }
            }
        } 
    }
	
	$GetProcess = GetProcess | Sort ComputerName | Select ComputerName, ProcessName, PID, Company, CPU, Description
    $DocPath = [environment]::getfolderpath("mydocuments") + "\Process-Report.csv"

    Switch($CheckBox.IsChecked) {

        $true { 
            
            $GetProcess | Export-Csv $DocPath -NoTypeInformation -Force
        }
        
        Default { 
        
            $GetProcess | Out-GridView -Title "Processes"
        }
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
    FindHotFixes Computer1, Computer2
#> 

param (

    [Parameter(ValueFromPipeline=$true)]
    [String[]]$ComputerName,

　
    [String]$Stamp = (Get-Date -Format G) + ":",
    
    $i=0,
    $j=0
)

    function HotFix {

        foreach($Computer in $ComputerName) {

            if(!([String]::IsNullOrWhiteSpace($Computer))) {

                if(Test-Connection -Quiet -Count 1 -Computer $Computer) {

                    Write-Progress -Activity "Retrieving HotFix Information..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $ComputerArray.count) * 100) + "%") -CurrentOperation "Processing $($computer)..." -PercentComplete ((($j++) / $ComputerArray.count) * 100)

                    Invoke-Command -Computername $Computer {
                    
                        Get-HotFix
                    }
                }
            }
        }    
    }

    $HotFix = HotFix | Receive-Job -Wait
    $DocPath = [environment]::getfolderpath("mydocuments") + "\HotFix-Report.csv"

    Switch ($CheckBox.IsChecked) {

        $true { 
            
            $HotFix | Export-Csv $DocPath -NoTypeInformation -Force
        }

    	Default { 
    
            $HotFix | Out-GridView -Title "HotFix Report" 
        }
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
    Remove user profiles from a specified system.

.DESCRIPTION
    Remove user profiles from a specified system with the use of DelProf2.exe.

.EXAMPLE
    Remove-UserProfiles Computer123456

.NOTES
    Author: JBear
    Date: 1/31/2017
#>

param(
    
    [parameter(mandatory=$true)]
    [string[]]$Computername
)

    function UseDelProf2 { 
               
        #Set parameters for remote computer and -WhatIf (/l)
        $WhatIf = @(

            "/l",
            "/c:$computer" 
        )
           
        #Runs DelProf2.exe with the /l parameter (or -WhatIf) to list potential User Profiles tagged for potential deletion
        & "\\SERVER12345\it\Documentation\PowerShell\Scripts\DelProf2.exe" $WhatIf

        #Display instructions on console
        Write-Host "`n`nPLEASE ENSURE YOU FULLY UNDERSTAND THIS COMMAND BEFORE USE `nTHIS WILL DELETE ALL USER PROFILE INFORMATION FOR SPECIFIED USER(S) ON THE SPECIFIED WORKSTATION!`n"

        #Prompt User for input
        $DeleteUsers = Read-Host -Prompt "To delete User Profiles, please use the following syntax ; Wildcards (*) are accepted. `nExample: /id:user1 /id:smith* /id:*john*`n `nEnter proper syntax to remove specific users" 

        #If only whitespace or a $null entry is entered, command is not run
        if([string]::IsNullOrWhiteSpace($DeleteUsers)) {

            Write-Host "`nImproper value entered, excluding all users from deletion. You will need to re-run the command on $computer, if you wish to try again...`n"

        }

        #If Read-Host contains proper syntax (Starts with /id:) run command to delete specified user; DelProf will give a confirmation prompt
        elseif($DeleteUsers -like "/id:*") {

            #Set parameters for remote computer
            $UserArgs = @(

                "/c:$computer"
            )

            #Split $DeleteUsers entries and add to $UserArgs array
            $UserArgs = $DeleteUsers.Split("")

            #Runs DelProf2.exe with $UserArgs parameters (i.e. & "C:\DelProf2.exe" /c:Computer1 /id:User1* /id:User7)
            & "\\SERVER12345\it\Documentation\PowerShell\Scripts\DelProf2.exe" $UserArgs
        }

        #If Read-Host doesn't begin with the input /id:, command is not run
        else {

            Write-Host "`nImproper value entered, excluding all users from deletion. You will need to re-run the command on $computer, if you wish to try again...`n"
        }
    }

    foreach($Computer in $Computername) {

        if(Test-Connection -Quiet -Count 1 -Computer $Computer) { 

            UseDelProf2 
        }

        else {
            
            Write-Host "`nUnable to connect to $Computer. Please try again..." -ForegroundColor Red
        }
    }
}#End RmUserProf

function InstallApplication {

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
    Author: JBear 
    Date: 2/9/2017 
    
    Edit: JBear
    Date: 10/13/2017 
#> 

param(

    [Parameter(Mandatory=$true,HelpMessage="Enter Computername(s)")]
    [String[]]$Computername,

    [Parameter(ValueFromPipeline=$true,HelpMessage="Enter installer path(s)")]
    [String[]]$Path = $null,

    [Parameter(ValueFromPipeline=$true,HelpMessage='Enter remote destination: C$\Directory')]
    $Destination = "C$\TempApplications"
)

    if($Path -eq $null) {

        Add-Type -AssemblyName System.Windows.Forms

        $Dialog = New-Object System.Windows.Forms.OpenFileDialog
        $Dialog.InitialDirectory = "\\kwajv101\deployments$"
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
            if(!([string]::IsNullOrWhiteSpace($Computer))) {

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
				    
				    	                $MSIArguments = @(
						
						                    "/i"
						                    $Executable
						                    "/qn"
					                    )

                                        Try {
                                        
                                            #Start MSI file                                    
                                            Start-Process 'msiexec.exe' -ArgumentList $MSIArguments -Wait -ErrorAction Stop

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
				    
				    	                $MSPArguments = @(
						
						                    "/p"
						                    $Executable
						                    "/qn"
					                    )				    

                                        Try {
                                                                                
                                            #Start MSP file                                    
                                            Start-Process 'msiexec.exe' -ArgumentList $MSPArguments -Wait -ErrorAction Stop

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
    Write-Host "`nJob creation complete. Please use the Get-Job cmdlet to check progress.`n"
    Write-Host "Once all jobs are complete, use Get-Job | Receive-Job to retrieve any output or, Get-Job | Remove-Job to clear jobs from the session cache."
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

Param (

	[Parameter(Mandatory=$true)]
    [String[]]$Computername,

    $i=0,
    $j=0
)

    function RemoveCertificates {
　
        foreach($Computer in $Computername) {

            New-Item "\\$computer\C$\Program Files\CrossCertRemoverTemp" -Type directory -Force | Out-Null
       
            Copy-Item -Path "\\SERVER12345\it\Documentation\PowerShell\Profile Repository\FBCA_crosscert_remover_v114.exe" -Destination "\\$Computer\C$\Program Files\CrossCertRemoverTemp\FBCA_crosscert_remover_v114.exe" -force
            Copy-Item -Path "\\SERVER12345\it\Documentation\PowerShell\Profile Repository\FBCA_crosscert_remover_v114.config" -Destination "\\$Computer\C$\Program Files\CrossCertRemoverTemp\FBCA_crosscert_remover_v114.config" -force

            Invoke-Command -Computername $Computer { 
            
                Start-Process "C:\Program Files\CrossCertRemoverTemp\FBCA_crosscert_remover_v114.exe" -ArgumentList "/s" -NoNewWindow -Wait
                Remove-Item "C:\Program Files\CrossCertRemoverTemp" -Recurse -Force
            }
        }
    } 
    
    RemoveCertificates
}#End CrossCertRm

function REARMOffice { 

<# 
.SYNOPSIS 
Written by JBear 3/7/2017
.DESCRIPTION
Copies and executes specifed filepath ($Path); AGM Office 2013 Activation Fix.
#> 

param(

    [parameter(mandatory=$true)]
    [String[]]$Computername,
    
    #Change network path to desired file, replace string as needed
    [String]$Path = "\\SERVER12345\IT\Applications\Microsoft (Multiple Items)\Office 2013 (AGM)\Office 2013 Fix\Office_ReArm 3-4-17\Office_2013_Rearm.exe",

    #Retrieve Leaf object from $Path
    [String]$FileName = (Split-Path -Path $Path -Leaf),

    #Static Temp location
    [String]$TempDir = "\\$Computer\C$\TempPatchDir\",

    #Final filepath 
    [String]$Executable = "$TempDir\$FileName"
)

    function InstallAsJob { 
    
        foreach($Computer in $Computername) {
    
            Write-Progress -Activity "Creating Office 2013 Rearm Job..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $Computername.count) * 100) + "%") -CurrentOperation "Processing $($Computer)..." -PercentComplete ((($j++) / $Computername.count) * 100)

            if(!([string]::IsNullOrWhiteSpace($Computer))) {

                #Test-Connection to $Computer
                if(Test-Connection -Quiet -Count 1 $Computer) { 

                    #Create job on localhost
                    Start-Job { 
                    
                        #Create $TempDir directory
                        New-Item -Type Directory $TempDir -Force | Out-Null

                        #Copy needed installer files to remote machine
                        Copy-Item -Path $Path -Destination $TempDir

                        #If file is an EXE
                        if($FileName -like "*.exe") {

                            Invoke-Command -ComputerName $Computer { 
                        
                                param($TempDir, $FileName, $Executable)
                            
                                #Start EXE file
                                Start-Process $Executable -ArgumentList "/s" -Wait
                            
                                #Remove $TempDir location from remote machine
                                Remove-Item -Path $TempDir -Recurse -Force
                            } -AsJob -JobName "Rearm Office 2013" -ArgumentList $TempDir, $FileName, $Executable
                        }
                    
                        elseif($FileName -like "*.msi") {
                    
                            Invoke-Command -ComputerName $Computer { 
                        
                                param($TempDir, $FileName, $Executable)

                                #Start MSI file
                                Start-Process 'msiexec.exe' "/i $Executable /qn" -Wait

                                #Remove $TempDir location from remote machine
                                Remove-Item -Path $TempDir -Recurse -Force
                            } -AsJob -JobName "Silent MSI Install" -ArgumentList $TempDir, $FileName, $Executable
                        }

                        elseif($FileName -like "*.msp") {
                    
                            Invoke-Command -ComputerName $Computer { 
                        
                                param($TempDir, $FileName, $Executable)

                                #Start MSP file
                                Start-Process 'msiexec.exe' "/p $Executable /qn" -Wait

                                #Remove $TempDir location from remote machine
                                Remove-Item -Path $TempDir -Recurse -Force
                            } -AsJob -JobName "Silent MSP Installer" -ArgumentList $TempDir, $FileName, $Executable
                        }

                        else {
                    
                            Write-Host "$Destination does not exist on $Computer, or has an incorrect file extension. Please try again."
                        }  
                    } -Name "$Computer Rearm Office2013" 
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
    AGM Office 2013 Activation Fix.

.DESCRIPTION
    AGM Office 2013 Activation Fix.

.NOTES
    Author: JBear
    Date:3/7/2017
#> 

param(

    [Parameter(Mandatory=$true)]
    [String[]]$Computername,
    
    #Change network path to desired file, replace string as needed
    [String]$Path = "\\SERVER12345\IT\Applications\AGM (AGM)\Activation Fixes\Windows\AGM10SystemUpdate.exe",

    #Retrieve Leaf object from $Path
    [String]$FileName = (Split-Path -Path $Path -Leaf),

    #Static Temp location
    [String]$TempDir = "\\$Computer\C$\TempPatchDir\",

    #Final filepath 
    [String]$Executable = "$TempDir\$FileName"
)

    function InstallAsJob { 
    
        #Each item in $Computernam variable
        ForEach($Computer in $Computername) {
    
            Write-Progress -Activity "Creating Windows Activation Job..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $Computername.count) * 100) + "%") -CurrentOperation "Processing $($Computer)..." -PercentComplete ((($j++) / $Computername.count) * 100)

            #If $Computer IS NOT null or only whitespace
            if(!([string]::IsNullOrWhiteSpace($Computer))) {

                #Test-Connection to $Computer
                if(Test-Connection -Quiet -Count 1 $Computer) { 

                    #Create job on localhost
                    Start-Job { 
                    
                        #Create $TempDir directory
                        New-Item -Type Directory $TempDir -Force | Out-Null

                        #Copy needed installer files to remote machine
                        Copy-Item -Path $Path -Destination $TempDir

                        #If file is an EXE
                        if($FileName -like "*.exe") {

                            Invoke-Command -ComputerName $Computer { 
                        
                                param($TempDir, $FileName, $Executable)
                            
                                #Start EXE file
                                Start-Process $Executable -ArgumentList "/s" -Wait
                            
                                #Remove $TempDir location from remote machine
                                Remove-Item -Path $TempDir -Recurse -Force
                            } -AsJob -JobName "Rearm Windows 7" -ArgumentList $TempDir, $FileName, $Executable
                        }                   

                        else {
                    
                            Write-Host "$Destination does not exist on $Computer, or has an incorrect file extension. Please try again."
                        }  
                    } -Name "$Computer Rearm WIN7" 
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

function CreateNewUser {

　
    Start-Process powershell.exe -ArgumentList '-NonInteractive -WindowStyle Hidden "CallNewUserGUI"'

}

function CallNewUserGUI {

    $Users = Import-Csv -Path "C:\Users\PrimeOptimus\Documents\Output.csv"

    function GenerateUser { 

    <#
    .SYNOPSIS 
        Creates a new active directory user from a template.

        Purpose of script to assist Help Desk with the creation of End-User accounts in Active Directory.

    .NOTES
        Author: JBear 
        Date: 11/2/2016

        Edit: JBear
        Date: 12/24/2016 - Edited to interact with GUI.
              8/1/2017 - Fixed array looping issue.
    #>

        #Script requires ActiveDirectory Module to be loaded
        Import-Module ActiveDirectory

        #User account information variables
        $Designation = $designationTextBox.Text
        $UserFirstname = $firstnameTextBox.Text
        $UserInitial = $middleinTextBox.Text
        $UserLastname = $lastnameTextBox.Text 
        $SupervisorEmail = $supervisoremailTextBox.Text
        $UserCompany = $organizationTextBox.Text
        $UserDepartment =  $departmentTextBox.Text
        $UserJobTitle = $jobtitleTextBox.Text
        $OfficePhone = $phoneTextBox.Text
        $Description = $descriptionTextBox.Text
        $Email = $emailTextBox.Text                                                              
        $Displayname = $(
     
            if([string]::IsNullOrWhiteSpace($middleinTextBox.Text)) {

                $UserLastname + ", " + $UserFirstname + " $Designation"
            }
        
            else {

                $UserLastname + ", " + $UserFirstname + " " + $UserInitial + " $Designation"
            }
        )
 
        $Info = $(

	        $Date = Get-Date
	        "Account Created: " + $Date.ToShortDateString() + " " + $Date.ToShortTimeString() + " - " +  [Environment]::UserName
        )

        $Password = '7890&*()uiopUIOP'
        $Template = ( $templatesListBox.items | where {$_.Isselected -eq $true} ).Name
        $FindSuperV = Get-ADUser -Filter { ( mail -Like $User.SupervisorEmail ) } -ErrorAction SilentlyContinue
        $FindSuperV = $FindSuperV | select -First "1" -ExpandProperty SamAccountName

        #Load Visual Basic .NET Framework
        [Void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
　
        #Do{ process } Until( )
        Do { 

            #Continue if $True
            While($True) {

                $SAM = [Microsoft.VisualBasic.Interaction]::InputBox("Enter desired Username for $Displayname :", "Create Username", "") 
            
                #Will loop if no value is supplied for $SAM
                If($SAM -ne "$Null") {

                    #If AD user exists, throw error warning; loop back to $SAM input
                    Try {

                        $FindSAM = Get-ADUser $SAM -ErrorAction Stop
                        $SAMError = [Microsoft.VisualBasic.Interaction]::MsgBox("Username [$SAM] already in use by: " + $FindSAM.Name + "`nPlease try again...", "OKOnly,SystemModal", "Error")
                    }

                    #On -EA Stop, specified account doesn't exist; continue with creation
                    Catch {

                        $SAMFound = $False 
                        Break 
                    }
                }
            }
        }

        #Break from Do { } when $SAMFound is $False
        Until($SAMFound -eq $False) 

        #Parameters from Template User Object
        $AddressPropertyNames = @("StreetAddress","State","PostalCode","POBox","Office","Country","City")
        $SchemaNamingContext = (Get-ADRootDSE).schemaNamingContext
        $PropertiesToCopy = Get-ADObject -Filter "objectCategory -eq 'CN=Attribute-Schema,$SchemaNamingContext' -and searchflags -eq '16'" -SearchBase $SchemaNamingContext -Properties * |  
                            Select -ExpandProperty lDAPDisplayname

        $PropertiesToCopy += $AddressPropertyNames
        $Password_SS = ConvertTo-SecureString -String $Password -AsPlainText -Force
        $Template_Obj = Get-ADUser -Identity $Template -Properties $PropertiesToCopy
        $OU = $Template_Obj.DistinguishedName -Replace '^cn=.+?(?<!\\),'

        #Replace SAMAccountName of Template User with new account for properties like the HomeDrive that need to be dynamic
        $Template_Obj.PSObject.Properties | where {

            $_.Value -match ".*$($Template_Obj.SAMAccountName).*" -and
            $_.Name -ne "SAMAccountName" -and
            $_.IsSettable -eq $True
        } | ForEach {

            Try {

                $_.Value = $_.Value -replace "$($Template_Obj.SamAccountName)","$SAM"
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
            "ChangePasswordAtLogon"=$false
            "UserPrincipalName"=$UserPrincipalName
            "SAMAccountName"=$SAM
            "Path"=$OU
            "OfficePhone"=$OfficePhone
            "EmailAddress"=$Email
            "Company"=$UserCompany
            "Department"=$UserDepartment
            "Description"=$Description   
            "Title"=$UserJobTitle 
            "SmartCardLogonRequired"=$True
        }

        $AddressPropertyNames | foreach {
        
            $params.Add("$_","$($Template_obj."$_")")
        }

        New-ADUser @params
        Start-Sleep -Seconds 3    
        Set-AdUser "$SAM" -Manager $FindSuperV -Replace @{ Info="$Info" }

        $TempMembership = Get-ADUser -Identity $Template -Properties MemberOf | 
                          Select -ExpandProperty MemberOf | 
                          Add-ADGroupMember -Members $SAM
    }

    #Pre-populated user information
    $Script:i = 0
    $User = $Users[$Script:i++]
    
    #User account information variables
    $Designation = $(

        if($User.Citizenship -EQ "3") {

            "Contractor Marshall ACME"

        }

        elseif($User.Citizenship -EQ "2") {

            "ACME"

        }

        elseif($User.Organization -LIKE "*Agency*") {

            "Temp ACME"

        }

        elseif($User.Department -LIKE "Temp*" -Or $User.Department -LIKE "*Short") {

            "Temp ACME"

        }

        elseif($User.Designation -EQ "1") {

            "Boss ACME"

        }

        elseif($User.Designation -EQ "2") {

            "Civilian ACME"

        }

        elseif($User.Designation -EQ "3") {

            "Contractor ACME"
        }
    )

    $UserFirstname = $User.FirstName
    $UserInitial = $User.MiddleIn
    $UserLastname = $User.LastName
    $SupervisorEmail = $User.SupervisorEmail
    $UserCompany = $User.Company
    $UserDepartment = $User.Department
    $Citizenship = $User.Citizenship
    $FileServer = $User.Location
    $UserJobTitle = $User.JobTitle
    $OfficePhone = $User.Phone
    $Email = $User.Email
    $Description = $(

        If($User.Citizenship -eq 2) {

            "Domain User (FN)"

        }

        ElseIf($User.Citizenship -eq 3) {
    
            "Domain User (USA)"

        }

        ElseIf($User.Citizenship -eq 1) {

            "Domain User"

        }
    )

#XML code for GUI objects
$inputXML = @"
<Window x:Class="Bear.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:Bear"
        mc:Ignorable="d"
        Title="Bear Necessities | $ProVersion | Create New Users" Height="510" Width="750" BorderBrush="#FF211414" Background="#FF6C6B6B" ResizeMode="CanMinimize" WindowStartupLocation="CenterScreen">

    <Grid>

        
        <TextBox Name="FirstName" Text="$UserFirstname" Background="Black" CharacterCasing="Upper" Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="12,284,0,0" VerticalAlignment="Top" Width="211" />
        <Label Content="(First Name)" Height="28" HorizontalAlignment="Left" Margin="12,262,0,0" VerticalAlignment="Top" FontWeight="Bold" Width="106" />

        <TextBox Name="MiddleIn" Text="$UserInitial" Background="Black" CharacterCasing="Upper" Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="258,284,0,0" VerticalAlignment="Top" Width="211" />
        <Label Content="(Middle Initial)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="258,262,0,0" VerticalAlignment="Top" Width="97" />

        <TextBox Name="LastName" Text="$UserLastname" Background="Black" CharacterCasing="Upper" Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="505,284,0,0" VerticalAlignment="Top" Width="211" />
        <Label Content="(Last Name)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="505,262,0,0" VerticalAlignment="Top" Width="97" />

        <TextBox Name="Organization" Text="$UserCompany" Background="Black" CharacterCasing="Upper" Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="12,332,0,0" VerticalAlignment="Top" Width="211" />
        <Label Content="(Organization)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="12,310,0,0" VerticalAlignment="Top" Width="97" />

        <TextBox Name="Department" Text="$UserDepartment" Background="Black" CharacterCasing="Upper" Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="258,332,0,0" VerticalAlignment="Top" Width="211" />
        <Label Content="(Department)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="258,310,0,0" VerticalAlignment="Top" Width="97" />

        <TextBox Name="Phone" Text="$OfficePhone" Background="Black" CharacterCasing="Upper" Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="505,332,0,0" VerticalAlignment="Top" Width="211" />
        <Label Content="(Phone)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="505,310,0,0" VerticalAlignment="Top" Width="97" />

        <TextBox Name="Email" Text="$Email" Background="Black" CharacterCasing="Upper" Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="12,380,0,0" VerticalAlignment="Top" Width="211" />
        <Label Content="(Official User Email)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="12,358,0,0" VerticalAlignment="Top" Width="127" />

        <TextBox Name="JobTitle" Text="$UserJobTitle" Background="Black" CharacterCasing="Upper" Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="258,380,0,0" VerticalAlignment="Top" Width="211" />
        <Label Content="(Job Title)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="258,358,0,0" VerticalAlignment="Top" Width="97" />

        <TextBox Name="Description" Text="$Description" Background="Black" CharacterCasing="Upper" Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="505,380,0,0" VerticalAlignment="Top" Width="211" />
        <Label Content="(Description)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="505,358,0,0" VerticalAlignment="Top" Width="97" />

        <TextBox Name="Designation" Text="$Designation" Background="Black" CharacterCasing="Upper" Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="12,428,0,0" VerticalAlignment="Top" Width="211" />
        <Label Content="(Designation)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="12,406,0,0" VerticalAlignment="Top" Width="97" />

        <TextBox Name="SupervisorEmail" Text="$SupervisorEmail" Background="Black" CharacterCasing="Upper" Cursor="IBeam" Foreground="White" Height="27" HorizontalAlignment="Left" Margin="258,428,0,0" VerticalAlignment="Top" Width="211" />
        <Label Content="(Supervisor's Email)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="258,406,0,0" VerticalAlignment="Top" Width="128" />

	<Button Name="NewUser" Background="Black" BorderBrush="Black" BorderThickness="2" Content="Create New User" Foreground="White" Height="30" HorizontalAlignment="Left" Margin="559,14,0,0" VerticalAlignment="Top" Width="144" FontSize="13" FontWeight="Bold" FontFamily="Arial" />

	<Label Content="(User Template)" FontWeight="Bold" Height="28" HorizontalAlignment="Left" Margin="198,65,0,0" VerticalAlignment="Top" Width="106" />
 	<ListBox Name="Templates" AllowDrop="True" Background="Black" BorderBrush="Black" BorderThickness="2" Foreground="White" Height="167" HorizontalAlignment="Left" ItemsSource="{Binding}" Margin="198,0,0,215" VerticalAlignment="Bottom" Width="211">

            <ListBoxItem Name="Student" Content="Student Template" />
            <ListBoxItem Name="Teacher" Content="Teacher Template" />
            </ListBox>

    </Grid>
</Window>               
 
"@ 
 
    $inputXML = $inputXML -replace 'mc:Ignorable="d"','' -replace "x:N",'N'  -replace '^<Win.*', '<Window' 
    [Void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
    [XML]$XAML = $inputXML
    $Reader = (New-Object System.Xml.XmlNodeReader $XAML)

    Try {

        $Form = [Windows.Markup.XamlReader]::Load( $Reader )
    }

    Catch {

        Write-Host "Unable to load Windows.Markup.XamlReader. Double-check syntax and ensure .net is installed."
    }

    #Store Form Objects In PowerShell
    $XAML.SelectNodes("//*[@Name]") | %{Set-Variable -Name "WPF$($_.Name)" -Value $Form.FindName($_.Name)}

    #Connect to Controls
    $firstnameTextBox = $Form.FindName('FirstName')
    $middleinTextBox = $Form.FindName('MiddleIn')
    $lastnameTextBox = $Form.FindName('LastName')
    $organizationTextBox = $Form.FindName('Organization')
    $emailTextBox = $Form.FindName('Email')
    $designationTextBox = $Form.FindName('Designation')
    $departmentTextBox = $Form.FindName('Department')
    $jobtitleTextBox = $Form.FindName('JobTitle')
    $phoneTextBox = $Form.FindName('Phone')
    $descriptionTextBox = $Form.FindName('Description')
    $supervisoremailTextBox = $Form.FindName('SupervisorEmail')
    $templatesListBox = $Form.FindName('Templates')
    $newuserButton = $Form.FindName('NewUser')

    #Create New User Button 
    $newuserButton.Add_Click({

        #Call user creation function
        GenerateUser

        $User = $Users[$script:i++]
        $Designation = $(

            if($User.Citizenship -EQ "3") {

                "Contractor Marshall ACME"

            }

            elseif($User.Citizenship -EQ "2") {

                "ACME"

            }

            elseif($User.Organization -LIKE "*Agency*") {

                "Temp ACME"

            }

            elseif($User.Department -LIKE "Temp*" -Or $User.Department -LIKE "*Short") {

                "Temp ACME"

            }

            elseif($User.Designation -EQ "1") {

                "Boss ACME"

            }

            elseif($User.Designation -EQ "2") {

                "Civilian ACME"

            }

            elseif($User.Designation -EQ "3") {

                "Contractor ACME"
            }
        )

        $Description = $(

            If($User.Citizenship -eq 2) {

                "Domain User (FN)"

            }

            ElseIf($User.Citizenship -eq 3) {
    
                "Domain User (USA)"

            }

            ElseIf($User.Citizenship -eq 1) {

                "Domain User"

            }
        )
        
        $firstnameTextBox.Text = $User.FirstName
        $middleinTextBox.Text = $User.MiddleIn
        $lastnameTextBox.Text = $User.LastName
        $organizationTextBox.Text = $User.Company
        $emailTextBox.Text = $User.Email
        $designationTextBox.Text = $Designation
        $departmentTextBox.Text = $User.Department
        $jobtitleTextBox.Text = $User.JobTitle
        $phoneTextBox.Text = $User.Phone
        $descriptionTextBox.Text = $Description
        $supervisoremailTextBox.Text =$User.SupervisorEmail
    })

    #Show Form
    $Form.ShowDialog() | Out-Null
}

function GUI {

    $Baloo = "\\SERVERa01\it\Documentation\BalooTrooper.png"
    $MyDocuments = [environment]::getfolderpath("mydocuments") + "\WindowsPowerShell\BalooTrooper.png"

    if(!(Test-Path $MyDocuments)) {
      
        Copy-Item "$Baloo" "$MyDocuments"
    }  

    Start-Process powershell.exe -argument '-NonInteractive -WindowStyle Hidden "CallGUI"'
}

function CallGUI { 

    $MyDocuments = [environment]::getfolderpath("mydocuments") + "\WindowsPowerShell\BalooTrooper.png"

#XML code for GUI objects
$inputXML = @"
<Window x:Class="BearNecessities.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:BearNecessities"
        mc:Ignorable="d"
        Title="Bear Necessities | v2.3" Height="510" Width="750" BorderBrush="#FF211414" Background="#FF6C6B6B" ResizeMode="CanMinimize" WindowStartupLocation="CenterScreen">
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
</Window>               
 
"@       
 
    $inputXML = $inputXML -replace 'mc:Ignorable="d"','' -replace "x:N",'N'  -replace '^<Win.*', '<Window' 
    [Void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
    [XML]$XAML = $inputXML
    $Reader=( New-Object System.Xml.XmlNodeReader $XAML )
    
    Try {

        $Form = [Windows.Markup.XamlReader]::Load( $reader )
    }

    Catch {

        Write-Host "Unable to load Windows.Markup.XamlReader. Double-check syntax and ensure .net is installed."
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

        $Stamp = (Get-Date -Format G) + ":"

        $SplitString = $inputTextBox.Text.Split(",")
        $SplitString = $SplitString.Trim()

        #Confirmation variables; prompt user
        $Caption = "Are you sure?"
        $Message = "All workstations listed will be restarted. Do you want to continue?"

        $Yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Yes"
        $No = New-Object System.Management.Automation.Host.ChoiceDescription "&No","No"

        $Choices = ([System.Management.Automation.Host.ChoiceDescription[]]($Yes,$No))

        $Answer = $host.ui.PromptForChoice($Caption,$Message,$Choices,1);

        #If NO, do nothing
        if($Answer -eq 1) {

	        $listBox.Items.Add("$Stamp Reboot(s) aborted!`n")
        }

        #If YES, execute Reboot
        elseif($Answer -eq 0) {

                Reboot $SplitString; $listBox.Items.Add("$Stamp Reboot initialized!`n")
	    }
    })

    #Ghost Button
    $ghostButton.Add_Click({

        $Stamp = (Get-Date -Format G) + ":"
        $SplitString = $inputTextBox.Text.Split(",")
        $SplitString = $SplitString.Trim()

        Ghost $SplitString 
        
        $listBox.Items.Add("$Stamp Ghost session opened!`n")

    })

    #HotFix Button
    $hotfixButton.Add_Click({

        $Stamp = (Get-Date -Format G) + ":"
        $listBox.Items.Add("Processing... please wait...`n")
        $SplitString = $inputTextBox.Text.Split(",")
        $SplitString = $SplitString.Trim()

        FindHotFixes $SplitString
    })

    #Certificates Button
    $invalidcertsButton.Add_Click({

        $Stamp = (Get-Date -Format G) + ":"
        $listBox.Items.Add("Processing... please wait...`n")
        $SplitString = $inputTextBox.Text.Split(",")
        $SplitString = $SplitString.Trim()

        CrossCertRm $SplitString
        $listBox.Items.Add("$Stamp Invalid certificates removed!`n")
    })

    #Printer Drivers Button
    $printdriversButton.Add_Click({

        $Stamp = (Get-Date -Format G) + ":"
        $SplitString = $inputTextBox.Text.Split(",")
        $SplitString = $SplitString.Trim()

        RmPrint $SplitString 
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
    $Form.ShowDialog() | Out-Null
}#EndGUI 
