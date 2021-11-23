######################################################################
######################################################################
######################################################################
#################################NOTES################################
######################################################################
######################################################################
######################################################################

<#
    Author Notes: The name and the methodology stems from a need to be
    able to conduct digital media forensics in austere enviornments. I 
    have tried to take various lessons I have learned the hard way and
    standardize the apporach for organizations needing an open source
    solution in areas that lack enterprise solutions. These techniques
    are not meant to replace such solutions like F-Response, KAPE,
    etc.  
#>

######################################################################
############################ PARAMETERS ##############################
######################################################################

<#
.SYNOPSIS

######################################################################
### AUTHOR:      s3raph                                            ###
### DATE:        07/01/2021                                        ###
### VERSION:     v.42 (Beta)                                       ###
### SYNOPSIS:    Battle Field Triage Script Meant To Standardize   ###
###              collection and initial analysis.                  ###
######################################################################

.DESCRIPTION

######################################################################
### SYNOPSIS:    Collection Starts Either Automated (With Switch), ###
###              manually (via CLI), or through the GUI. Triage    ###
###              begins with order of volitility once initial info ###
###              is collected.                                     ###
###              -> 0. Atomospherics.                              ###
###              -> 1. Memory.                                     ###
###              -> 2. Mandiant Redline Collector (Comprehensive). ###
###              -> 3. Forensic Triage Pull (Registry, EVTx, etc). ###
###              -> 4. Full Disk Collection.                       ###
######################################################################

.LINK

######################################################################
### GITHUB:     https://github.com/s3raph-x00/BattleField-Triage/  ###
######################################################################

.EXAMPLE
###########################################################################
# ./Battlefield_Triage.ps1 -env_verbose v -env_triage 3  -env_location ./ #
# [The Script]             [Verbose]      [Quick Triage] [Saves to ./]    #
###########################################################################

.EXAMPLE
###########################################################################
# ./Battlefield_Triage.ps1 -env_verbose q -env_triage 0  -env_location D:\#
# [The Script]             [Quiet]        [Full Triage]  [Saves to D:\]   #
###########################################################################

#>

param ($env_verbose, $env_triage, $env_location)
# env_verbose
    <# 
        Variables:   [v] = verbose 
                     [vv] = very verbose 
                     [q] = quiet
                     [ne] = quiet and no errors.
                     [null] = quiet

                     Default: [q] or quiet.

        Example:     ./Battlefield_Triage.ps1 -env_verbosity v

        Description: Specifies the verbosity of the script. 
    #>

# env_triage
    <# 
        Variables:   [0] = Pull All Possible Artifacts
                     [1] = Comprehensive (See Github)
                     [2] = Triage+ (Basics and More)
                     [3] = Triage (Basic Triage Pull)
                     [M] = Manual
                     [null] = Manual

                     Default is: [null] or Manual

        Example:     ./Battlefield_Triage.ps1 -env_speed 0

        Description: Associates Functions With Argument Values.

                     Prefetch: [3], [2], [1], [0]
                     Atmospherics: [3], [2], [1], [0]
                     Background Network Capture: [3], [2], [1], [0]
                     Full Memory Capture: [2], [1], [0]
                     Redline Collection: [3], [2], [1], [0]
                     Triage-Rip-Lite (WMI, Reg Queries, etc): [3], [2], [1], [0]
                     Triage-Rip-Normal (Lite + VSS, SHIMCACHE, AMCACHE, RDP_Bitmap): [2], [1], [0]
                     Triage-Rip-Full (Normal + ADS Detection, File Hash, and Hunting Techniques): [1], [0]
    #>

# env_location
    <# 
        Variables;   [File location in relative or full file path]
                     
                     Default is: [./] or where the script was run from.
                     
        Example:     ./Battlefield_Triage.ps1 -env_location ./
        Example:     ./Battlefield_Triage.ps1 -env_location D:\forensics

        Description: Specifies the location where the logs, forensic artifacts, and associated files will be saved. 
    #>

######################################################################
############################# VARIABLES ##############################
######################################################################

<# 
    The Error Action Preference Is Set This Way Inititaly As There Are
    Known Errors. This Cleans up the CLI Until The End Of The Initial 
    Configuration.
#> 

$ErrorActionPreference = 'silentlycontinue' 
$host                       ##This is You!
$console                    ##Used for UI
$colors                     ##Colors for UI
$voice                      ##I canz have talkng
$buffer                     ##Really?
$bckgrnd                    ##Background for UI
clear
$Seraph                     ##Banner
clear
function function_games
{
    Add-Type -AssemblyName System.speech
    $voice = New-Object System.Speech.Synthesis.SpeechSynthesizer
    $voice.SelectVoice(‘Microsoft Zira Desktop’)
    $voice.Speak("Dave, Do You Want To Play A Game?")
    $voice.Dispose()
    clear
}

######################################################################
############################## CONFIG ################################
######################################################################

$global:var_CollectionSizePlanTotal = 0

$host.UI.RawUI.BufferSize = new-object System.Management.Automation.Host.Size(175,20000)
$host.UI.RawUI.WindowSize = new-object System.Management.Automation.Host.Size(175,60)
$console.BufferSize = $buffer

$Host.UI.RawUI.BackgroundColor = ($bckgrnd = 'Black')
$Host.UI.RawUI.ForegroundColor = 'DarkGreen'

$Host.PrivateData.ConsolePaneForegroundColor = "Green"
$Host.PrivateData.ConsolePaneBackgroundColor= $bckgrnd
$Host.PrivateData.ConsolePaneTextBackgroundColor= "Black"

$console = $host.UI.RawUI
$colors = $host.PrivateData
$colors.VerboseForegroundColor = "White"
$colors.VerboseBackgroundColor = "Black"
$colors.WarningForegroundColor = "Yellow"
$colors.WarningBackgroundColor = "Black"
$colors.ErrorForegroundColor = "Black"
$colors.ErrorBackgroundColor = "Red"
$console.ForegroundColor = "Green"
$console.BackgroundColor = "Black"


######################################################################
############################## BANNER ################################
######################################################################

clear
$Seraph = 
"
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::      #######                                               /      ::
::    /       ###                                           #/       ::
::   /         ##                                           ##       ::
::   ##        #                                            ##       ::
::    ###                                                   ##       ::
::   ## ###           /##  ###  /###     /###       /###    ##  /##  ::
::    ### ###        / ###  ###/ #### / / ###  /   / ###  / ## / ### ::
::      ### ###     /   ###  ##   ###/ /   ###/   /   ###/  ##/   ###::
::        ### /##  ##    ### ##       ##    ##   ##    ##   ##     ##::
::          #/ /## ########  ##       ##    ##   ##    ##   ##     ##::
::           #/ ## #######   ##       ##    ##   ##    ##   ##     ##::
::            # /  ##        ##       ##    ##   ##    ##   ##     ##::
::  /##        /   ####    / ##       ##    /#   ##    ##   ##     ##::
:: /  ########/     ######/  ###       ####/ ##  #######    ##     ##::
::/     #####        #####    ###       ###   ## ######      ##    ##::
::|                                              ##                / ::
:: \)                                            ##               /  ::
::                                               ##              /   ::
::                                                ##            /    ::
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"

  $colour=("red","darkred","green","darkgreen","cyan","darkcyan","darkmagenta"."Red")
  [int]$num=-1
  
  $info = $Seraph -split "`n"
  Write-Host ""
  foreach($i in $info){
    [int]$perspective=($num / 5)
    write-host $i -foregroundcolor $colour[$perspective]
    $num++   
  }
    Write-Host ""
  Start-Sleep -s 3
  clear

######################################################################
################################ FIN #################################
######################################################################

function function_fin
{
echo "Done . . ."
pause -s 3


##The Following Posh Code was pulled from hxxps://poshcode.org/5289 but has been taken down
##It was ported by danielrehn@github
  $spacecowboy = "
  IC5kODg4OGI      uICA4ODg4ODg4ODg4I  Dg4ODg4ODg4ODggICA  gICBZO      DhiICA
  gZDg4UCAgLmQ     4ODg4OGIuICA4ODggI  CAgIDg4OA0KZDg4UCA  gWTg4Y      iA4ODg
  gICAgI  CAgIDg   4OCAgI      CAgICA  gICAgI              CAgWTg      4YiBkO
  DhQICB   kODhQI  iAiWTg      4YiA4O  DggICA              gIDg4O      A0KICJ
  ZODg4Y   i4gICA  4ODg4O      Dg4ICA  gIDg4O              Dg4ODg      gICAgI
  CAgICA   gICBZO  Dg4UCA      gICA4O  DggICA              gIDg4O      CA4ODg
  gICAgI   Dg4OA0  KICAgI      CJZODh  iLiA4O              DggICA      gICAgI
  Dg4OCA  gICAgI   CAgICA      gICAgI  CAgODg4ICAgICA4ODg  gICAgIDg4OCA4ODggI
  CAgIDg4OA0KI     CAgICA      gIjg4O  CA4ODggICAgICAgIDg  4OCAgICAgICAgICAgI
  CAgICAgODg       4ICAgI      CA4ODg              gICAgI  Dg4OCA      4ODggI
  CAgIDg4          OA0KWT      g4YiAg              ZDg4UC  A4ODgg      ICAgIC
  AgIDg4           OCAgIC      AgICAg              ICAgIC  AgICAg      ODg4IC
  AgICBZ           ODhiLi      AgZDg4              UCBZOD  hiLiAu      ZDg4UA
  0KICJZ           ODg4OF      AiICA4              ODg4OD  g4ODg4      IDg4OD
  g4ODg4           ODggICAgICAgICAgOD  g4ICAgICAgIlk4ODg4  OFAiIC      AgIlk4
  ODg4OF           AiDQogLmQ4ODg4Yi4g  IDg4ODg4ODhiLiAgIC  AgZDg4      ODggIC
  
  
  5kODg4OGIuICA4O  Dg4ODg4ODg4DQpkODh  wICBZODhiID      g4OCAgIFk4OGIgICBk
  ODg4ODggZDg4UCA  gWTg4YiA4ODgNCiAiW  Tg4OGIuICAgO     Dg4ICAgZDg4UCBkODh
  QIDg4O           CA4ODg      gICAgI  CAgIDg  4ODg4O   DgNCiA             
  gICAiW           Tg4Yi4      gODg4O  Dg4OFA   iIGQ4O  FAgIDg            
  4OCA4O           DggICA      gICAgI  Dg4OA0   KICAgI  CAgIjg            
  4OCA4O           DggICA      gICBkO  DhQICA   gODg4I  Dg4OCA            
  gICA4O           DggODg      4DQpZO  DhiICB   kODhQI  Dg4OCA            
  gICAgZ           Dg4ODg      4ODg4O  DggWTg   4YiAgZ  Dg4UCA4ODgNCiAiWTg
  4ODhQI           iAgODg      4ICAgI  GQ4OFA   gICAgI  Dg4OCAgIlk4ODg4UCI
  gIDg4O           Dg4ODg      4ODgNC  iAuZDg   4ODhiL  iAgIC5            
  kODg4O           DhiLiA      gODg4I  CAgICA   gIDg4O  CA4ODg            
  4ODhiL           iAgICA      uZDg4O  Dg4Yi4   gWTg4Y  iAgIGQ            
  4OFANC           mQ4OFA      gIFk4O  GIgZDg   4UCIgI  lk4OGI            
  gODg4I           CAgbyA      gIDg4O  CA4ODg  gICI4O   GIgIGQ            
  4OFAiICJZODhiIF  k4OGIgZDg4UA0KODg4  ICAgICAgICA4     ODggICAgIDg4OCA4OD
  ggZDg4OGIgODg4I  Dg4ODg4ODhLLiAgODg  4ICAgICA4OD      ggICBZODg4UA0KODg4
  
  ICAgICAgICA4ODggICAgIDg4OCA4ODg4ODg4ODg4ODg4IDg4OCAgIlk4OGIgODg4ICAgICA4
   ODggICAgODg4DQo4ODggICAgODg4IDg4OCAgICAgODg4IDg4ODg4UCBZODg4ODggODg4IC
    AgIDg4OCA4ODggICAgIDg4OCAgICA4ODgNClk4OGIgIGQ4OFAgWTg4Yi4gLmQ4OFAgOD
     g4OFAgICBZODg4OCA4ODggICBkODhQIFk4OGIuIC5kODhQICAgIDg4OA0KICJZODg4
      OFAiICAgIlk4ODg4OFAiICA4ODhQICAgICBZODg4IDg4ODg4ODhQIiAgICJZODg4
                            ODhQIiAgICAgODg4
  " -join "`n"
  
  $colour=("red","yellow","darkyellow","green","cyan","darkcyan","darkmagenta")
  [int]$num=-1
  
  $bytes  = [System.Convert]::FromBase64String($spacecowboy)
  $info = [System.Text.Encoding]::UTF8.GetString($bytes) -split "`n"
  Write-Host ""
  foreach($i in $info){
    [int]$perspective=($num / 3)
    write-host $i -foregroundcolor $colour[$perspective]
    $num++   
  }
start-sleep -Seconds 3
break
}

function function_failwhale
{
    if ($env_verbose -eq "V")
    {
        write-host -fore Red -back black "▄██████████████▄▐█▄▄▄▄█▌"
        write-host -fore Red -back black "██████▌▄▌▄▐▐▌███▌▀▀██▀▀"
        write-host -fore Red -back black "████▄█▌▄▌▄▐▐▌▀███▄▄█▌"
        write-host -fore Red -back black "▄▄▄▄▄██████████████"
        pause
    }
}

######################################################################
############################## WARNING ###############################
######################################################################

function function_Agreement
{
    $agreement1string = "[PROMPT] Do You Accept Responsibility For Using This Script And Have Appropriate Permission For Use?"
    write-host -fore white -back black $agreement1string
    $agreement1 = Read-Host -Prompt '[Yes/No]'
    if ($agreement1 -eq "Yes")
    {
        write-host -fore Gray -back black "\x90\x52\x65\x6d\x65\x6d\x62\x65\x72\x20\x77\x69\x74\x68\x20\x47\x72"
        write-host -fore Gray -back black "\x65\x61\x74\x20\x50\x6f\x77\x65\x72\x20\x63\x6f\x6d\x65\x73\x20\x74"
        write-host -fore Gray -back black "\x68\x65\x20\x61\x62\x69\x6c\x69\x74\x79\x20\x74\x6f\x20\x62\x72\x65"
        write-host -fore Gray -back black "\x61\x6b\x20\x61\x20\x6c\x6f\x74\x20\x6f\x66\x20\x73\x68\x69\x74\x21"
        pause -s 3
        function_InherentScriptLogging
    }
    if ($agreement1 -eq "No")
    {
        write-host -fore Gray -back black "[INFO] Ending Stack Now"
        pause -s 3
        clear
        function_fin
    }
    if ($agreement1 -eq "exit")
    {
        write-host -fore Gray -back black "[INFO] Ending Stack Now"
        pause -s 3
        clear
        function_fin
    }
    else
    {
        write-host -fore Red -back black "$agreement1 is not a valid response."
        write-host -fore Red -back black "[ERROR] Response must be either a Yes or No"
        function_failwhale
        clear
        function_Agreement
    }
}

######################################################################
############################## PREAMP ################################
######################################################################

function function_InherentScriptLogging
{
    $ScriptStartDate = Get-Date –f "D-(yyyy-MM-dd)_T-(HH-mm-ss)"
    $ScriptStartTime = Get-Date –f "HH-mm-ss"
    $CollectionDate = Get-Date –f "yyyy-MM-dd"
    $Prompt_Script_LocationString = "[PROMPT] Do You Want To Specify Where to Store Logs and Forensic Artifacts?"
    write-host -fore white -back black $Prompt_Script_LocationString 
    $Prompt_Script_Location = Read-Host -Prompt '[Yes/No]'
    if ($Prompt_Script_Location -eq "YES")
    {
        $string_fileoutputdir = '[PROMPT] Input the Directory to store logs'
        $fileoutputdir = Read-Host -Prompt "(i.e. Press [Enter] for the Current Directory './' or enter your choice: C:/Users/Administrator/Desktop)"
        $fileoutputdirbool = [string]::IsNullOrEmpty($fileoutputdir)
        write-host -fore Gray -back Black $fileoutputdir 
        if ($fileoutputdirbool -eq $False)
        {
            write-host -fore Gray -back black "[INFO] Finished with Directory Input, beginning to create file structure"
                $var_Saved_File_Output_Script_Start = $fileoutputdir + "/" + $CollectionDate + "/" + $ScriptStartTime + "/"
                $var_Saved_File_Output_Script_Start_bool = Test-Path $var_Saved_File_Output_Script_Start
                if ($var_Saved_File_Output_Script_Start_bool -eq $False)
                {
                    mkdir $var_Saved_File_Output_Script_Start -ErrorAction SilentlyContinue
                }
                function_InherentScriptingLogName_Check

        }
        if ($fileoutputdirbool -eq $True)
        {
            $fileoutputdir = "./"
            write-host -fore Gray -back Black "[INFO] Finished with Directory Input, beginning to create file structure"
                $var_Saved_File_Output_Script_Start = $fileoutputdir + "/" + $CollectionDate + "/" + $ScriptStartTime + "/"
                $var_Saved_File_Output_Script_Start_bool = Test-Path $var_Saved_File_Output_Script_Start
                if ($var_Saved_File_Output_Script_Start_bool -eq $False)
                {
                    mkdir $var_Saved_File_Output_Script_Start -ErrorAction SilentlyContinue
                }
                function_InherentScriptingLogName_Check
        }
    }

    if ($Prompt_Script_Location -eq "NO")
    {
        $fileoutputdir = "./"
        write-host -fore Gray -back Black "[INFO] Finished with Directory Input, beginning to create file structure"
            $var_Saved_File_Output_Script_Start = $fileoutputdir + "/" + $CollectionDate + "/" + $ScriptStartTime + "/"
            $var_Saved_File_Output_Script_Start_bool = Test-Path $var_Saved_File_Output_Script_Start
            if ($var_Saved_File_Output_Script_Start_bool -eq $False)
            {
                mkdir $var_Saved_File_Output_Script_Start -ErrorAction SilentlyContinue
            }
            function_InherentScriptingLogName_Check
    }
}

function function_InherentScriptingLogName_Check
{
    $var_Saved_File_Output_Script_Start_bool = Test-Path $var_Saved_File_Output_Script_Start
    if ($var_Saved_File_Output_Script_Start_bool -eq $True)
    {
        function_InherentScriptingLogName
    }
    else
    {
        write-host -back black -fore red "[ERROR] Directory:"  $fileoutputdir " was not created, going back to prompt. Check Permissions and/or User Input."
        function_failwhale
        pause
        clear
        function_InherentScriptLogging
    }
}


function function_InherentScriptingLogName
{
    $computername = $env:COMPUTERNAME
    $SavedLogs = $ScriptStartTime + "_" + $computername
    $string_ISLN_log = "[INFO] Starting Script on: " + $ScriptStartDate + " (Date:yyyy-MM-dd)_(Time:HH-mm-ss)"
    write-host -fore Gray -back Black $string_ISLN_log
    try
    {
        $SavedLogFile = $CollectionDate + "\" + $SavedLogs
        write-host -fore Black -back White "-----------Logging Enabled----------"
        echo "-----------Logging Enabled----------" >> $SavedLogFile
        echo "[INFO] Starting Script on $ScriptStartDate (Date:yyyy-MM-dd)_(Time:HH-mm-ss)" >> $SavedLogFile
        try
        {
            $SavedTemp = $SavedLogs + "_tmp"
            $StoredVariables = $SavedLogs + "_var"
            $StoredForensicLocation = "./" + $CollectionDate + "\" + $ScriptStartTime + "\"
            $StoredSelecteDrive = $SavedLogs + "_driveplan"
            $SavedVarFile = $CollectionDate + "\" + $ScriptStartTime + "\" + $StoredVariables
            $SavedInitialFile = $CollectionDate + "\" + $ScriptStartTime + "\" + $computername + "_Initial_Collect.txt"
            $SavedVarFTKFile = $CollectionDate + "\" + $ScriptStartTime + "\" + $StoredVariables + "_ftk"
            $SavedTempFile = $CollectionDate + "\" + $ScriptStartTime + "\" + $SavedTemp
            $SavedSelectedDrive = $CollectionDate + "\" + $ScriptStartTime + "\" + $StoredSelecteDrive
            $StoredTimeHack = $CollectionDate + "\" + "var_timehack"
            cmd.exe /c echo $ScriptStartTime > $StoredTimeHack
            clear
            function_Artifact_Storage_TARTARUS
        }
        catch
        {
            write-host -fore Red -back black "[ERROR] Failed to save into temp file, check permissions"
            function_failwhale
            clear
        }
    }
    catch
    {
        write-host -fore Red -back black "[ERROR] Failed to save into log file, check permissions"
        function_failwhale
        clear
    }
}

function function_Artifact_Storage_TARTARUS
{
    $SavedForensicArtifacts = $fileoutputdir + "\" + $CollectionDate + "\" + $ScriptStartTime + "\" + "Artifacts\"
    try
    {
        $var_SavedForensicArtifactsbool = Test-Path $SavedForensicArtifacts
        if ($var_SavedForensicArtifactsbool -eq $FALSE)
        {
            mkdir $SavedForensicArtifacts
        }
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $SavedForensicArtifacts
    }

    $SavedForensicArtifactsCSV = $SavedForensicArtifacts + "\CSV\"
    try
    {
        $var_SavedForensicArtifactsbool_CSV = Test-Path $SavedForensicArtifactsCSV
        if ($var_SavedForensicArtifactsbool_CSV -eq $FALSE)
        {
            mkdir $SavedForensicArtifactsCSV
        }
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $SavedForensicArtifactsCSV
    }
    
    $SavedForensicArtifactsJSON = $SavedForensicArtifacts + "\JSON\"
    try
    {
        $var_SavedForensicArtifactsbool_JSON = Test-Path $SavedForensicArtifactsJSON
        if ($var_SavedForensicArtifactsbool_JSON -eq $FALSE)
        {
            mkdir $SavedForensicArtifactsJSON
        }
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $SavedForensicArtifactsJSON                
    }

    $SavedForensicArtifactsXML = $SavedForensicArtifacts + "\XML\"
    try
    {
        $var_SavedForensicArtifactsbool_XML = Test-Path $SavedForensicArtifactsXML
        if ($var_SavedForensicArtifactsbool_XML -eq $FALSE)
        {
            mkdir $SavedForensicArtifactsXML
        }
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $SavedForensicArtifactsXML
    }

    $SavedForensicArtifactsWMI = $SavedForensicArtifacts + "\WMI\"
    try
    {
        $var_SavedForensicArtifactsbool_WMI = Test-Path $SavedForensicArtifactsWMI
        if ($var_SavedForensicArtifactsbool_WMI -eq $FALSE)
        {
            mkdir $SavedForensicArtifactsWMI
        }
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $SavedForensicArtifactsWMI
    }

    $SavedForensicArtifactsTasks = $SavedForensicArtifacts + "\Tasks\"
    try
    {
        $var_SavedForensicArtifactsbool_Tasks = Test-Path $SavedForensicArtifactsTasks
        if ($var_SavedForensicArtifactsbool_Tasks -eq $FALSE)
        {
            mkdir $SavedForensicArtifactsTasks
        }
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $SavedForensicArtifactsTasks
    }

    $StoredForensicLocationNET = $StoredForensicLocation + "\Net\"
    try
    {
        $var_SavedForensicArtifactsbool_NET = Test-Path $StoredForensicLocationNET
        if ($var_SavedForensicArtifactsbool_NET -eq $FALSE)
        {
            mkdir $StoredForensicLocationNET
        }
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $StoredForensicLocationNET
    }

    $StoredForensicLocationWBEM = $StoredForensicLocation + "\WBEM\"
    try
    {
        $var_SavedForensicArtifactsbool_BEM = Test-Path $StoredForensicLocationWBEM
        if ($var_SavedForensicArtifactsbool_BEM -eq $FALSE)
        {
            mkdir $StoredForensicLocationWBEM
        }
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $StoredForensicLocationNET
    }

    function_Initial_Collect
}

##########################################################################################
##########################################################################################
################################# INFO GATHERING #########################################
##########################################################################################
##########################################################################################

function function_Initial_Collect
{
    Function_RIP_Prefetch_and_Network
    function_SystemInfoGathering
}

##########################################################################################
############################### System Fingerprinting ####################################
##########################################################################################

function function_SystemInfoGathering
{
    write-host -fore Black -back White "-----Gathering System Information-----"
    echo "-----Gathering System Information-----" >> $SavedLogFile
    $var_ComputerName = $env:COMPUTERNAME
    $var_ComputerNameString = "[SYS] The Computer Name is: " + $var_ComputerName
    $var_UserDomain = $env:USERDOMAIN
    $var_LogonServer = $env:LOGONSERVER ## Local or Domain
    $var_LogonServerFix = $var_LogonServer|Where{$_ -ne ""}|ForEach{$_.Replace("\\","\")}
    $var_LogonServerCompare = $var_LogonServer|Where{$_ -ne ""}|ForEach{$_.Replace("\","")}
    if($var_LogonServerCompare -ne $var_UserDomain)
    {
        $var_LogonServerString = "[SYS] The Logon Server is [Domain\Server]: " + $var_UserDomain + $var_LogonServer
    }
    else
    {
        $var_LogonServerString = "[SYS] The Logon Server is the Local System (i.e.): " + $var_LogonServerCompare
    }
    $var_SessionName = $env:SESSIONNAME
    $var_SessionNameString = "[SYS] The Session Name and/or Type is: " + $var_SessionName ## Console
    $var_UserName = $env:USERNAME
    $var_UserString = "[SYS] The User This Script is Running Under is [Domain\Username]: " + $var_UserDomain + "\" + $var_UserName
    write-host -fore Gray -back black "[INFO] Finished Gathering Basic System Info"
    echo "[INFO] Finished Gathering Basic System Info" >> $SavedLogFile

    write-host -fore Gray -back Black "[INFO] Checking Primary Windows Directory"
    echo "[INFO] Checking Primary Windows Directory" >> $SavedLogFile
    try
    {
        $windirlocation = (Get-CIMInstance -ClassName CIM_OperatingSystem).WindowsDirectory
        $windirlocationoutput = "[INFO] Windows is installed at the following location: " + $windirlocation
        write-host -fore Gray -back Black $windirlocationoutput
        echo $windirlocationoutput >> $SavedLogFile
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Could Not Pull Windows Location, Defaulting to: C:\Windows"
        echo "[WARN] Could Not Pull Windows Location, Defaulting to: C:\Windows" >> $SavedLogFile
        $windirlocation = "C:\windows"
    }

    write-host -fore Black -back White "------Logging System Information------"
    echo "------Logging System Information------" >> $SavedLogFile
    $var_SessionNameString >> $SavedLogFile
    $var_LogonServerString >> $SavedLogFile
    $var_ComputerNameString >> $SavedLogFile
    $var_UserString >> $SavedLogFile
    function_ProcessorInfoGathering
}

##########################################################################################
############################## Processor Fingerprinting ##################################
##########################################################################################

function function_ProcessorInfoGathering
{
    write-host -fore Black -back White "---Gathering Processor Information---"
    echo "---Gathering Processor Information---" >> $SavedLogFile
    $var_processor_arch = $env:PROCESSOR_ARCHITECTURE ## AMD64
    $var_processor_identifier = $env:PROCESSOR_IDENTIFIER ## Intel64 Family 6 Model 94 Stepping 3, GenuineIntel
    $var_processor_revision = $env:PROCESSOR_REVISION ## 5e03
    $var_processor_arch_string = "[SYS] Processor Arch is: " + $var_processor_arch
    $var_processor_identifier_string = "[SYS] Processor ID is: " + $var_processor_identifier
    $var_processor_revision_string = "[SYS] Processor Revision is: " + $var_processor_revision
    write-host -fore Gray -back black "[INFO] Finished Gathering Processor Info"
    echo "[INFO] Finished Gathering Processor Info" >> $SavedLogFile    

    
    write-host -fore Black -back White "----Logging Processor Information----" 
    echo "----Logging Processor Information----" >> $SavedLogFile
    $var_processor_arch_string >> $SavedLogFile
    $var_processor_identifier_string >> $SavedLogFile
    $var_processor_revision_string >> $SavedLogFile
    Function_Get-OSVersionMain
}


##########################################################################################
############################# O/S Version Fingerprinting #################################
##########################################################################################

Function Function_Get-OSVersionMain
{
clear
write-host -fore Black -back White "------Gathering O/S Information------"
echo "------Gathering O/S Information------" >> $SavedLogFile
    try
    {
        Function_Get-OSVersionFull
        $osfull = [System.BitConverter]::GetBytes((Function_Get-OSVersionFull)::GetVersion())
        $MajorRelease = $osfull[0]
        $MinorRelease = $osfull[1]
        $OSBuild = [byte]$osfull[2],[byte]$osfull[3]
        $OSBuildNumber = [System.BitConverter]::ToInt16($OSBuild,0)
        $FullVersionText = "[OS] O/S Version is {0}.{1}, build {2}" -F $MajorRelease,$MinorRelease,$OSBuildNumber
        $FullVersionText >> $SavedLogFile
        Function_Get-TotalMemoryPlan
    }
    catch
    {
        write-host -fore Yellow -back black "[WARN] Could Not Pull Full O/S Version, Attempting to get O/S info a different way."
        echo "[WARN] Could Not Pull Full O/S Version, Attempting to get O/S info a different way." >> $SavedLogFile  
        Function_Get-OSVersionLite
    }
}

Function Function_Get-OSVersionLite
{
    try
    {
        $OSBasic = $env:OS ## Windows_NT
        $OSv1 = [environment]::OSVersion.Version
        Function_Get-TotalMemoryPlan
    }
    catch
    {
        write-host -fore Red -back black "[ERROR] Could Not Pull O/S Version"
        echo "[ERROR] Could Not Pull O/S Version" >> $SavedLogFile
        function_failwhale
        clear
        Function_Get-TotalMemoryPlan
    }
}

### Pulled and Modified From: https://devblogs.microsoft.com/scripting/use-powershell-to-find-operating-system-version/ by Dr. Scripto ###
Function Function_Get-OSVersionFull
{
    try
    {
    $getosfull = @"
    [DllImport("kernel32.dll")]
    public static extern uint GetVersion();
"@
    Add-Type -MemberDefinition $getosfull -Name "Win32OSVersion" -Namespace Win32Functions -PassThru
    }
    catch
    {
        Function_Get-OSVersionLite
    }
}


##########################################################################################
################################### Memory Collection ####################################
##########################################################################################

Function Function_Get-TotalMemoryPlan
{
    echo "-----Gathering Memory Information----" >> $SavedLogFile
    $var_total_memory = 0
    $var_total_memory_wmi = (get-wmiobject -Class "win32_physicalmemory" -Namespace "root\CIMv2").capacity
    $iteration = 0
    foreach ($var_memorymodule in $var_total_memory_wmi)
    {
        if ($iteration -le 1)
        {
        $var_total_memory = $var_total_memory + ($var_total_memory_wmi[$iteration] / 1024)
        $iteration++
        }
    }
    if ($var_total_memory -gt 0)
    {
        clear
        $var_total_memory_GB = [int]$var_total_memory / 1048576
        $var_string_total_memory_plan = "[INFO] Size of System Memory Is: " + $var_total_memory_GB + ". Do You Wish To Do A Memory Capture?"
        $var_string2_total_memory_plan = "[MEM] Size of System Memory Is: " + $var_total_memory_GB + "GBs." >> $SavedLogFile
        $var_MemoryCollectionPlanPromptText = "[PROMPT] Do You Wish to Pull a Memory Image of the System Now [Yes|No]? This will take at least: " + $var_total_memory_GB + "GBs in the " + "directory."
        write-host -fore White -back black $var_MemoryCollectionPlanPromptText
        $var_MemoryCollectionPlanPrompt = Read-Host -Prompt "[Yes/No]"

        if ($var_MemoryCollectionPlanPrompt -eq "YES")
        {
            $var_memory_capture_location = $StoredForensicLocation + $var_ComputerName + "_mem"
            Function_MemoryCollectionTools
        }
        if ($var_MemoryCollectionPlanPrompt -eq "NO")
        {
            write-host -fore Gray -back black "[INFO] Skipping Memory Collection."
            echo "[INFO] Skipping Memory Collection." >> $SavedLogFile
            Function_RedLineCollectorPrompt
        }
        if ($var_MemoryCollectionPlanPrompt -ne "No")
        {
            if ($var_MemoryCollectionPlanPrompt -ne "Yes")
            {
            write-host -fore Red -back Black "[ERROR] Your Response was not YES or NO"
            echo "[ERROR] Your Response was not YES or NO"
            function_failwhale
            clear
            Function_Get-TotalMemoryPlan
            }
        }            
    }
    else
    {
        clear
        function_failwhale
        write-host -fore Red -back black "[ERROR] Could Not Pull Memory Capacity"
        echo "[ERROR] Could Not Pull Memory Capacity" >> $SavedLogFile
        write-host -fore Gray -back black "[INFO] Skipping Memory Collection."
        echo "[INFO] Skipping Memory Collection." >> $SavedLogFile
        Start-Sleep -s 2
        Function_RedLineCollectorPrompt
        clear
    }
}

Function Function_MemoryCollectionTools
{
    write-host -fore Gray -back black "[INFO] Attempting to Start Memory Collection Tools."
    echo "[INFO] Attempting to Start Memory Collection Tools." >> $SavedLogFile

    try
    {
        try
        {
            try
            {
                $succeed = 0
                write-host -fore Gray -back black "[MEM] Attempting to Spawn Winpmem now, please be patient."
                echo "[MEM] Attempting to Spawn Winpmem now, please be patient." >> $SavedLogFile
                #$filename = $StoredForensicMEMLocation + "\" + $ScriptStartTime + "_mem.aff4"

                echo $memoryfilenameprint
                echo $memoryfilenameprint >> $SavedLogFile
                $StoredForensicMEMLocation = $StoredForensicLocation + "\Memory\" 
                try
                {
                    mkdir $StoredForensicMEMLocation
                }
                catch
                {
                    write-host -back black -fore yellow "[WARN] Stored Memory Location Was Either Already Existed or Could Not Be Created."
                }
                $StoredForensicMEMLocationPMEM = $StoredForensicLocation + "\Memory\" + $ScriptStartTime + "_" + $var_ComputerName + "_mem.aff4"
                $memoryfilenameprint = "[MEM] The memory capture file from winpmem is: " + $StoredForensicMEMLocationPMEM
                $var_pagefileexists = ""
                $var_pagefileexistsbool = Test-Path C:\pagefile.sys
                if ($var_pagefileexistsbool -eq $TRUE)
                {
                    $var_pagefileexists = " -p C:\pagefile.sys "
                }
                cmd.exe /c start ./src/winpmem/winpmem.exe $var_pagefileexists -o $StoredForensicMEMLocationPMEM | Out-Null
                $var_winpmemfilezie = (Get-ChildItem $StoredForensicMEMLocationPMEM | % {[int]($_.Length)}) / 1048576
                $var_testfilesizeagainst = ([int]$var_total_memory * .66) / 1024
                if ([int]$var_testfilesizeagainst -lt [int]$var_winpmemfilezie)
                {
                    write-host -fore Gray -back black "[INFO] File Size is Greater Than 66% of Total Memory, winpmem likely succeeded."
                    echo "[INFO] File Size is Greater Than 66% of Total Memory, winpmem likely succeeded." >> $SavedLogFile
                    [int]$succeed = 1
                    if ([int]$succeed -eq 1)
                    {
                        Function_RedLineCollectorPrompt
                    }
                }
                if ([int]$var_testfilesizeagainst -gt [int]$var_winpmemfilezie)
                {
                    write-host -back black -fore yellow "[WARN] File Size is Less Than 66% of Total Memory, winpmem likely failed."
                    echo "[WARN] File Size is Less Than 66% of Total Memory, winpmem likely failed." >> $SavedLogFile
                    [int]$succeed = 0
                    $failme = 1 / 0
                }
            }
            catch
            {
                write-host -back black -fore yellow "[WARN] Unspecified Error Occured, winpmem could have failed."
                echo "[WARN] Unspecified Error Occured, winpmem could have failed." >> $SavedLogFile
                [int]$succeed = 0
                if ([int]$succeed -eq 0)
                {
                    write-host -fore Gray -back black "[MEM] Attempting to Spawn Surge-Collect now, please be patient."
                    echo "[MEM] Attempting to Spawn Surge-Collect now, please be patient." >> $SavedLogFile
                    cmd.exe /c start ./src/surge/surge-collect.exe gravityoutput $StoredForensicMEMLocation
                    [int]$succeed = 1
                    if ([int]$succeed -eq 1)
                    {
                        Function_RedLineCollectorPrompt
                    }
                }
                if ([int]$succeed -eq 1)
                {
                    Function_RedLineCollectorPrompt
                }
            }
        }
        catch
        {
            write-host -back black -fore yellow "[WARN] Unspecified Error Occured, winpmem and Surge Collect could have failed."
            echo "[WARN] Unspecified Error Occured, winpmem and Surge Collect could have failed." >> $SavedLogFile
            $var_os_arch_mem_info_dump_decision = gwmi win32_operatingsystem | select osarchitecture -ExpandProperty osarchitecture

            if ($var_os_arch_mem_info_dump_decision -eq "64-bit")
            {
                write-host -fore Red -back black "[INFO] Starting RamCapture (64-bit) now, please be patient."
                echo "[INFO] Starting RamCapture now, please be patient." >> $SavedLogFile
                $var_RamCapture64 = ./src/RamCapture/x64/RamCapture64.exe
                cmd.exe /c start $var_RamCapturex64
                Function_Get-DiskInfoMain
            }
            if ($var_os_arch_mem_info_dump_decision -eq "32-bit")
            {
                write-host -fore Red -back black "[INFO] Starting RamCapture (32-bit) now, please be patient."
                echo "[INFO] Starting RamCapture now, please be patient." >> $SavedLogFile
                $var_RamCapture86 = ./src/RamCapture/x86/RamCapture86.exe
                cmd.exe /c start $var_RamCapturex86
                Function_Get-DiskInfoMain
            }
        }
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Unspecified Error Occured, winpmem, RamCapture and Surge Collect could have failed."
        echo "[WARN] Unspecified Error Occured, winpmem, RamCapture and Surge Collect could have failed." >> $SavedLogFile
        write-host -fore Red -back black "[INFO] Starting Memoryze now, please be patient."
        $StoredForensicMEMLocationMemoryze = $StoredForensicLocation + "\Memory\" + $ScriptStartTime + "_" + $var_ComputerName + "_ryzed_mem.raw"
        echo "[INFO] Starting Memoryze now, please be patient." >> $SavedLogFile
        $var_Memoryze = "./src/memoryze/MemoryDD.bat"
        start $var_Memoryze -o $StoredForensicMEMLocationMemoryze
        Function_Get-DiskInfoMain
    }
    Function_Get-DiskInfoMain
}

Function Function_Get-TotalMemoryPlanMain
{
    clear
    Function_Get-TotalMemoryPlan
}

##########################################################################################
################################### Red Line Collector ###################################
##########################################################################################

Function Function_RedLineCollector
{
    try
    {
        write-host -fore Gray -back black "[REDLINE] Mandiant Red Line Collector is About to Spawn."
        echo "[REDLINE] Mandiant Red Line Collector is About to Spawn." >> $SavedLogFile
        start ./src/man/RunRedlineAudit.bat -wait -NoNewWindow
        Function_RIP_TRIAGE_MAIN
    }
    catch
    {
        write-host -back black -fore yellow "[REDLINE] Mandiant Red Line Collector Appears To Have Failed"
        echo "[REDLINE] Mandiant Red Line Collector Appears To Have Failed" >> $SavedLogFile
        Function_RIP_TRIAGE_MAIN
    }
}

Function Function_RedLineCollectorPrompt
{
    clear
    echo "------Starting Red Line Collection-----" >> $SavedLogFile
    $var_CollectionPlanPromptText = "[PROMPT] Do You Wish to Pull a Mandiant Red Line Collection of the Device?"
    write-host -fore White -back black $var_CollectionPlanPromptText
    $var_CollectionPlanPrompt = Read-Host -Prompt "[Yes/No]"

    if ($var_CollectionPlanPrompt -eq "YES")
    {
        Function_RedLineCollector
    }
    if ($var_CollectionPlanPrompt -eq "NO")
    {
        write-host -fore Gray -back black "[INFO] Skipping Red Line Collection, Moving to Disk Collection Stage"
        echo "[INFO] Skipping Red Line Collection, Moving to Disk Collection Stage"  >> $SavedLogFile
        Function_RIP_TRIAGE_MAIN
    }
    if ($var_CollectionPlanPrompt -ne "YES")
    {
        if ($var_CollectionPlanPrompt -ne "No")
        {
        write-host -fore Red -back black "[ERROR] Your Response was not YES or NO"
        function_failwhale
        clear
        function_CollectionPlanPrompt
        }
    }            
}

##########################################################################################
################################# Forensic Artifact Pull #################################
##########################################################################################

################################### QUICK(ish) COMMANDS ##################################

Function Function_RIP_Prefetch_and_Network
{
    try
    {
        $vartempstring = "[TRIAGE] Starting Initial Host Triage Information Collection."
        write-host -fore Gray -back black $vartempstring
        $vartempstring >> $SavedLogFile

        write-host -fore Black -back White "[TRIAGE] Starting Starting Network Trace"
        echo "[TRIAGE] Starting Starting Network Trace" >> $SavedInitialFile
        echo $string_ISLN_log >> $SavedInitialFile

        $var_networkETLcapturetrace = $StoredForensicLocationNET + $computername + "_Network_Collect.etl"
        netsh trace start capture=yes tracefile=$var_networkETLcapturetrace persistent=yes maxsize=4096

        write-host -fore Black -back White "-----Gathering Initial Information-----"
        echo "-----Gathering Initial Information-----" >> $SavedInitialFile
        echo $string_ISLN_log >> $SavedInitialFile
        $var_ComputerName = $env:COMPUTERNAME
        $var_ComputerNameString = "[SYS] The Computer Name is: " + $var_ComputerName
        echo $var_ComputerNameString >> $SavedInitialFile
        echo "" >> $SavedInitialFile
        write-host -fore Black -back White "-----Gathering Network State Information-----"
        echo "-----Gathering Network State Information-----" >> $SavedInitialFile
        echo "-----NETSTAT Output-----" >> $SavedInitialFile
        netstat -natqo >> $SavedInitialFile
        echo "" >> $SavedInitialFile
        echo "-----ARP Cache Output-----" >> $SavedInitialFile
        echo "" >> $SavedInitialFile
        arp -a >> $SavedInitialFile
        echo "" >> $SavedInitialFile
        echo "-----TASKLIST Output-----" >> $SavedInitialFile
        tasklist /v >> $SavedInitialFile
        echo "" >> $SavedInitialFile
        echo "-----TASKLIST/SVC Output-----" >> $SavedInitialFile
        tasklist /svc >> $SavedInitialFile
        echo "" >> $SavedInitialFile
        echo "-----Service Output-----" >> $SavedInitialFile
        get-service -Verbose | Format-List * >> $SavedInitialFile
        # HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory
        # Get-ChildItem C:\Windows\Prefetch 
    }
    catch
    {
        $vartempstring = "[ERROR] Failed To Pull Initial Host Triage Information."
        write-host -fore Red -back black $vartempstring
        $vartempstring >> $SavedLogFile
        function_failwhale
        clear
    }
}

Function Function_RIP_TRIAGE
{
    ##### HOST INFO #####
    try
    {
        $vartempstring = "[TRIAGE] Starting Host Triage Information Collection."
        write-host -fore Gray -back black $vartempstring
        $vartempstring >> $SavedLogFile

        $var_InfoWin32_OptionalFeature_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_OptionalFeature.csv"      
        Get-WMIObject -Class Win32_OptionalFeature -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_OptionalFeature_csv

        $var_InfoLocalTime_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_LocalTime.csv"
        Get-WMIObject -Class Win32_LocalTime -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoLocalTime_csv

        $var_InfoTimeZone_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_TimeZone.csv"
        Get-WMIObject -Class Win32_TimeZone -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoTimeZone_csv

        $var_InfoComputerSystem_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_ComputerSystem.csv"
        Get-WMIObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoComputerSystem_csv

        $var_InfoOperatingSystem_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_OperatingSystem.csv"
        Get-WMIObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoOperatingSystem_csv

        $var_InfoSystemSetting_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_SystemSetting.csv"
        Get-WMIObject -Class Win32_SystemSetting -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoSystemSetting_csv

        $var_InfoSystemSlot_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_SystemSlot.csv"
        Get-WMIObject -Class Win32_SystemSlot -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoSystemSlot_csv

        $var_InfoSystemServices_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_SystemServices.csv"
        Get-WMIObject -Class Win32_SystemServices -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoSystemServices_csv

        $var_InfoSystemResources_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_SystemResources.csv"
        Get-WMIObject -Class Win32_SystemResources -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoSystemResources_csv

        $var_InfoSystemLoadOrderGroups_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_SystemLoadOrderGroups.csv"
        Get-WMIObject -Class Win32_SystemLoadOrderGroups -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoSystemLoadOrderGroups_csv

        $var_InfoSystemDevices_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_SystemDevices.csv"
        Get-WMIObject -Class Win32_SystemDevices -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoSystemDevices_csv

        $var_InfoSystemDesktop_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_SystemDesktop.csv"
        Get-WMIObject -Class Win32_SystemDesktop -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoSystemDesktop_csv

        $var_InfoSystemConfigurationChangeEvent_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_SystemConfigurationChangeEvent.csv"
        Get-WMIObject -Class Win32_SystemConfigurationChangeEvent -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoSystemConfigurationChangeEvent_csv

        $var_InfoDCOMApplicationSetting_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_DCOMApplicationSetting.csv"
        Get-WMIObject -Class Win32_DCOMApplicationSetting -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoDCOMApplicationSetting_csv

        $var_InfoPrinterDriver_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_PrinterDriver.csv"
        Get-WMIObject -Class Win32_PrinterDriver -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoPrinterDriver_csv

        $var_InfoOSRecoveryConfiguration_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_OSRecoveryConfiguration.csv"
        Get-WMIObject -Class Win32_OSRecoveryConfiguration -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoOSRecoveryConfiguration_csv

        $var_InfoProcessor_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_Processor.csv"
        Get-WMIObject -Class Win32_Processor -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoProcessor_csv

        $var_InfoSystemEnclosure_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_SystemEnclosure.csv"
        Get-WMIObject -Class Win32_SystemEnclosure -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoSystemEnclosure_csv

        $var_InfoQuickFixEngineering_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_WindowsHostFixList.csv"
        Get-WMIObject -Class Win32_QuickFixEngineering -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoQuickFixEngineering_csv

        $var_InfoEnvironment_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_Environment.csv"
        Get-WMIObject -Class Win32_Environment -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoEnvironment_csv

        $var_InfoBIOS_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_BIOS.csv"
        Get-WMIObject -Class Win32_BIOS -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoBIOS_csv
    }
    catch
    {
        $vartempstring = "[ERROR] Failed To Pull Host Triage Information."
        write-host -fore Red -back black $vartempstring
        $vartempstring >> $SavedLogFile
        function_failwhale
        clear
    }

    ##### DEVICE INFO #####
    try
    {
        $vartempstring = "[TRIAGE] Starting Device Triage Information Collection."
        write-host -fore Gray -back black $vartempstring
        $vartempstring >> $SavedLogFile

        $var_InfoBootConfiguration_csv = $SavedForensicArtifactsCSV + $computername + "_Device_Info.Win32_BootConfiguration.csv"
        Get-WMIObject -Class Win32_BootConfiguration -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoBootConfiguration_csv

        $var_InfoAllocatedResource_csv = $SavedForensicArtifactsCSV + $computername + "_Device_Info.Win32_AllocatedResource.csv"
        Get-WMIObject -Class Win32_AllocatedResource -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoAllocatedResource_csv

        $var_InfoPMCIAController_csv = $SavedForensicArtifactsCSV + $computername + "_Device_Info.Win32_PMCIAController.csv"
        Get-WMIObject -Class Win32_PMCIAController -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoPMCIAController_csv

        $var_InfoPointingDevice_csv = $SavedForensicArtifactsCSV + $computername + "_Device_Info.Win32_PointingDevice.csv"
        Get-WMIObject -Class Win32_PointingDevice -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoPointingDevice_csv

        $var_InfoUSBHub_csv = $SavedForensicArtifactsCSV + $computername + "_Device_Info.Win32_USBHub.csv"
        Get-WMIObject -Class Win32_USBHub -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoUSBHub_csv

        $var_InfoPrinter_csv = $SavedForensicArtifactsCSV + $computername + "_Device_Info.Win32_Printer.csv"
        Get-WMIObject -Class Win32_Printer -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoPrinter_csv

        $var_InfoVideoController_csv = $SavedForensicArtifactsCSV + $computername + "_Device_Info.Win32_VideoController.csv"
        Get-WMIObject -Class Win32_VideoController -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoVideoController_csv

        $var_InfoPnPSignedDriver_csv = $SavedForensicArtifactsCSV + $computername + "_Device_Info.Win32_PnPSignedDriver.csv"
        Get-WMIObject -Class Win32_PnPSignedDriver -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoPnPSignedDriver_csv

        $var_InfoAltSignedDriver_csv = $SavedForensicArtifactsCSV + $computername + "_Device_Info.Win32_AltSignedDriver.csv"
        DriverQuery /fo csv /si >> $var_InfoAltSignedDriver_csv

        $var_InfoVerboseDriver_csv = $SavedForensicArtifactsCSV + $computername + "_Device_Info.Win32_VerboseDriver.csv"
        DriverQuery /fo csv /v >> $var_InfoVerboseDriver_csv
    }
    catch
    {
        $vartempstring = "[ERROR] Failed To Pull Device Triage Information."
        write-host -fore Red -back black $vartempstring
        $vartempstring >> $SavedLogFile
        function_failwhale
        clear
    }

    ##### DRIVE INFO ######
    try
    {
        $vartempstring = "[TRIAGE] Starting Drive Triage Information Collection."
        write-host -fore Gray -back black $vartempstring
        $vartempstring >> $SavedLogFile

        $var_InfoWin32_SystemPartitions_csv = $SavedForensicArtifactsCSV + $computername + "_Drive_Info.Win32_SystemPartitions.csv"
        Get-WMIObject -Class Win32_SystemPartitions -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_SystemPartitions_csv

        $var_InfoTapeDrive_csv = $SavedForensicArtifactsCSV + $computername + "_Drive_Info.Win32_TapeDrive.csv"
        Get-WMIObject -Class Win32_TapeDrive -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoTapeDrive_csv

        $var_InfoCDROMDrive_csv = $SavedForensicArtifactsCSV + $computername + "_Drive_Info.Win32_CDROMDrive.csv"
        Get-WMIObject -Class Win32_CDROMDrive -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoCDROMDrive_csv

        $var_InfoPnPEntity_csv = $SavedForensicArtifactsCSV + $computername + "_Drive_Info.Win32_PnPEntity.csv"
        Get-WMIObject -Class Win32_PnPEntity -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoPnPEntity_csv

        $var_InfoWin32_SystemDriver_csv = $SavedForensicArtifactsCSV + $computername + "_Drive_Info.Win32_SystemDriver.csv"
        Get-WMIObject -Class Win32_SystemDriver -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_SystemDriver_csv

        ### Credit Goes to newhandle's Meta-Blue.ps1 project ###
        $var_InfoWin32_System32Driver_csv = $SavedForensicArtifactsCSV + $computername + "_Drive_Info.Win32_System32Driver_csv.csv"
        Get-ChildItem -path C:\Windows\System32\drivers -include *.sys -recurse -ErrorAction SilentlyContinue | Get-AuthenticodeSignature | where {$_.status -ne 'Valid'} | Export-Csv -NoTypeInformation -Append $var_InfoWin32_System32Driver_csv | out-null
    }
    catch
    {
        $vartempstring = "[ERROR] Failed To Pull Drive Triage Information."
        write-host -fore Red -back black $vartempstring
        $vartempstring >> $SavedLogFile
        function_failwhale
        clear
    }

    ##### ACCESS INFO #####
    try
    {
        $vartempstring = "[TRIAGE] Starting Access Triage Information Collection."
        write-host -fore Gray -back black $vartempstring
        $vartempstring >> $SavedLogFile

        $var_InfoSystemUsers_csv = $SavedForensicArtifactsCSV + $computername + "_Access_Info.Win32_SystemUsers.csv"
        Get-WMIObject -Class Win32_SystemUsers -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoSystemUsers_csv

        $var_InfoUserAccount_csv = $SavedForensicArtifactsCSV + $computername + "_Access_Info.Win32_UserAccount.csv"
        Get-WMIObject -Class Win32_UserAccount -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoUserAccount_csv

        $var_InfoUserDesktop_csv = $SavedForensicArtifactsCSV + $computername + "_Access_Info.Win32_UserDesktop.csv"
        Get-WMIObject -Class Win32_UserDesktop -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoUserDesktop_csv

        $var_InfoSystemAccount_csv = $SavedForensicArtifactsCSV + $computername + "_Access_Info.Win32_SystemAccount.csv"
        Get-WMIObject -Class Win32_SystemAccount -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoSystemAccount_csv

        $var_InfoSystemDesktop_csv = $SavedForensicArtifactsCSV + $computername + "_Access_Info.Win32_SystemDesktop.csv"
        Get-WMIObject -Class Win32_SystemDesktop -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoSystemDesktop_csv

        $var_InfoDesktop_csv = $SavedForensicArtifactsCSV + $computername + "_Access_Info.Win32_Desktop.csv"
        Get-WMIObject -Class Win32_Desktop -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoDesktop_csv

        $var_InfoEnvironment_csv = $SavedForensicArtifactsCSV + $computername + "_Access_Info.Win32_Environment.csv"
        Get-WMIObject -Class Win32_Environment -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoEnvironment_csv

        $var_InfoAccount_csv = $SavedForensicArtifactsCSV + $computername + "_Access_Info.Win32_Account.csv"
        Get-WMIObject -Class Win32_Account -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoAccount_csv

        $var_InfoGroup_csv = $SavedForensicArtifactsCSV + $computername + "_Access_Info.Win32_Group.csv"
        Get-WMIObject -Class Win32_Group -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoGroup_csv

        $var_InfoNetworkLoginProfile_csv = $SavedForensicArtifactsCSV + $computername + "_Access_Info.Win32_NetworkLoginProfile.csv"
        Get-WMIObject -Class Win32_NetworkLoginProfile -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoNetworkLoginProfile_csv

        $var_InfoGPResult_xml =  $SavedForensicArtifactsXML + "\" + $computername + "_Host_Info.GPResult.xml"
        gpresult /f /X $var_InfoGPResult_xml
    }
    catch
    {
        $vartempstring = "[ERROR] Failed To Pull Access Triage Information."
        write-host -fore Red -back black $vartempstring
        $vartempstring >> $SavedLogFile
        function_failwhale
        clear
    }

    ##### Network Info #####
    try
    {
        $vartempstring = "[TRIAGE] Starting Network Triage Information Collection."
        write-host -fore Gray -back black $vartempstring
        $vartempstring >> $SavedLogFile

        $var_InfoClusterShare_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_ClusterShare.csv"
        Get-WMIObject -Class Win32_ClusterShare -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoClusterShare_csv

        $var_InfoNetworkAdapterConfiguration_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_NetworkAdapterConfiguration.csv"
        Get-WMIObject -Class Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoNetworkAdapterConfiguration_csv

        $var_InfoShare_Win_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_Share_Win.csv"
        Get-WMIObject -Class Win32_Share -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoShare_Win_csv

        $var_InfoDnsClientServerAddress_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_DnsClientServerAddress.csv"
        Get-DnsClientServerAddress -Verbose -ErrorAction SilentlyContinue | export-csv -NoTypeInformation -Verbose -Append $var_InfoDnsClientServerAddress_csv

        $var_InfoNetNeighbor_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_NetNeighbor.csv"
        Get-NetNeighbor -Verbose -ErrorAction SilentlyContinue | export-csv -NoTypeInformation -Verbose -Append $var_InfoNetNeighbor_csv

        $var_InfoSystemNetworkConnections_Win_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_SystemNetworkConnections_Win.csv"
        Get-WMIObject -Class Win32_SystemNetworkConnections -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoSystemNetworkConnections_Win_csv

        $var_InfoSubSession_Win_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_SystemNetworkConnections_Win.csv"
        Get-WMIObject -Class Win32_SubSession -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoSubSession_Win_csv

        $var_InfoShareToDirectory_Win_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_ShareToDirectory_Win.csv"
        Get-WMIObject -Class Win32_ShareToDirectory -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoShareToDirectory_Win_csv

        $var_InfoSessionResource_Win_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_SessionResource_Win.csv"
        Get-WMIObject -Class Win32_SessionResource -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoSessionResource_Win_csv

        $var_InfoSessionProcess_Win_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_SessionProcess_Win.csv"
        Get-WMIObject -Class Win32_SessionProcess -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoSessionProcess_Win_csv

        $var_InfoWin32_Session_Win_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_Session_Win.csv"
        Get-WMIObject -Class Win32_Session -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_Session_Win_csv

        $var_InfoSMBConnection_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_SMBConnection.csv"
        Get-SMBConnection -Verbose -ErrorAction SilentlyContinue | export-csv -NoTypeInformation -Verbose -Append $var_InfoSMBConnection_csv

        $var_InfoSMBShare_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_SMBShare.csv"
        Get-SMBShare -Verbose -ErrorAction SilentlyContinue | export-csv -NoTypeInformation -Verbose -Append $var_InfoSMBShare_csv

        $var_InfoNetTCPConnection_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_NetTCPConnection.csv"
        Get-NetTCPConnection -Verbose -ErrorAction SilentlyContinue | export-csv -NoTypeInformation -Append $var_InfoNetTCPConnection_csv

        $var_InfoNetshDLL_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_NetshDLL.csv"
        Get-ItemProperty -ErrorAction SilentlyContinue 'HKLM:\SOFTWARE\Microsoft\Netsh' | export-csv -NoTypeInformation -Verbose -Append $var_InfoNetshDLL_csv

        $var_InfoProtocolBinding_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_ProtocolBinding.csv"        
        Get-WMIObject -Class Win32_ProtocolBinding -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoProtocolBinding_csv

        $var_InfoComSetting_csv = $SavedForensicArtifactsCSV + $computername + "_Network_Info.Win32_ComSetting.csv"
        Get-WMIObject -Class Win32_ComSetting -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoComSetting_csv
    }
    catch
    {
        $vartempstring = "[ERROR] Failed To Pull Network Triage Information."
        write-host -fore Red -back black $vartempstring
        $vartempstring >> $SavedLogFile
        function_failwhale
        clear
    }


    ##### Powershell/WMIC #####
    try
    {
        $vartempstring = "[TRIAGE] Starting PowerShell/WMIC Triage Information Collection."
        write-host -fore Gray -back black $vartempstring
        $vartempstring >> $SavedLogFile

        $var_InfoPowerShellVersions_csv = $SavedForensicArtifactsCSV + $computername + "_WMIC-PS_Info.PowerShell_Versions.csv"
        Get-WindowsOptionalFeature -Online -FeatureName microsoftwindowspowershell* -ErrorAction SilentlyContinue | export-csv -NoTypeInformation -Verbose -Append $var_InfoPowerShellVersions_csv

        $var_InfoWMIElementSetting_csv = $SavedForensicArtifactsCSV + $computername + "_WMIC-PS_Info.WMIC_ElementSetting.csv"
        Get-WMIObject -Class Win32_WMIElementSetting -ErrorAction SilentlyContinue | export-csv -NoTypeInformation -Verbose -Append $var_InfoWMIElementSetting_csv

        $var_InfoWMICFilterToConsumerBinding_csv = $SavedForensicArtifactsCSV + $computername + "_WMIC-PS_Info.WMIC_FilterToConsumerBinding.csv"
        Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | export-csv -NoTypeInformation -Verbose -Append $var_InfoWMICFilterToConsumerBinding_csv

        $var_InfoWMICEventConsumer_csv = $SavedForensicArtifactsCSV + $computername + "_WMIC-PS_Info.WMIC_EventConsumer.csv"
        Get-WMIObject -Namespace root\Subscription -Class __EventConsumer -ErrorAction SilentlyContinue | export-csv -NoTypeInformation -Verbose -Append $var_InfoWMICEventConsumer_csv

        $var_InfoWMICEventFilter_csv = $SavedForensicArtifactsCSV + $computername + "_WMIC-PS_Info.WMIC_EventFilter.csv"
        Get-WMIObject -Namespace root\Subscription -Class __EventFilter -ErrorAction SilentlyContinue | export-csv -NoTypeInformation -Verbose -Append $var_InfoWMICEventFilter_csv

        $var_InfoWMICFilterToConsumerBindingDefault_csv = $SavedForensicArtifactsCSV + $computername + "_WMIC-PS_Info.WMIC_FilterToConsumerBindingDefault.csv"
        Get-WMIObject -Namespace root\Default -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | export-csv -NoTypeInformation -Verbose -Append $var_InfoWMICFilterToConsumerBindingDefault_csv

        $var_InfoWMICEventConsumerDefault_csv = $SavedForensicArtifactsCSV + $computername + "_WMIC-PS_Info.WMIC_EventConsumerDefault.csv"
        Get-WMIObject -Namespace root\Default -Class __EventConsumer -ErrorAction SilentlyContinue | export-csv -NoTypeInformation -Verbose -Append $var_InfoWMICEventConsumerDefault_csv

        $var_InfoWMICEventFilterDefault_csv = $SavedForensicArtifactsCSV + $computername + "_WMIC-PS_Info.WMIC_EventFilterDefault.csv"
        Get-WMIObject -Namespace root\Default -Class __EventFilter -ErrorAction SilentlyContinue | export-csv -NoTypeInformation -Verbose -Append $var_InfoWMICEventFilterDefault_csv

        $var_InfoWMISettingVAR_csv = $SavedForensicArtifactsCSV + $computername + "_WMIC-PS_Info.WMIC_ElementSettingVar.csv"
        Get-WMIObject -Class Win32_WMISetting | export-csv -NoTypeInformation -Verbose -Append $var_InfoWMISettingVAR_csv

        $var_test_path_cimom = test-path -Path "HKLM:\$User\SOFTWARE\Microsoft\Wbem\CIMOM"
        if ($var_test_path_psexec -eq "True")
        {
            $var_InfoWin32_CIMOM_REG_csv = $SavedForensicArtifactsCSV + $computername + "_WMIC-PS_Info.Win32_CIMOM_REG.csv"
            Get-ItemProperty "HKLM:\$User\SOFTWARE\Microsoft\Wbem\CIMOM" | export-csv -NoTypeInformation -Verbose -Append $var_InfoWin32_CIMOM_REG_csv
        }
        else
        {
            $vartempstring = "[WARN] Registry Key: HKLM:\$User\SOFTWARE\Microsoft\Wbem\CIMOM Does Not Exist."
            write-host -fore Yellow -back black $vartempstring
            $vartempstring >> $SavedLogFile
        }

        $var_test_path_psexec = test-path -Path "HKLM:\System\CurrentControlSet\Services\PSEXECSVC"
        if ($var_test_path_psexec -eq "True")
        {
            $var_REG_PSEXEC_SVC_csv = $SavedForensicArtifactsCSV + $computername + "_WMIC-PS_Info.PSEXEC_SVC.csv"
            Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\PSEXECSVC" | export-csv -NoTypeInformation -Verbose -Append $var_REG_PSEXEC_SVC_csv
        }
        else
        {
            $vartempstring = "[WARN] Registry Key: HKLM:\System\CurrentControlSet\Services\PSEXECSVC Does Not Exist."
            write-host -fore Yellow -back black $vartempstring
            $vartempstring >> $SavedLogFile
        }

        $windirlocationWMIDB =  $windirlocation + "\System32\wbem\"
        Copy-Item $windirlocationWMIDB $StoredForensicLocationWBEM -Recurse
    }
    catch
    {
        $vartempstring = "[ERROR] Failed To Pull PowerShell/WMIC Information."
        write-host -fore Red -back black $vartempstring
        $vartempstring >> $SavedLogFile
        function_failwhale
        clear
    }

    ##### Process/Memory Info #####
    try
    {
        $vartempstring = "[TRIAGE] Starting Process Triage Information Collection."
        write-host -fore Gray -back black $vartempstring
        $vartempstring >> $SavedLogFile

        $var_InfoWin32_process_csv = $SavedForensicArtifactsCSV + $computername + "_Memory_Info.Win32_process.csv"
        Get-WMIObject -Class Win32_process -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_process_csv

        $var_InfoWin32_ScheduledJob_csv = $SavedForensicArtifactsCSV + $computername + "_Memory_Info.Win32_ScheduledJob.csv"
        Get-WMIObject -Class Win32_ScheduledJob -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_ScheduledJob_csv
       
        $var_InfoWin32_PageFileUsage_csv = $SavedForensicArtifactsCSV + $computername + "_Memory_Info.Win32_PageFileUsage.csv"
        Get-WMIObject -Class Win32_PageFileUsage -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_PageFileUsage_csv

        $var_InfoWin32_PageFileSetting_csv = $SavedForensicArtifactsCSV + $computername + "_Memory_Info.Win32_PageFileSetting.csv"
        Get-WMIObject -Class Win32_PageFileSetting -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_PageFileSetting_csv

        $var_InfoWin32_Service_csv = $SavedForensicArtifactsCSV + $computername + "_Memory_Info.Win32_Service.csv"
        Get-WMIObject -Class Win32_Service -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_Service_csv

        $var_InfoWin32_Product_csv = $SavedForensicArtifactsCSV + $computername + "_Memory_Info.Win32_Product.csv"
        Get-WMIObject -Class Win32_Product -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_Product_csv

        $var_InfoWin32_StartupCommand_csv = $SavedForensicArtifactsCSV + $computername + "_Memory_Info.Win32_StartupCommand.csv"
        Get-WMIObject -Class Win32_StartupCommand -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_StartupCommand_csv

        $var_test_path_knowndll = test-path -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs\"
        if ($var_test_path_knowndll -eq "True")
        {
            $var_InfoWin32_LocalKnownDLL_csv = $SavedForensicArtifactsCSV + $computername + "_Memory_Info.Win32_LocalKnownDLL.csv"
            Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs\' | export-csv -NoTypeInformation -Verbose -Append $var_InfoWin32_LocalKnownDLL_csv
        }
        else
        {
            $vartempstring = "[WARN] Registry Key: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs\ Does Not Exist."
            write-host -fore Yellow -back black $vartempstring
            $vartempstring >> $SavedLogFile
        }


        <#
            The following two commands are nice since they rip out all of the performance monitoring statistics and puts them into a single CSV the second command 
            pulls all of the associated threads for processes. Unfortuantely, they take a minute so they are disabled by default.
        #>

        # $var_InfoWin32_Perf_csv = $SavedForensicArtifactsCSV + $computername + "_Memory_Info.Win32_Perf.csv"
        # Get-WMIObject -Class Win32_Perf -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_Perf_csv

        # $var_InfoWin32_Thread_csv = $SavedForensicArtifactsCSV + $computername + "_Memory_Info.Win32_Thread.csv"
        # Get-WMIObject -Class Win32_Thread -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_Thread_csv
    }
    catch
    {
        $vartempstring = "[ERROR] Failed To Pull Process Information."
        write-host -fore Red -back black $vartempstring
        $vartempstring >> $SavedLogFile
        function_failwhale
        clear
    }

    ##### Virtual Machine Info ######
    try
    {
        $vartempstring = "[TRIAGE] Starting To Pull Virtual Machine Information."
        write-host -fore Gray -back black $vartempstring
        $vartempstring >> $SavedLogFile

        $var_InfoWin32_VMWare_csv = $SavedForensicArtifactsCSV + $computername + "_VM_Info.Win32_VMware_PerfRawData.csv"
        Get-WMIObject -Class Win32_PerfRawData_VMware | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_VMWare_csv

        $var_InfoWin32_VMWareVMName_csv = $SavedForensicArtifactsCSV + $computername + "_VM_Info.Win32_VMWare_VMName.csv"
        Get-WMIObject -Class Win32_VMWareVMName | Select-Object -Property Name | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_VMWareVMName_csv
    }
    catch
    {
        $vartempstring = "[ERROR] Failed To Virtual Machine Info."
        write-host -fore Red -back black $vartempstring
        $vartempstring >> $SavedLogFile
        function_failwhale
        clear
    } 

    ##### Logs and Stuff ######
    try
    {
        $vartempstring = "[TRIAGE] Starting Log Triage Information Collection."
        write-host -fore Gray -back black $vartempstring
        $vartempstring >> $SavedLogFile

        $var_InfoWin32_NTEventLogFile_csv = $SavedForensicArtifactsCSV + $computername + "_Logging_Info.Win32_NTEventLogFile.csv"
        Get-WMIObject -Class Win32_NTEventLogFile -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_NTEventLogFile_csv

        <#
            The following two commands are nice since they rip out all Windows events and puts them into a single CSV, however there are better ways of doing this and it takes forever.
            Hence why it is commented out. Feel free to uncomment if you want. Or don't, I'm not your dad.
        #>

        #var_InfoWin32_NTEventLogs_csv = $SavedForensicArtifactsCSV + $computername + "_Logging_Info.Win32_NTEventLogs.csv"
        #Get-WMIObject -Class Win32_NTLogEvent -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_NTEventLogs_csv
    }
    catch
    {
        $vartempstring = "[ERROR] Failed To Pull Logs and Associated Information."
        write-host -fore Red -back black $vartempstring
        $vartempstring >> $SavedLogFile
        function_failwhale
        clear
    }    

    ##### VARIOUS HUNT TECHNIQUES #####
    ### Credit Goes to newhandle's Meta-Blue.ps1 project ###
    try
    {
        $vartempstring = "[TRIAGE] Starting Collection of Info For Various HUNT Techniques."
        write-host -fore Gray -back black $vartempstring
        $vartempstring >> $SavedLogFile


        $var_test_path_shell = test-path -Path "HKCU:\SOFTWARE\classes\ms-settings-shell\open\command"
        if ($var_test_path_shell -eq $TRUE)
        {
            $var_InfoWin32_UACBypassFodHelper_csv = $SavedForensicArtifactsCSV + $computername + "_Hunt_Info.Win32_UACBypassFodHelper.csv"
            Get-ItemProperty "HKCU:\SOFTWARE\classes\ms-settings-shell\open\command" | export-csv -NoTypeInformation -Append $var_InfoWin32_UACBypassFodHelper_csv
        }
        else
        {
            $vartempstring = "[WARN] Registry Key: HKCU:\SOFTWARE\classes\ms-settings-shell\open\command Does Not Exist."
            write-host -fore Yellow -back black $vartempstring
            $vartempstring >> $SavedLogFile
        }

        $var_test_path_time = test-path -Path "HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders\*"
        if ($var_test_path_time -eq $TRUE)
        {
            $var_InfoWin32_NTP_INFO_csv = $SavedForensicArtifactsCSV + $computername + "_Hunt_Info.Win32_NTP_INFO.csv"
            Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders\*" | export-csv -NoTypeInformation -Append $var_InfoWin32_NTP_INFO_csv
        }
        else
        {
            $vartempstring = "[WARN] Registry Key: HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders\* Does Not Exist."
            write-host -fore Yellow -back black $vartempstring
            $vartempstring >> $SavedLogFile
        }

        $var_test_path_consent = test-path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\*\NonPackaged\*"
        if ($var_test_path_consent -eq $TRUE)
        {
            $var_InfoWin32_CAP_INFO_csv = $SavedForensicArtifactsCSV + $computername + "_Hunt_Info.Win32_CAP_INFO.csv"
            Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\*\NonPackaged\*" | export-csv -NoTypeInformation -Append $var_InfoWin32_CAP_INFO_csv
        }
        else
        {
            $vartempstring = "[WARN] Registry Key: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\*\NonPackaged\* Does Not Exist."
            write-host -fore Yellow -back black $vartempstring
            $vartempstring >> $SavedLogFile
        }

        $var_test_path_pipe = test-path -Path \\.\pipe\
        if ($var_test_path_pipe -eq $TRUE)
        {
            $var_InfoWin32_NAMEDPIPES_csv = $SavedForensicArtifactsCSV + $computername + "_Hunt_Info.Win32_NAMEDPIPES.csv"
            Get-ChildItem \\.\pipe\ | export-csv -NoTypeInformation -Append $var_InfoWin32_NAMEDPIPES_csv
        }
        else
        {
            $vartempstring = "[WARN] \\.\pipe\ Does Not Exist"
            write-host -fore Yellow -back black $vartempstring
            $vartempstring >> $SavedLogFile
        }

    }
    catch
    {
        $vartempstring = "[ERROR] Failed To Pull Information For Various HUNT Techniques."
        write-host -fore Red -back black $vartempstring
        $vartempstring >> $SavedLogFile
        function_failwhale
        clear
    }   
}

Function Function_RIP_Registry
{
    $ForensicFileStoreREG = $SavedForensicArtifacts + "\REG\"
    try
    {
        $vartempstring = "[TRIAGE] Starting Registry Artifact Collection."
        if ($env_verbose -eq "V")
        {
            write-host -fore Gray -back black $vartempstring
        }
        $vartempstring >> $SavedLogFile
 
        $var_InfoWin32_Registry_csv = $SavedForensicArtifactsCSV + $computername + "_Registry_Info.Win32_Registry.csv"
        Get-WMIObject -Class Win32_Registry | export-csv -NoTypeInformation -Append $var_InfoWin32_Registry_csv
 
        $windirlocationREG =  $windirlocation + "\System32\config\"
        Copy-Item $windirlocationREG $ForensicFileStoreREG -Recurse
    }
    catch
    {
        if ($env_verbose -eq "V")
        {
            write-host -fore Red -back black "[ERROR] Failed to Copy Registry."
        }
        echo "[ERROR] Failed to Copy Registry." >> $SavedLogFile
        function_failwhale
        clear
    }
}

Function Function_RIP_AMCACHE
{
    try
    {
        $vartempstring = "[TRIAGE] Starting AMCACHE Artifact Collection."
        if ($env_verbose -eq "V")
        {
            write-host -fore Gray -back black $vartempstring
        }
        $vartempstring >> $SavedLogFile

        $ForensicFileStoreAMCACHE = $SavedForensicArtifacts + "AMCACHE/"
        $ForensicFileStoreAMCACHE
        $windirlocationamcache =  $windirlocation + "\AppCompat\Programs\"
        $windirlocationamcache
        Copy-Item $windirlocationamcache $ForensicFileStoreAMCACHE -Recurse
    }
    catch
    {
        if ($env_verbose -eq "V")
        {
            write-host -fore Red -back black "[ERROR] Failed to Copy AMCACHE."
        }
        echo "[ERROR] Failed to Copy AMCACHE." >> $SavedLogFile
        function_failwhale
        clear
    }
}

function function_Triage_Meta-Blue_ProcessHash
### Credit Goes to newhandle's Meta-Blue.ps1 project ###
{
    $vartempstring = "[TRIAGE] Starting Process Hashing Artifact Collection."
    if ($env_verbose -eq "V")
    {
        write-host -fore Gray -back black $vartempstring
    }
    $vartempstring >> $SavedLogFile

    $var_InfoProcessHash_csv = $SavedForensicArtifactsCSV + $computername + "_Hunt_Info.Win32_ProcessHash.csv"
    $var_MB_hashes = @()
    $var_MB_pathsofexe = (gwmi win32_process -ErrorAction SilentlyContinue | select executablepath | ?{$_.executablepath -ne ""})
    $var_MB_execpaths = [System.Collections.ArrayList]@();foreach($i in $var_MB_pathsofexe){$var_MB_execpaths.Add($i.executablepath)| Out-Null}
    foreach($i in $var_MB_execpaths)
    {
        if($i -ne $null)
        {
            Get-filehash -algorithm SHA256 -path $i -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoProcessHash_csv
        }
    }
}

function function_Triage_Meta-Blue_DriverHash
### Credit Goes to newhandle's Meta-Blue.ps1 project ###
{
    $vartempstring = "[TRIAGE] Starting Driver Hashing Artifact Collection."
    if ($env_verbose -eq "V")
    {
        write-host -fore Gray -back black $vartempstring
    }
    $vartempstring >> $SavedLogFile

    $var_InfoDriverHash_csv = $SavedForensicArtifactsCSV + $computername + "_Hunt_Info.Win32_DriverHash.csv"
    $var_MB_driverPath = (gwmi win32_systemdriver).pathname          
    foreach($var_MB_driver in $var_MB_driverPath)
    {                
        Get-filehash -algorithm SHA256 -path $var_MB_driver -ErrorAction SilentlyContinue | export-csv -Append -Verbose -NoTypeInformation $var_InfoDriverHash_csv              
    }
}

function function_Triage_Meta-Blue_DLLHash
### Credit Goes to newhandle's Meta-Blue.ps1 project ###
{
    $vartempstring = "[TRIAGE] Starting DLL Hashing Artifact Collection."
    if ($env_verbose -eq "V")
    {
        write-host -fore Gray -back black $vartempstring
    }
    $vartempstring >> $SavedLogFile

    $var_InfoDLLHash_csv = $SavedForensicArtifactsCSV + $computername + "_Hunt_Info.Win32_DLLHash.csv"
    $var_MB_a = (Get-Process -Module -ErrorAction SilentlyContinue | ?{!($_.FileName -like "*.exe")})
    $var_MB_a = $var_MB_a.FileName.ToUpper() | sort
    foreach($var_MB_file in $var_MB_a)
    {
        Get-FileHash -Algorithm SHA256 $var_MB_file | export-csv -Append -Verbose -NoTypeInformation $var_InfoDLLHash_csv
    }
}


function function_Triage_Meta-Blue_DLLSEARCHORDER
### Credit Goes to newhandle's Meta-Blue.ps1 project ###
{
    $vartempstring = "[TRIAGE] Starting DLL Search Order Hijacking Information Collection."
    if ($env_verbose -eq "V")
    {
        write-host -fore Gray -back black $vartempstring
    }
    $vartempstring >> $SavedLogFile

    $var_InfoWin32_DLLSearchOrderHijack_csv = $SavedForensicArtifactsCSV + $computername + "_Host_Info.Win32_DLLSearchOrderHijack.csv"
    Get-ChildItem -Recurse -path C:\Windows\* -include *.dll | Get-AuthenticodeSignature | Where-Object Status -NE "Valid" | export-csv -Append -Verbose -NoTypeInformation $var_InfoWin32_DLLSearchOrderHijack_csv
}

Function Function_RIP_Schedule_Tasks
{
    try
    {
        $vartempstring = "[TRIAGE] Starting Scheduled Task Collection."
        if ($env_verbose -eq "V")
        {
            write-host -fore Gray -back black $vartempstring
        }
        $vartempstring >> $SavedLogFile
        
        $ForensicFileStoreScheduledTasks = $SavedForensicArtifacts + "Tasks/"
        $ForensicFileStoreScheduledTasksFile = $ForensicFileStoreScheduledTasks + $computername + "scheduledtasks_rip.csv"
        Get-ScheduledTask -Verbose | export-csv -Verbose -NoTypeInformation -Append $ForensicFileStoreScheduledTasksFile
    }
    catch
    {
        if ($env_verbose -eq "V")
        {
            write-host -fore Red -back black "[ERROR] Failed to Pull and Save Scheduled Tasks."
        }
        function_failwhale
        clear
    }
}

Function Function_RIP_Event_Logs
{
    $ForensicFileStoreEVT = $SavedForensicArtifacts + "\EVTx\"
    try
    {
        $vartempstring = "[TRIAGE] Starting Event Log Collection."
        if ($env_verbose -eq "V")
        {
            write-host -fore Gray -back black $vartempstring
        }
        $vartempstring >> $SavedLogFile

        $windowsversioncheck = (Get-CimInstance CIM_OperatingSystem | select -ExpandProperty version).Split(".")[0]
        if ($windowsversioncheck -gt 7)
        {
            try
            {
                $windirlocationevt =  $windirlocation + "\System32\winevt\Logs\"
                Copy-Item $windirlocationevt $ForensicFileStoreEVT -Recurse
            }
            catch
            {
                if ($env_verbose -eq "V")
                {
                    write-host -fore Red -back black "[ERROR] Failed to Copy Event Log Files."
                }
                function_failwhale
                clear
            }
        }
        if ($windowsversioncheck -lt 7)
        {
            try
            {
                $windirlocationevt =  $windirlocation + "\System32\config\"
                Copy-Item $windirlocationevt $ForensicFileStoreEVT -Recurse
            }
            catch
            {
                if ($env_verbose -eq "V")
                {
                    write-host -fore Red -back black "[ERROR] Failed to Copy Event Log Files."
                }
                function_failwhale
                clear
            }
        }

        $var_InfoWin32_Reg_EVTApplication_Settings = $SavedForensicArtifactsCSV + $computername + "_EventLog_Info.Win32_EVTApplication_Settings.csv"
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" | export-csv -NoTypeInformation -Append $var_InfoWin32_Reg_EVTApplication_Settings

        $var_InfoWin32_Reg_EVTSystem_Settings = $SavedForensicArtifactsCSV + $computername + "_EventLog_Info.Win32_EVTSystem_Settings.csv"
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System" | export-csv -NoTypeInformation -Append $var_InfoWin32_Reg_EVTSystem_Settings
        
        $var_InfoWin32_Reg_EVTSecurity_Settings = $SavedForensicArtifactsCSV + $computername + "_EventLog_Info.Win32_EVTSecurity_Settings.csv"
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" | export-csv -NoTypeInformation -Append $var_InfoWin32_Reg_EVTSecurity_Settings
    }
    catch
    {
        if ($env_verbose -eq "V")
        {
            write-host -fore Red -back black "[ERROR] Failed to Copy Event Logs."
        }
        function_failwhale
        clear
    }
}

Function Function_RIP_RDP_BITMAP
{
    try
    {
    $CurrentUsernames = Get-WMIObject win32_userprofile -filter "LocalPath Like '%\\Users\\%'" | select -ExpandProperty LocalPath

        foreach ($CurrentUsernameRDP in $CurrentUsernames)
        {
            $ForensicFileStoreRDPBIT = $SavedForensicArtifacts + "\" + $CurrentUsernameRDP + "\RDPBIT\"
            $windowsversioncheck = (Get-CimInstance CIM_OperatingSystem | select -ExpandProperty version).Split(".")[0]
            if ($windowsversioncheck -lt 7)
            {
                try
                {
                    $windirlocationRDPBIT =  $CurrentUsernameRDP + "\Local Settings\Application Data\Microsoft\Terminal Server Client\Cache\"
                    Copy-Item $windirlocationRDPBIT $ForensicFileStoreRDPBIT -Recurse
                }
                catch
                {
                    if ($env_verbose -eq "V")
                    {
                        write-host -back black -fore yellow "[WARN] User Name: " + $CurrentUsernameRDP + " either has not used RDP, you don't have permissions, or there was an unspecified error."
                    }
                    $RDPArtificatWARNText = "[WARN] User Name: " + $CurrentUsernameRDP + " either has not used RDP, you don't have permissions, or there was an unspecified error."
                    echo $RDPArtificatWARNText >> $SavedLogFile
                    function_failwhale
                    clear
                }
            }
            if ($windowsversioncheck -ge 7)
            {
                try
                {
                    $windirlocationRDPBIT =  $CurrentUsernameRDP + "\AppData\Local\Microsoft\Terminal Server Client\Cache\"
                    Copy-Item $windirlocationRDPBIT $ForensicFileStoreRDPBIT -Recurse
                }
                catch
                {
                    if ($env_verbose -eq "V")
                    {
                        write-host -back black -fore yellow "[WARN] User Name: " + $CurrentUsernameRDP + " either has not used RDP, you don't have permissions, or there was an unspecified error."
                    }
                    $RDPArtificatWARNText = "[WARN] User Name: " + $CurrentUsernameRDP + " either has not used RDP, you don't have permissions, or there was an unspecified error."
                    echo $RDPArtificatWARNText >> $SavedLogFile
                    function_failwhale
                    clear
                }
            }
            else
            {
            write-host -back black -fore yellow "[WARN] Windows Version Number:" $windowsversioncheck "could not be pulled properly or does not fall within the normalized specifications, defaulting to Windows 7+ File Structure."
            $RDPArtificatWARN2Text = "[WARN] Windows Version Number: " + $windowsversioncheck + " could not be pulled properly or does not fall within the normalized specifications, defaulting to Windows 7+ File Structure."
            echo $RDPArtificatWARN2Text >> $SavedLogFile

                try
                {
                $windirlocationRDPBIT =  $CurrentUsernameRDP + "\AppData\Local\Microsoft\Terminal Server Client\Cache\"
                Copy-Item $windirlocationRDPBIT $ForensicFileStoreRDPBIT -Recurse
                }
                catch
                {
                    if ($env_verbose -eq "V")
                    {
                        write-host -back black -fore yellow "[WARN] User Name: " + $CurrentUsernameRDP + " either has not used RDP, you don't have permissions, or there was an unspecified error."
                    }
                    $RDPArtificatWARNText = "[WARN] User Name: " + $CurrentUsernameRDP + " either has not used RDP, you don't have permissions, or there was an unspecified error."
                    echo $RDPArtificatWARNText >> $SavedLogFile
                    function_failwhale
                    clear
                }
            }
        }
    }
    catch
    {
        if ($env_verbose -eq "V")
        {
            write-host -fore Red -back black "[ERROR] Failed to Copy RDP Bitmap Cache Files."
        }
        function_failwhale
        clear
    }        
}

##not done
Function Function_RIP_COMMON_AUTORUNS
{
    try
    {
        $vartempstring = "[TRIAGE] Starting Collection of Info For Common."
        write-host -fore Gray -back black $vartempstring
        $vartempstring >> $SavedLogFile

        $var_InfoWin32_Reg_System_ExRunOnce = $SavedForensicArtifactsCSV + $computername + "_Autoruns_Info.Win32_Reg_System_ExRunOnce.csv"
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" | export-csv -NoTypeInformation -Verbose -Append $var_InfoWin32_Reg_System_ExRunOnce

        $var_InfoWin32_Reg_System_ExRun = $SavedForensicArtifactsCSV + $computername + "_Autoruns_Info.Win32_Reg_System_ExRun.csv"
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run" | export-csv -NoTypeInformation -Verbose -Append $var_InfoWin32_Reg_System_ExRun

        $var_InfoWin32_Reg_System_CuRun = $SavedForensicArtifactsCSV + $computername + "_Autoruns_Info.Win32_Reg_System_CuRun.csv"
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | export-csv -NoTypeInformation -Verbose -Append $var_InfoWin32_Reg_System_CuRun

        $var_InfoWin32_Reg_System_UserInit = $SavedForensicArtifactsCSV + $computername + "_Autoruns_Info.Win32_Reg_System_UserInit.csv"
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon\Userinit" | export-csv -NoTypeInformation -Verbose -Append $var_InfoWin32_Reg_System_UserInit

        $var_InfoWin32_Reg_CurUser_ExRunOnce = $SavedForensicArtifactsCSV + $computername + "_Autoruns_Info.Win32_Reg_CurUser_ExRunOnce.csv"
        Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" | export-csv -NoTypeInformation -Verbose -Append $var_InfoWin32_Reg_CurUser_ExRunOnce

        $var_InfoWin32_Reg_CurUser_ExRun = $SavedForensicArtifactsCSV + $computername + "_Autoruns_Info.Win32_Reg_CurUser_ExRun.csv"
        Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run" | export-csv -NoTypeInformation -Verbose -Append $var_InfoWin32_Reg_CurUser_ExRun
        
        # %APPDATA%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
    }
    catch
    {
        $vartempstring = "[INFO] SHIMCACHE Property: (SdbTime) Does Not Appear To Exist."
        if ($env_verbose -eq "V")
        {
            write-host -fore Red -back black $vartempstring
        }
        $vartempstring = "[ERROR] Failed To Pull Information For Various HUNT Techniques."
        $vartempstring >> $SavedLogFile
        function_failwhale
        clear
    } 
}

Function Function_RIP_SHIMCACHE
{
    $windowsversioncheck = (Get-CimInstance CIM_OperatingSystem | select -ExpandProperty version).Split(".")[0]
    [int]$windowsversionchecknum = [convert]::ToINt32($windowsversioncheck)
    $windowsversioncheck
    if ($windowsversionchecknum -gt 7)
    {
        try
        {
            $vartempstring = "[TRIAGE] Starting Collection of Info For SHIMCache Artifacts (Windows 7+)."
            write-host -fore Gray -back black $vartempstring
            $vartempstring >> $SavedLogFile

            $var_InfoWin32_Reg_ShimCache_Main = $SavedForensicArtifactsCSV + $computername + "_ShimCache_Info.Win32_Reg_ShimCache_Main.csv"
            $var_RIP_SHIMCACHE_MAIN_Test = Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\" 
            if ($var_RIP_SHIMCACHE_MAIN_Test -eq $TRUE)
            {
                $var_RIP_SHIMCACHE_MAIN = Get-ItemProperty -Verbose -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\" | export-csv -Verbose -Append $var_InfoWin32_Reg_ShimCache_Main
                $var_InfoWin32_Reg_ShimCache_ACC = $SavedForensicArtifactsCSV + $computername + "_ShimCache_Info.Win32_Reg_ShimCache_ACC.csv"
                try
                {
                    $var_RIP_SHIMCACHE_ACC = Get-ItemProperty -Verbose -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\" | Select-Object AppCompatCache -ExpandProperty AppCompatCache | export-csv -Verbose -Append $var_InfoWin32_Reg_ShimCache_ACC
                }
                catch
                {
                    $vartempstring = "[INFO] SHIMCACHE Property: (AppCompatCache) Does Not Appear To Exist."
                    if ($env_verbose -eq "V")
                    {
                        write-host -fore Gray -back black $vartempstring
                    }
                    $vartempstring >> $SavedLogFile
                }

                $var_InfoWin32_Reg_ShimCache_CMB = $SavedForensicArtifactsCSV + $computername + "_ShimCache_Info.Win32_Reg_ShimCache_CMB.csv"
                try
                {
                $var_RIP_SHIMCACHE_CMB = Get-ItemProperty -Verbose -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\" | Select-Object AppCompatCache -ExpandProperty CacheMainSDB | export-csv -Verbose -Append $var_InfoWin32_Reg_ShimCache_CMB
                }
                catch
                {
                    $vartempstring = "[INFO] SHIMCACHE Property: (CacheMainSDB) Does Not Appear To Exist."
                    if ($env_verbose -eq "V")
                    {
                        write-host -fore Gray -back black $vartempstring
                    }
                    $vartempstring >> $SavedLogFile
                }

                $var_InfoWin32_Reg_ShimCache_ST = $SavedForensicArtifactsCSV + $computername + "_ShimCache_Info.Win32_Reg_ShimCache_ST.csv"
                try
                {
                    $var_RIP_SHIMCACHE_ST = Get-ItemProperty -Verbose -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\" | Select-Object AppCompatCache -ExpandProperty SdbTime | export-csv -Verbose -Append $var_InfoWin32_Reg_ShimCache_ST
                }
                catch
                {
                    $vartempstring = "[INFO] SHIMCACHE Property: (SdbTime) Does Not Appear To Exist."
                    if ($env_verbose -eq "V")
                    {
                        write-host -fore Gray -back black $vartempstring
                    }
                    $vartempstring >> $SavedLogFile
                }
            }
        }
        catch
        {
            $vartempstring = "[ERROR] Failed To Pull SHIMCache Artifacts."
            write-host -fore Red -back black $vartempstring
            $vartempstring >> $SavedLogFile
            function_failwhale
            clear
        }
    }
    if ($windowsversionchecknum -lt 7)
    {
        try
        {
            $vartempstring = "[TRIAGE] Starting Collection of Info For SHIMCache Artifacts (Windows XP =>)."
            if ($env_verbose -eq "V")
            {
                write-host -fore Gray -back black $vartempstring
            }
            $vartempstring >> $SavedLogFile

            $var_InfoWin32_Reg_ShimCache_Main = $SavedForensicArtifactsCSV + $computername + "_ShimCache_Info.Win32_Reg_ShimCache_Main.csv"
            $var_RIP_SHIMCACHE_MAIN = Get-ItemProperty -Verbose -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility\" | export-csv -NoTypeInformation -Verbose -Append $var_InfoWin32_Reg_ShimCache_Main

            $var_InfoWin32_Reg_ShimCache_ACC = $SavedForensicArtifactsCSV + $computername + "_ShimCache_Info.Win32_Reg_ShimCache_ACC.csv"
            $var_RIP_SHIMCACHE_ACC = Get-ItemProperty -Verbose -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility\" | Select-Object AppCompatCache -ExpandProperty AppCompatCache | export-csv -NoTypeInformation -Verbose -Append $var_InfoWin32_Reg_ShimCache_ACC

            $var_InfoWin32_Reg_ShimCache_CMB = $SavedForensicArtifactsCSV + $computername + "_ShimCache_Info.Win32_Reg_ShimCache_CMB.csv"
            $var_RIP_SHIMCACHE_CMB = Get-ItemProperty -Verbose -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility\" | Select-Object AppCompatCache -ExpandProperty CacheMainSDB | export-csv -NoTypeInformation -Verbose -Append $var_InfoWin32_Reg_ShimCache_CMB

            $var_InfoWin32_Reg_ShimCache_ST = $SavedForensicArtifactsCSV + $computername + "_ShimCache_Info.Win32_Reg_ShimCache_ST.csv"
            $var_RIP_SHIMCACHE_ST = Get-ItemProperty -Verbose -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility\" | Select-Object AppCompatCache -ExpandProperty SdbTime | export-csv -NoTypeInformation -Verbose -Append $var_InfoWin32_Reg_ShimCache_ST
        }
        catch
        {
            $vartempstring = "[ERROR] Failed To Pull SHIMCache Artifacts."
            if ($env_verbose -eq "V")
            {
                write-host -fore Red -back black $vartempstring
            }
            $vartempstring >> $SavedLogFile
            function_failwhale
            clear
        }
    }
    else
    {
        $vartempstring = "[ERROR] Failed To Pull SHIMCache Artifacts."
        write-host -fore Red -back black $vartempstring
        $vartempstring >> $SavedLogFile
        function_failwhale
    clear
    }
}

##################################### SLOW(ish) COMMANDS ##################################

Function Function_RIP_Alt_Data_Streams
{
    $ForensicFileStoreADS = $SavedForensicArtifacts + "\ADS\"
    $ForensicFileStoreADSfile = $ForensicFileStoreADS + "alternatedatastreams.txt"
    $var_DriveLetters = Get-PSDRive -PSProvider FileSystem
    foreach($var_Drive in $var_DriveLetters)
    {
        $var_DriveString = $var_Drive.ToString()
        $var_DriveSearch = $var_DriveString + ":\*"
        try
        {
            Get-Item -Path $var_DriveSearch -Stream * | Get-Content >> $ForensicFileStoreADSfile
        }
        catch
        {
            if ($env_verbose -eq "V")
                {
                write-host -fore Red -back black "[ERROR] Failed to Query Alternate Data Streams and Save Into A File."
                function_failwhale
                clear
            }
        }
    }
    ##cmd.exe /c start dir /s /r %SYSTEMROOT%\ | find ":DATA" ## Does not Pipe Within Powershell Properly
}

Function Function_RIP_VSS_INFO
#Pulled from https://stackoverflow.com/questions/40796634/how-to-enumerate-shadow-copies-of-a-given-file-or-folder
{
    try
    {
        $vartempstring = "[TRIAGE] Starting Collection of Info For Volume Shadow Copies."
        if ($env_verbose -eq "V")
        {
            write-host -fore Gray -back black $vartempstring
        }
        $vartempstring >> $SavedLogFile

        $var_InfoWin32_VSS_Copies = $SavedForensicArtifactsCSV + $computername + "_VolumeShadow_Info.Win32_VSS_Copies.csv"

        $shadowStorageList = @();
        $volumeList = Get-WmiObject Win32_Volume -Property SystemName,DriveLetter,DeviceID,Capacity,FreeSpace -Filter "DriveType=3" | select @{n="DriveLetter";e={$_.DriveLetter.ToUpper()}},DeviceID,@{n="CapacityGB";e={([math]::Round([int64]($_.Capacity)/1GB,2))}},@{n="FreeSpaceGB";e={([math]::Round([int64]($_.FreeSpace)/1GB,2))}} | Sort DriveLetter;
        $shadowStorages = gwmi Win32_ShadowStorage -Property AllocatedSpace,DiffVolume,MaxSpace,UsedSpace,Volume |
                    Select @{n="Volume";e={$_.Volume.Replace("\\","\").Replace("Win32_Volume.DeviceID=","").Replace("`"","")}},
                    @{n="DiffVolume";e={$_.DiffVolume.Replace("\\","\").Replace("Win32_Volume.DeviceID=","").Replace("`"","")}},
                    @{n="AllocatedSpaceGB";e={([math]::Round([int64]($_.AllocatedSpace)/1GB,2))}},
                    @{n="MaxSpaceGB";e={([math]::Round([int64]($_.MaxSpace)/1GB,2))}},
                    @{n="UsedSpaceGB";e={([math]::Round([int64]($_.UsedSpace)/1GB,2))}}

        # Create an array of Customer PSobject
        foreach($shStorage in $shadowStorages) 
        {
            $tmpDriveLetter = "";
            foreach($volume in $volumeList) {
                if($shStorage.DiffVolume -eq $volume.DeviceID) 
                {
                    $tmpDriveLetter = $volume.DriveLetter;
                }
            }
            $objVolume = New-Object PSObject -Property @{
                Volume = $shStorage.Volume
                AllocatedSpaceGB = $shStorage.AllocatedSpaceGB
                UsedSpaceGB = $shStorage.UsedSpaceGB
                MaxSpaceGB = $shStorage.MaxSpaceGB
                DriveLetter = $tmpDriveLetter
            }
            $shadowStorageList += $objVolume;
        }

        for($i = 0; $i -lt $shadowStorageList.Count; $i++)
        {
            $objCopyList = Get-WmiObject Win32_ShadowCopy  | Where-Object {$_.VolumeName -eq $shadowStorageList[$i].Volume} | select DeviceObject, InstallDate
            $shadowStorageList[$i] | add-member Noteproperty shadowcopies $objCopyList
            $shadowStorageList[$i] | export-csv -NoTypeInformation -Append -Verbose $var_InfoWin32_VSS_Copies
        }
    }
    catch
    {
        if ($env_verbose -eq "V")
        {
            write-host -fore Red -back black "[ERROR] Failed to Query Volume Shadow Copies."
        }
        function_failwhale
        clear
    }
}

Function Function_Hash_All_Files_OS_DRIVE
{
    $ForensicFileStoreADS = $SavedForensicArtifacts + "\HASHES\"
    $ForensicFileStoreADSfile = $ForensicFileStoreADS + $computername + "_FileHashes_Info.Win32_SHA512_Hash_OS_Drive.csv"
    $var_DriveLetters = Get-PSDRive -PSProvider FileSystem
    foreach($var_Drive in $var_DriveLetters)
    {
        $var_DriveString = $var_Drive.ToString()
        $var_DriveSearch = $var_DriveString + ":\*"
        try
        {
            Get-ChildItem -Path C:\ -Recurse | Get-FileHash -a SHA512 | Format-List | export-csv -NoTypeInformation -Verbose -Append $ForensicFileStoreADSfile
        }
        catch
        {
            write-host -fore Red -back black "[ERROR] Failed to Query and Calculate File Hashes and Save Into A File."
            function_failwhale
            clear
        }
    }
    ##cmd.exe /c start dir /s /r %SYSTEMROOT%\ | find ":DATA" ## Does not Pipe Within Powershell Properly
}

Function Function_RIP_TRIAGE_SELECTOR
{
    clear
    echo "------Starting TRIAGE Collection-----" >> $SavedLogFile
    $var_CollectionPlanPromptText = "[PROMPT] What Kind of TRIAGE Do You Wish To Conduct (Enter Nothing For Quick TRIAGE)?"
    write-host -fore White -back black $var_CollectionPlanPromptText
    write-host -fore White -back black "################################################################################"
    write-host -fore White -back black "### Select (1) - Quick Triage                                                ###"
    write-host -fore White -back black "###              [Triage Script, Event Log Pull, Registry Pull]              ###"
    write-host -fore White -back black "### Select (2) - Comprehensive Triage                                        ###"
    write-host -fore White -back black "###              [Includes Above and VSS, SHIMCACHE, AMCACHE, RDP_Bitmap]    ###"
    write-host -fore White -back black "### Select (3) - Comprehensive Triage + More (Takes A Lot Of Time)           ###"
    write-host -fore White -back black "###              [Includes Above And Calculates File Hashes, ADS detection]  ###"
    write-host -fore White -back black "### Select (9) - Skip TRIAGE Collection and Move To Disk Collection Prompt   ###"
    write-host -fore White -back black "################################################################################"
    $var_CollectionPlanPrompt_Triage = Read-Host -Prompt "[1/2/3/9]"

    if ($var_CollectionPlanPrompt_Triage -eq "1")
    {
        Function_RIP_TRIAGE
        Function_RIP_Registry
        Function_RIP_Event_Logs
        Function_RIP_Schedule_Tasks
        Function_Get-DiskInfoMain
    }
    if ($var_CollectionPlanPrompt_Triage -eq "2")
    {
        Function_RIP_TRIAGE
        Function_RIP_Registry
        Function_RIP_Event_Logs
        Function_RIP_Schedule_Tasks
        Function_RIP_RDP_BITMAP
        Function_RIP_AMCACHE
        Function_RIP_SHIMCACHE
        #Function_Triage_Meta-Blue_DLLSEARCHORDER
        #Function_Triage_Meta-Blue_ProcessHash
        #Function_Triage_Meta-Blue_DriverHash
        #Function_Triage_Meta-Blue_DLLHash
        Function_Get-DiskInfoMain
    }
    if ($var_CollectionPlanPrompt_Triage -eq "3")
    {
        Function_RIP_TRIAGE
        Function_RIP_Registry
        Function_RIP_Event_Logs
        Function_RIP_Schedule_Tasks
        Function_RIP_RDP_BITMAP
        Function_RIP_AMCACHE
        Function_RIP_SHIMCACHE
        #Function_Triage_Meta-Blue_DLLSEARCHORDER
        #Function_Triage_Meta-Blue_ProcessHash
        #Function_Triage_Meta-Blue_DriverHash
        #Function_Triage_Meta-Blue_DLLHash
        Function_RIP_Alt_Data_Streams
        Function_RIP_VSS_INFO
        Function_Hash_All_Files_OS_DRIVE
        Function_Get-DiskInfoMain
    }
    if ($var_CollectionPlanPrompt_Triage -eq "9")
    {
        if ($env_verbose -eq "V")
        {
            write-host -fore Gray -back black "[INFO] Skipping Additional TRIAGE of the Device."
        }
        echo "[INFO] Skipping Additional TRIAGE of the Device."  >> $SavedLogFile
        Function_Get-DiskInfoMain
    }
    if (($var_CollectionPlanPrompt_Triage -ne "1") -and ($var_CollectionPlanPrompt_Triage -ne "2") -and ($var_CollectionPlanPrompt_Triage -ne "3") -and ($var_CollectionPlanPrompt_Triage -ne "9"))
    {
        write-host -fore Red -back black "[ERROR] Your Response: (" + $var_CollectionPlanPrompt_Triage +  "). was Not YES or NO"
        function_failwhale
        clear
        Function_RIP_TRIAGE_SELECTOR
    }  
}

Function Function_RIP_TRIAGE_MAIN
{
    clear
    echo "------Starting TRIAGE Collection-----" >> $SavedLogFile
    $var_CollectionPlanPrompt_Triage_Main_Text = "[PROMPT] Do You Wish to Conduct Additional TRIAGE of the Device?"
    write-host -fore White -back black $var_CollectionPlanPrompt_Triage_Main_Text
    $var_CollectionPlanPrompt_Triage_Main = Read-Host -Prompt "[Yes/No]"

    if ($var_CollectionPlanPrompt_Triage_Main -eq "YES")
    {
        Function_RIP_TRIAGE_SELECTOR
    }
    if ($var_CollectionPlanPrompt_Triage_Main -eq "NO")
    {
        if ($env_verbose -eq "V")
        {
            write-host -fore Gray -back black "[INFO] Skipping Additional TRIAGE of the Device."
        }
        echo "[INFO] Skipping Additional TRIAGE of the Device?"  >> $SavedLogFile
        Function_Get-DiskInfoMain
    }
    if ($var_CollectionPlanPrompt_Triage_Main -ne "YES")
    {
        if ($var_CollectionPlanPrompt_Triage_Main -ne "NO")
        {
        write-host -fore Red -back black "[ERROR] Your Response Was Not YES or NO."
        function_failwhale
        #clear
        Function_RIP_TRIAGE_MAIN
        }
    }    
}

##########################################################################################
#################################### Hard Drive Info #####################################
##########################################################################################

Function Function_Get-DiskInfoWMIC
{
    if ($previouslyran -eq 0)
    {
        echo "------Gathering Disk Information-----" >> $SavedLogFile
        $MainSystemDrive = $env:SystemDrive
        $MainSystemDrive = "[DISK] -Main System Drive is: " + $MainSystemDrive
        $var_NumberofDrives = (get-disk | Where-Object {$_.Size -gt 0 }).Number.Count
        try
        {
            $SELECT_INFO_HDD_model = wmic diskdrive get model
            $SELECT_INFO_HDD_model = $SELECT_INFO_HDD_model|Where{$_ -ne ""}|ForEach{$_.Replace("Model","")}
            $SELECT_INFO_HDD_model = $SELECT_INFO_HDD_model|Where{$_ -ne ""}|ForEach{$_.Replace("\r+\r\n+","")}
            $SELECT_INFO_HDD_model[1]

            $SELECT_INFO_HDD_serial = wmic diskdrive get serialNumber
            $SELECT_INFO_HDD_serial = $SELECT_INFO_HDD_serial|Where{$_ -ne ""}|ForEach{$_.Replace("Serial","")}
            $SELECT_INFO_HDD_serial = $SELECT_INFO_HDD_serial|Where{$_ -ne ""}|ForEach{$_.Replace("\r+\r\n+","")}
            $SELECT_INFO_HDD_serial[1]

            $SELECT_INFO_HDD_size = wmic diskdrive get size
            $SELECT_INFO_HDD_mediatype = wmic diskdrive get mediaType
            $SELECT_INFO_HDD_partitions = wmic diskdrive get Partitions
            echo "------Dumping Disk Information-----" >> $SavedLogFile
            echo "-----------------------------------" >> $SavedLogFile
            echo $SELECT_INFO_HDD_model >> $SavedLogFile
            $ALL_INFO_HDD = wmic diskdrive
            Function_Get-DiskSMARTInfo
            $previouslyran = 1
        }
        catch
        {
            $var_Disk_serials = WMIC path win32_physicalmedia get serialnumber
            $previouslyran = 1
        }
    }
    else
    {
        echo "Already Ran"
    }
}

Function Function_Get-DiskSMARTInfo
{
    try
    {
        echo "-----Gathering SMART Information-----" >> $SavedLogFile
        $previouslyran = 0
        $SMART_INFO_HDD = wmic diskdrive get status
        $SMART_INFO_HDD = $SMART_INFO_HDD|Where{$_ -ne ""}|ForEach{$_.Replace("Status","")}
        $SMART_INFO_HDD = $SMART_INFO_HDD|Where{$_ -ne ""}|ForEach{$_.Replace(" ","")}
        $SMART_INFO_HDD = $SMART_INFO_HDD|Where{$_ -ne ""}|ForEach{$_.Replace(" ","")}
        $Iteration = 1
        foreach ($line in $SMART_INFO_HDD)
        {
            echo "[INFO] New Drive Found:" >> $SavedLogFile
            echo "------Gathering Disk Information-----" >> $SavedLogFile
            if ($SMART_INFO_HDD -ne "OK")
            {
                $LineOut = "[ERROR] Drive [" + $Iteration + "] Has SMART Errors" >> $SavedLogFile
                write-host -fore Red -back black $LineOut 
                $HDError = True
                ##Do an Array of failed drives here##
                $Iteration +=  1
            }
            else
            {
                $LineOut = "[DISK] Drive [" + $Iteration + "] Looks Good" >> $SavedLogFile
                $var_DriveCallNumber = $Iteration - 1
                Function_Get_DiskInfoSpecifics
                if ($env_verbose -eq "V")
                {
                    $LineOut                    
                }
                $Iteration +=  1
            }
        }
        Function_Full_Disk_Plan
    }
    catch
    {
        if ($env_verbose -eq "V")
        {
            write-host -fore Red -back black "[ERROR] Could Not Pull SMART Info"
        }
        echo "[ERROR] Could Not Pull SMART Info" >> $SavedLogFile
        pause
        function_failwhale
        clear
    }
    finally
    {
        function_EndClearCleanUp
    }
}

Function Function_Get_DiskInfoSpecifics
{
    try
    {
        $DiskInfoWMIC_csv = $SavedForensicArtifactsCSV + $computername + "_Drive_Info.Win32_DiskInfo.csv"
        gwmi win32_logicaldisk | export-csv -NoTypeInformation -Append $DiskInfoWMIC_csv
        $var_temp_disk_variable = get-disk -Number $var_DriveCallNumber
        $var_temp_disk_variable_ConnectionCheck = get-disk -number $var_DriveCallNumber | Select-Object -exp BusType
        $var_DriveNumber = $var_DriveCallNumber + 1
        $var_temp_disk_variable_computername = $var_temp_disk_variable.PSComputerName
        $var_temp_disk_variable_location = $var_temp_disk_variable.Location
        $var_temp_disk_variable_partitionstyle = $var_temp_disk_variable.PartitionStyle
        $var_temp_disk_variable_name = $var_temp_disk_variable.FriendlyName
        $var_temp_disk_variable_manufacturer = $var_temp_disk_variable.Manufacturer
        $var_temp_disk_variable_model = $var_temp_disk_variable.Model
        $var_temp_disk_variable_firmware = $var_temp_disk_variable.FirmwareVersion
        $var_temp_disk_variable_serial = $var_temp_disk_variable.SerialNumber
        $var_temp_disk_variable_uniqueid = $var_temp_disk_variable.UniqueId
        $var_temp_disk_variable_guid = $var_temp_disk_variable.Guid
        $var_temp_disk_variable_allocatedsize = $var_temp_disk_variable.AllocatedSize
        if ($var_temp_disk_variable_computername -ne "")
        { 
            ###############################This Does Not Display Correct Results For Some External/Remote Drives ##################################
            if ($var_temp_disk_variable_computername -ne $var_ComputerName)
            {
                $var_temp_disk_variable_string_0 = "[DISK] Drive [" + $var_DriveNumber + "] appears to be remote. The location is: " + $var_temp_disk_variable_computername + " or: " + $var_temp_disk_variable_location
                echo $var_temp_disk_variable_string_0 >> $SavedLogFile
            }
        }
        $var_temp_disk_variable_string_1 = "[DISK] Drive [" + $var_DriveNumber + "] Name: " + $var_temp_disk_variable_name 
        echo $var_temp_disk_variable_string_1 >> $SavedLogFile
        $var_temp_disk_variable_string_2 = "[DISK] Drive [" + $var_DriveNumber + "] Make: " + $var_temp_disk_variable_manufacturer + " Model: " + $var_temp_disk_variable_model + " Firmware: " + $var_temp_disk_variable_firmware
        echo $var_temp_disk_variable_string_2 >> $SavedLogFile
        $var_temp_disk_variable_string_3 = "[DISK] Drive [" + $var_DriveNumber + "] Serial: " + $var_temp_disk_variable_serial + " GUID: " + $var_temp_disk_variable_uniqueid
        echo $var_temp_disk_variable_string_3 >> $SavedLogFile
        $var_temp_disk_variable_allocatedsizeGB = $var_temp_disk_variable_allocatedsize / 1073741824
        $var_temp_disk_variable_string_4 = "[DISK] Drive [" + $var_DriveNumber + "] Allocated Size (In Bytes): " + $var_temp_disk_variable_allocatedsize + ". In GB's: " + $var_temp_disk_variable_allocatedsizeGB
        echo $var_temp_disk_variable_string_4 >> $SavedLogFile

        $var_temp_disk_variable_test = $var_temp_disk_variable_ConnectionCheck | Out-String
        $var_temp_disk_variable_test = $var_temp_disk_variable_test|Where{$_ -ne ""}|ForEach{$_.Replace("BusType","")}
        $var_temp_disk_variable_test = $var_temp_disk_variable_test|Where{$_ -ne ""}|ForEach{$_.Replace("-------","")}
        $var_temp_disk_variable_test2 = $var_temp_disk_variable_test.Trim("`r`n")
        $var_temp_disk_variable_test3 = [String]$var_temp_disk_variable_test2
        $var_temp_disk_variable_test4 = [String]"SATA" 
        if ($var_temp_disk_variable_test4 -eq $var_temp_disk_variable_test3)
        {
            $var_temp_disk_variable_string_0 = "[DISK] Drive [" + $var_DriveNumber + "] appears to be Directly Connected (SATA)."
            echo $var_temp_disk_variable_string_0 >> $SavedLogFile
            function_CollectionPlanPrompt
        }
        if ($var_temp_disk_variable_test2 -eq "SCSI")
        {
            $var_temp_disk_variable_string_0 = "[DISK] Drive [" + $var_DriveNumber + "] appears to be Directly Connected (SCSI)."
            echo $var_temp_disk_variable_string_0 >> $SavedLogFile
            function_CollectionPlanPrompt
        }
        if ($var_temp_disk_variable_test2 -eq "USB")
        {
            $var_temp_disk_variable_string_0 = "[DISK] Drive [" + $var_DriveNumber + "] appears to be Externally Connected (USB)."
            echo $var_temp_disk_variable_string_0 >> $SavedLogFile
            function_CollectionPlanPrompt
        }
        if ($var_temp_disk_variable_test2 -eq "IDE")
        {
            $var_temp_disk_variable_string_0 = "[DISK] The Drive [" + $var_DriveNumber + "] appears to be Directly Connected (IDE)."
            echo $var_temp_disk_variable_string_0 >> $SavedLogFile
            function_CollectionPlanPrompt
        }
        if ($var_temp_disk_variable_test2 -eq "EIDE")
        {
            $var_temp_disk_variable_string_0 = "[DISK] The Drive [" + $var_DriveNumber + "] appears to be Directly Connected (E-IDE)."
            echo $var_temp_disk_variable_string_0 >> $SavedLogFile
            function_CollectionPlanPrompt
        }
    }
    catch
    {
        if ($env_verbose -eq "V")
        {
            write-host -fore Red -back black "[ERROR] Could Not Pull Specific Drive Info" 
        }
        echo "[ERROR] Could Not Pull Specific Drive Info" >> $SavedLogFile
        function_failwhale
        clear
    }
}

Function Function_CollectionPlanPrompt
{
    $var_CollectionSizePlanadd = [int]$var_temp_disk_variable_allocatedsizeGB
    $vartempstring = "[DISK] Total size of currently selected drive is: " + $var_CollectionSizePlanadd + "GB"
    write-host -fore Gray -back black $vartempstring
    $var_CollectionPlanPromptText = "[PROMPT] Do You Wish to Add the Internally Connected Device (" + $var_temp_disk_variable_name + ") with serial: " + $var_temp_disk_variable_serial + " to the Collection Plan?"
    write-host -fore White -back black $var_CollectionPlanPromptText
    $var_CollectionPlanPrompt = Read-Host -Prompt "[Yes/No]"

    if ($var_CollectionPlanPrompt -eq "YES")
    {
        $var_DriveNumber >> $SavedVarFTKFile
        $var_CollectionSizePlanadd >> $SavedVarFile
        if ($env_verbose -eq "V")
        {
            write-host -fore Gray -back black "-----------------------------------------------------"
        }
    }
    if ($var_CollectionPlanPrompt -eq "NO")
    {
        if ($env_verbose -eq "V")
        {
            $string_CollectionNoPromptResponse = "[INFO] Skipping Drive: [" + $var_DriveNumber + "]."
            write-host -fore Gray -back black $string_CollectionNoPromptResponse
            write-host -fore Gray -back black "-----------------------------------------------------"
        }
    }
    if ($var_CollectionPlanPrompt -ne "YES")
    {
        if ($var_CollectionPlanPrompt -ne "No")
        {
            write-host -fore Red -back black "[ERROR] Your Response was not Yes or No"
            function_failwhale
            clear
            function_CollectionPlanPrompt
        }
    }            
}

Function Function_Full_Disk_Plan
{
    if ($env_verbose -eq "V")
    {
        write-host -fore Gray -back black "--Generating Forensic Image Plan--"
    }
    echo "--Generating Forensic Image Plan--" >> $SavedLogFile
    ForEach ($line in (get-content $SavedVarFile))
    {
        $var_tmp_int = [int]$line
        $global:var_CollectionSizePlanTotal = $var_tmp_int + $global:var_CollectionSizePlanTotal
    }
    $var_CollectionSizePlanTotalTB = $global:var_CollectionSizePlanTotal / 1024
    clear
    $var_string_final_plan_output = "[INFO] The Total Amount Needed to Create Forensic Images is: " + $global:var_CollectionSizePlanTotal + "GBs." + " Or (in TBs): " + $var_CollectionSizePlanTotalTB + "TBs." 
    $var_string_final_plan_output >> $SavedLogFile
    write-host -fore Gray -back black $var_string_final_plan_output
    write-host -fore yellow -back black "[PROMPT] Do You Wish to Accept the Collection Plan and Start Collection?"
    $var_CollectionPlanPromptTextConfirm = Read-Host -Prompt "[Yes/No]"

    if ($var_CollectionPlanPromptTextConfirm -eq "YES")
    {
        Del $SavedVarFile
        Function_Full_Disk_Collect
    }
    if ($var_CollectionPlanPromptTextConfirm -eq "NO")
    {
        Del $SavedVarFile
        if ($env_verbose -eq "V")
        {
            write-host -fore yellow -back black "[INFO] Restarting Collection Plan Process."
        }
        clear
        Function_Get-DiskInfoMain
    }
    if ($var_CollectionPlanPromptTextConfirm -ne "YES")
    {
        if ($var_CollectionPlanPromptTextConfirm -ne "No")
        {
            write-host -fore Red -back black "[ERROR] Your Response was not Yes or No."
            function_failwhale
            clear
            Function_Get-DiskInfoMain
        }
    }      
}

Function Function_Full_Disk_Collect
{
    ForEach ($line in (get-content $SavedVarFTKFile))
    {
        $StoredForensicDiskLocation = $StoredForensicLocation + "\Disk\"
        $DiskVarNumber = $line - 1
        $DiskCollectVar = "\\.\PHYSICALDRIVE" + $DiskVarNumber
        $StoredForensicDiskLocationStore = $StoredForensicDiskLocation
        $StoredForensicDiskLocationStoreFile = $StoredForensicDiskLocationStore + "DiskCollect_" + $DiskVarNumber
        $var_StaredForensicDiskLocationCheck = Test-Path -path $StoredForensicDiskLocationStore
        if ($var_StaredForensicDiskLocationCheck -eq $FALSE)
        {
            try
            {
                mkdir $StoredForensicDiskLocationStore
            }
            catch
            {
                if ($env_verbose -eq "V")
                {
                    write-host -fore Yellow -back black "[INFO] Folder Already Created."
                }
            }
        }
        cmd.exe /c start ./src/ftk/ftkimager.exe --verify $DiskCollectVar $StoredForensicDiskLocationStoreFile
    }
}

Function Function_Get-DiskInfoMain
{
    clear
    $agreement1string = "[PROMPT] Do You Want To Try And Pull Full Disk Images?"
    write-host -fore white -back black $agreement1string
    $agreement1 = Read-Host -Prompt '[Yes/No]'
    if ($agreement1 -eq "Yes")
    {
        Function_Get-DiskSMARTInfo
    }
    if ($agreement1 -eq "No")
    {
        write-host -fore Gray -back black "[INFO] Ending Stack Now"
        pause -s 3
        clear
        function_EndClearCleanUp
    }
    else
    {
        write-host -fore Red -back black "$agreement1 is not a valid response."
        write-host -fore Red -back black "[ERROR] Response must be either a Yes or No"
        function_failwhale
        pause -s 3
        Function_Get-DiskInfoMain
    }
}

######################################################################
############################### LA MER ###############################
######################################################################

function function_Post_Processing_JSON_Conversion
{
    foreach ($var_CSV_filename in Get-ChildItem $SavedForensicArtifactsCSV)
    {
        $SavedForensicArtifactsJSONStorageTemp = $var_CSV_filename.basename
        $SavedForensicArtifactsJSONName = $SavedForensicArtifactsJSON + "\" + $SavedForensicArtifactsJSONStorageTemp + ".json"
        Import-Csv $var_CSV_filename.fullname | ConvertTo-Json | Out-File $SavedForensicArtifactsJSONName
    }
}

function function_EndClearCleanUp
{
    if ($env_verbose -eq "V")
    {
        write-host -fore Gray -back black "[FIN] Staring Cleanup And Ending Processes"
    }
    echo "[FIN] Staring Cleanup And Ending Processes" >> $SavedLogFile

    if ($env_verbose -eq "V")
    {
        write-host -fore Gray -back black "[FIN] Ending Network Tracing"
    }
    echo "[FIN] Ending Network Tracing" >> $SavedLogFile
    
    function_Post_Processing_JSON_Conversion    
    netsh trace stop
    if ($env_verbose -eq "v")
    {
        echo "----------- FIN ----------" >> $SavedLogFile
    }
    function_fin
    pause
}

$ErrorActionPreference = 'Inquire'
Function_Agreement


###########################################################################
################################# ENDING ##################################
###########################################################################

############################### LEGAL NOTES ###############################

###########################################################################
###               Copyright (C)  2021  s3raph                             #
###                                                                       #
### This program is free software: you can redistribute it and/or modify  # 
### it under the terms of the GNU General Public License as published by  #
### the Free Software Foundation, either version 3 of the License, or     #
### (at your option) any later version.                                   #
###                                                                       #
### This program is distributed in the hope that it will be useful,       #
### but WITHOUT ANY WARRANTY; without even the implied warranty of        #
### MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         #
### GNU General Public License for more details.                          #
###                                                                       #
### You should have received a copy of the GNU General Public License     #  
### along with this program.                                              #
### If not, see <https://www.gnu.org/licenses/>.                          #
###########################################################################

################################## FIN ####################################
