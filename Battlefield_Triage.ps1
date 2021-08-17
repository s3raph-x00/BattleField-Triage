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
        function_KatnissSalute
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
########################### MEME WORTHY ##############################
######################################################################

function function_KatnissSalute
{    
    $pwd = (Get-Item -Path ".\" -Verbose).FullName
	Start-Sleep -m 350
    Clear  
	(New-Object Media.SoundPlayer "$pwd/1.wav").Play()
	write-host "?SNHHHHHHNQO??77??77???SOOSOOOSSOOO??COC????OCOO?COOOOSCCCC??SSOC?CCC??C???CCCOOOCCCOO?77SS??7?????CC?>77??????OOO?>777?>77>77CCOOOC7??C??????7??7CN"
	write-host "7SHHHHclearHNNNQC??7>7>77COOCOSOOCCOCC77??OSC??CC?COO??CCCCC??CO?OSCOOC?SOC??OC?C?C?C????C??!7SSOO77??CCC?77???C?77?OC7!7777?>77>!>?COSQO77CCC77777!"
	write-host "CQNHHHHHHNQC77!7?777CCCCCC???CCCC?777COC?CC?C??C???CCC???C??CCCOC?C????CO??77777????????CSSQO??????C77>7777?7?OSC7>77??7???77?CCCCC7?7777777?7>?77CN"
	write-host "CSNHHQHHHNSC7777??7???7OOC?????OCC>>>?OC?OC??????7??C????OC?OC?C7??7??CCC??7?7???7?????CSSSQC?7?C?777777777???CQC7?CCOC???77!77?7>>77?77>77777777>?H"
	write-host "7ONHHHHHHNSC777?C???OOOOCCC??7??7:---!C??OSCC??7??C??????OCCCC???77?COOCC777?7CSC?77777COO???7??7?7>77CC7777777OOCCO??7777>>>>777???777CC??77777?7?H"
	write-host "7ONNHHHHHHOC777?OO?COOSCC77777?7>-:-:>>CCCCOC?C?C?C??7?C?????7777??COSC??????COOC???77?OO?>>7??7?777?COSOC??777OO??77>>7777777?????C?77COSO??777?7?H"
	write-host "7SNHHHHHHHO?7???OCCCQSOOO?77?????:77C>>OC???7?CCCCC?CCC?7>>?????777??C?????C??CO?7??CC???7???7?CC??CCCCCCCC7777?7>77>>77??7>7??77?7>?7>>77??CC??>>?H"
	write-host "?QNHHNHHHNO?7CCCC???SSOOOC?77?7?77CCC7>????>7?OOCO?COOO?777CO???77>77?77????COCC7>7?CC777?C????CCC??C?7777??>77777???7>7?C777?7777>7??7777?C?C??7!?H"
	write-host "OHHHHHNHHNO?7??77?77CCOCC??>7?7?7??7?777?7>7?CC???CSHQO7?CCCC7??7>77??C??????C?7>7?CCC??7?CC??CCOOC777!77CC???77?COO?777?7!?7?7>>>77???77COCC???7!?H"
	write-host "?QNHNHHHHNO??C?77777COOCC??>7????C?77?7777>7?C??7?CQQQC??CCCC>7?77?7??????????7>>7?COC7????C??CCCCC?77>77CCCC??7?COC???7?77?7?7>7>77??C?COSC?7??7>?N"
	write-host "!SNHHHHHHHO?CC??7?>7COSO??777CCOOC?7????>>>77??777COC?77?CO??>77777>?C???7777?7>>7?CCC7C????C???OSC??777??COOOC??7??CC?7?777C????7?C7?OOOSS?7>7?7>?H"
	write-host ">SNHHHHHHNSCCOCCCCCCCCC7??77CCOOSSO?CC??7??7?777>7????>777??7?CC?777777?7????7777???77?CC?CCSOCOSSO?7?C??CCOOS?C??CCCCCC77????OCO???77OSOCC7>7>7>!?H"
	write-host ">SNHHHQHHNOCCOOSQSSC77???COCOOSOSSOOOC???OOOS???>>?77>>?777??OC???77??CCC??777777?CC77?CCOOSSO?COSC??OOC?CCCCC?7C?COC???77????OSO?????OO?CC?7>!!>:?N"
	write-host "CQHHHHHHHNO7CSOOOOC?7777COQOOOSSQSO?CCO??CCSSO?7>7>>!!>>>7???CC?77?777?77??C777777>>>>777C?SO7>7??CCC?C?777777??77???777?CCCCOOO????????COC??77777?N"
	write-host "OQNHHNNHHN7>7?C?CO?77>?77CO??CCOOSC7?CO?7??OOC77>7>>!!>77?CC?>7777>77777777C?>???7!>!!>7>7?O?7?777CC?7???777??7??7?77777CSSC7C?7?CCOC77COC?!7C????CH"
	write-host ">QNHHHHHNM?!>?C7CCCC77>??7>77?7?COCOSSSC7>7777?>>>??777?CC?C?>>7???7??77?C?7??CCC77>7777777???C??7OC?>>7>>7>7?7?7>777!???CO7>7CCCSSSC77?CC?>>OSOC?CH"
	write-host "7SNNHHHHHN7!7C??OOCCC???CC????77CCOOCOC?7?7>>7C7!>7????777>?7>777??777?777?7?COCC?777777???77?OSO?OOC???777????7?C?77>>?CC7>>??C?SOOC77C??C??SQO?7CH"
	write-host "?QNHHHHHHN7!7???SC??7???CO7>77??77O?CC77??7777?7>>7??7?>>>!77777??C7!>7777>>????>77???CC??????OOSCSCCOSOOCCSC7?C?OSOCCSOC7>77CC???SCCC?C7CC?COO?CCCH"
	write-host "?QNHHHHHNN7>7??7C?77>77???>!>??C7>OC??777777777>>77?777>>7777777??C7!>77?7>!7??7777??C?C???C?CCCO?S??COOCCCCO???COSSOOSSC777?CC???SCOCCO????CC??C?CN"
	write-host ">QHHHNHHNH7!777>77>7!!!7777>7?CC77?C?7?7>?77777!77??>>>77????>7??77!!!?7777>>?7>77>>>!!77?CO?7CCC??777CC7777CCCCOOHHHQQS?CC?OSC?OOOOC??C?C7??7>?C?CN"
	write-host "?QHHHHHHNN7>7??777?777!>7!>>777???7?7777777>77>7?CCC??77?C????777>77??C?7>7??CCC77>>>>>77??C?77>77777>7??77???CCCC?CCCSSOO?CC?7???CC??77OC?>>7?OSCOH"
	write-host "OHHHQHHHNN>!7C?77777>!777???>>7777>??77777777777???CC?7?OOO???77!!7???OC7>!777????7>>77>!>77>?>>!>!>7>>?77>>7???777??COSOOC????7?777??7COC7>>COQSOON"
	write-host "CHHHNHHHHH>!77?777!777??C77>>!!>>>>??7777??C?7??7??CC?7OSOOO?C?77???C?COC77?777777?7777>7??OCCCCCCCCC7>C??C???CC????CCCCC?7?C??OC??7CCOCC?7?CCOSC7CH"
	write-host "OHHHNHHHNN>:>7777?>77?OOC77!!!>?777???77??CC?>7?77?C???CC?C??C?77>??7?CC????77777!>7>>77CSQNHNNNNNNNQO777?CCC?CSC?7??????????77777?7?CC7>>7COOOOC7CH"
	write-host "SHHHHHNHNN:->77777777???77>!!!!>7???7777??77??77>>CO???!-!>:!!???7>!77?OCOC77?7?77777!>CCQSSCQHHQHHHNNHSO??OS?CS7?7?7?CC????7?7?>>77????CCOCOOOOC7?H"
	write-host "OHHHHHHNNM!!!777777777777?777!>777??7???7777??OC??OS???>:!7!!>???777?COOOC?>7??C?7!!??COSQHQSHHQSQHHHNNNNOC????O?7???OO??77?????C??77?COSCC77????!7H"
	write-host "SNHHHHNHNH!:!>77?777??C?CC??OCC?>>77>7??7>7C??SQC?COOOO7>?7C7?CC77C?OCOSO?7!7OC7?7:>HHQSOHHQNHOSHNHHHSQHNQO??CCC77OCOQO?C77??CCOCC7>7CSOC??7!>!?S7?N"
	write-host "OHHHNHHHNH!::>??7?7?CCCCCOOCOCC??7777?OC777C?7?O77?CCCO77????77??COOOCCSO??>???OCCSHQQCSQHHHNNHHHHHHHHQQHNH??C??7?OOSQO?7?77?OOOCC7??CC??CC?>>7?O?OH"
	write-host "SHHHNHHHNH!-!>7777??OOOCOSSOCCC???777CSCC77??>7C77??COC77????7?CCOSSOOCOOC?77?COCONHQSCSQHNHHQHQNHHNHHHQHNNC??????OOOSC77??7?OOOC????C?7??CC>>7?C7CH"
	write-host "SHHNHHHNNQ:!C????CCOQSOCCC?7?>COCOCCOSQSSC???>!>7?OOC?!!!7>?>!7CSQQSCCOCCOC777??SHHOCOSQHHMH?!-!?OHNHHHQQHHQ>>?777CCCC?7>?S77CC??OSOSS77>7?C7?C77:?M"
	write-host "SHHHNHHNNQ77C77?CCOSSSC?777>777COSQQQQHSSOOOC77777CC?7!!>7?7>!!>C?CC7??7?CC??C?7QNQSSSCHMNQ7-;;-->?OHHNQQQHNC>777?777?777>??7??OOOOSQSC??????C?77>CM"
	write-host "SHNHHQHHNH>:C7??COSSOOO7>?7?777CSQHQC7CSSSSQSSOOOO?77????COCC?7?O7??77??CCCCOCCHNHQHSCOMN?-.;;;;-;::CHHNHHHNNO7?777??7??77?COOSQSO?CCC???????C?7>>CN"
	write-host "SHHHHHHHNQ>!??COCOOOSSO???7??CCCOQSC7777CCOSSSSSS?77????CSSSCOOOO?7?????CCCC?CQHQHQSOOQNC..;-----;---!HNHHHNNHC777???7?????COSSHO?77?OOC7777????7!CM"
	write-host "OHNHHHHHNS77??OOCCCOO??777?COCCOQO77777C??CCCOOQO77>?77?OSSSOHHSSCCC?CCC7C??CHNHHHQSCSMO:.;;----;-::-:QNHHHHHNQ77???7???CSOQQQQQSO?CSOSO?!!>?7?C?!?M"
	write-host "SHNHHHHHNQ?7?CSOOOSQC??7??C??CCCSO7?7???7CC?OSOOC77>77?COOC?7?CCOCCC????C??>CHHHHHHQOQM?-;;;------:::!?HNHHHHHSO7>?77??7??CCSHSOOSOC77SO?77OC>>?C:?M"
	write-host "SHHHHHHHNQC?OSOOCOQQ777CCOOSSOOOSS7??CC?7??OOSO??7>7?CSOO??7!>C7OCOC?CC?O??>ONHHQHHSQHMC-;;;---:;::-!!?QHHHHHHQS7!7??7>7!77?OQC??C>7>>OO>7?S?>!77!7N"
	write-host "SNHHHHQHNQ7>CO?>CSHO777COOOOSSSSSSC7?CS?777??>>!!!>7CCC?C7?C!>OQ7>77CC??CCCCSNHHHHQHHNM>;;;;-------:!!?OSNNHHHQSC>7??7>>7?7COSC7??C7777?7?OS?!!77>CN"
	write-host "SNHHHHQHNQ7!?C77CSQO77?CCOCOSQQSSOC7?OSC7>>77>:!!!77CC???7??!?OQ!>7?OC?CCCCOSNHHHHHHHNM!;;;;-----::::>CCQHNHHHQSC????7?7???C?OC???C7??>77?OS?>!7?7ON"
	write-host "QHHHHHHHNS>:7?7??COC7?CC7COCSHQSSC?7?CSCC77?77>>??CCC7!?C77!7?OOCCOSO?CCCCCOQHQQHHHHHNQ-----;-:>---!>!:>CHNHHHHQOOOC77777?77>7OOOOCCS?7!7?OSC!>7CCSN"
	write-host "SNHHHHHHNH7!7?????????777?C7CCCCOOC?>7???>>77>7??C??7>7??7>7>7OC?OSC7>CSSC7OHHHHQQQHNNO;;----;---:-:>:7>7HNHHHNHCOO?7??77?C??COCCC??CC?7??C??77OCCSN"
	write-host "QHHHQNHHNH7>7?7CC???77!>??77??77?CC?>7>!777!77?7777777777>>77CCC?C?7>>CCC??QNHQHSQSHMH?-;;;------;!!-.:-:SQHHHNQ?777>??7?COCOOC?77>>????C77???CSC7SN"
	write-host "SHHHHHHHNS>!>>7OO?CC!:!?O777?7?7??C??77>7777777>!>>7??>777777???7>>777?C?CONNHHHQHHNHC>;;;;..;-:::!>7?COCSHHHHHNO>777?C?CQO?COSOCC????COOCCC?7OQSOSN"
	write-host "SNNHHHHHNS!:>>7COCSO>!7C?7>7?7?OOOO?C??7777?7>77>>77C?>>7>?7?C??7!!7?7?C?CSNHQHHHNHNCC>;.-:?>C777!!!QMNOOHHNHHHNQ77?????OSC?>?QQSSCOOCSSSOOC???CSHQN"
	write-host "QHHHHHHHNS7??7?COOOO777??7>7?CCCOSSOOC777>77>777>>7???7>7>7CC???>>777>?O>CSNHQQQHHHN?7>->?7SQHOC-:>7NQS??SHHHHHNQC!>>>>>7???>OSQQOOOC?SSOOSC?C77COQH"
	write-host "QHHHHHHHNQO??77?CC?7>>?77?7??C?COCS???>!>!!7>!>>>>>CC?>???CSSCC7>7C7???O>OHNQHQQNHHHSO7!---OSOSC-;7HNHQNHNHHHHHHHO!>?7!>>!OC?SHHQQOC7CSSCCC>7S?!?OQN"
	write-host "QNHHHHHHNQO?!!77??7777>7CCOOOC?7????7777CSC?77>>77>77?CC?OQOC7>!>>77777?7CSNHHQQHHNNQO!:?SHMHS?7-;7MQCHNQNNHHHQHHQ7777?CC?OC?OQNQQSOCOSO!!>>!7>?CCQH"
	write-host "QNHHHHHHNS77>>?7?>7?C?7OCCCOC77>77??77COSOOC7?7:>>>777COOQQQ7>!!!>777!7?>?ONNHHQQHHNQ7:OMHMHCH7!;.!QS-OQOHNHHNONHH>77??OOOCCOSOQQOOOOOHO!!>::!7SSOQN"
	write-host "QHHQHHHHNC!!!>77C?CO?C??COC??>>77?C???7CCCOC?>>7777??C?OQQSS???C7777777?7CSHNHHNHQHNHO?NNCN?:C::;;;?O!?SOQQQHNONNQ>7??OOOCOSSOOOOCCC?OQC!!7!!7?SQCON"
	write-host "QNHHHHHHN?>7>77>>7CCC?7???>7?CC7?OOC777777???777CQOSCCOSS?CO?OOOC?7???7??SQNNHHNQH??NH?!-:!!7-;-;;;CO!:7>?77HNQNNS!>?CSQQCCQS7>77>?C??C7!7>>>?SHQ?CN"
	write-host "QHHHQHHHN?>?C?77>!CC?77777>?CC??C?7777?77>7C77>7SNO7>>7OC77??OC??O?7?7?CSSQNHQHNHH:!MS:-;::::;;:-;:CN7!:---7SHNNNS>?CCOSO?777>>7????7777>>>>>COSS?OH"
	write-host "QHHHHHHHNO?CC?777COO7777777??7>>7?>>7>?7?77C?7C?SQ?>!!>7?CC??OSOCC7CC777?QHHHHHQNH--MH!.;--;------.!Q>!>>:!?ONNQNQ7??CC?>7>7!!>?77C?7>7>>>7>7SSSC7CM"
	write-host "QHNHHHHHNO??7>>!7OSO777?777C7>>7CC7777?777?OC>CCCC>>>77CSOC7COOC?77OC7777SHQQHHQNH-!MMC;;---;--;;;;7H!!:::-CQNHHHQ??C?77!>777!7?7!7>>>!!777>>C??!:?N"
	write-host "HHHHHHHHNO??777!??CC77???77?CCCCCC777>>77COO7>77777?SSOSC7>>?OC???7??77COHNHQHQSNH>-OHH.;;;;;::;;.:!;;:;..-CQQHHHO77?7>>!>>>?77?>>>>>7::>>7>>?7!>:CN"
	write-host "HHHHHHHHN??77??>77?C???OO???OS??????C????CCC77?7CCOOSSQO?!!>????7?>>?77ONNHNHNQQQC?!>ON-;;;;-!:;;!>-.-:;.7OQQQHHQC77?7>>>77>??>>!>>>77!>>>?>7>7>>!?N"
	write-host "QHHHHNNNN?!>7OO?!>>?CC??O?77CO?7COSSCOQQC?77C?OOSQSSQQO?777???C?77>>7?COQQHNHHSQQ!??>?M:;---::!?HN-;!:;;7QSQHQNHS??7?C??77?777!:>>77>7>7?>>7?77?7>CN"
	write-host "HNHHHHHHN7>7?COC>!>CCC?CO?>7CC?COQHQCOHHSC?7?OOSSSOOQQO?7?C?7777>7>77?COQHHHNH7OQO>C!?M>---:!;;:>>;-:;.-Q>:SNQHNSOCOOO?7777?77>!!>?77>7>777?C7?C?>ON"
	write-host "HNHHHHHNM7>7?OOC!>>CCCC?O?>>C??OSQQSOOQHSSC>7OCSOOOOQQO?7?O?>>>7>7>777?CHNHHNN7?OQ!S7CM!:-;::;;..;;-;;.:M;.SNOHNHSCOSO?777>C7>77:>7?777>77?CO7?CC7ON"
	write-host "HNHHHHHHN?>:!CC?7??7?CCC?7?CC??7COOCCOHHOSSHSS??OSOSSSSSSOOO7>>7?7?7?77OHSOQNN-::S>!>7M?-:!::;;;;;:-;;!S7.;HNSHHSHSCCCCOO777C?777?OSCOOCOSOC7!>>7>ON"
	write-host "QHHHHHHHNC:-;7777C?7C??C7>7SCCO??????SHO?CSNSOC?OOOCOOOHQOOO?77??7>77??ONCCQHM: .!S>!?MS>:!--;;;;-!;.!QO.->MNOCH7CNC>OSHN?77?>>7??CCCO7CQSC>!!>>!!ON"
	write-host "HHHNHHHNN7:>>?C?7CCOCOCCC>7CCCOC7!!7?SO>!>7??OSCOOCOOOQQS?CSOSQQC777??COQCOHHNQ>.!NO;;?N?:---:----::-?7..CQNQ77QC7QS?SQSO7??77?COOCCOS?COC7!>!!77!?M"
	write-host "QHHHNHHNN!!7CCSS7?CSOOO??7>??COC7!7>7C7!7?77?SHSOOOOSSSS?7?SSQHHSC?COCOSQCOHNHNNOSMS-.>HQ:;:-:--!;-:C7..7QNHH77OOCQQCOC77!7OCSQQQSQHQHHSC?777?>7??ON"
	write-host "HHHHHNNNH!7CCCCC>!!>?7?77>!7?COSCCC?7C77???7?OQQSSQOCCCO?>7CCSQQSOSOOCSSOOSNHHHNNNMH---CN!-!-;---;-77-.:NNHNS7CHQQHHOC77>>??CCCC?CQQQC??>!!?O?7???SN"
	write-host "HHHHHHHNH>?SC??7>:!7OCCCC?7CCSSSOOOCCC??C777?CSSSOSO77?CCC?7?OQQSOOOOOSSOQQNQHHHHHHH>:;!?!!:-;!-;-!7:..?MHHH?!?QSSHC7C77?C7>77??7?SQS7:>>!7OS?>!>>CN"
	write-host "HHHNHHHNH7CO!::>77?CSSSCOOOOSOOC7>7??>>7???7?>COC???CCC7COC!7?OSC?CSOCSCCHHHHHQHNNHSSC!--:!;-!:-;:?--.>QNHNQC:7?>7C!>S??7COCC?77?C77C?>7?CSQ7!>>>:CN"
	write-host "HHNHHHNNN!77!>7>!?C?QQSCOCOSSS?>>?C7??7>????7>OHQO7COC7>7C7>?OSSOSSQSOSSSHHHHHHHHNNC?CC::!:--:;;->-;;:HNQQQHS>7>>CC77O?7>7CSO>>777!777C???C?!>>!7!ON"
	write-host "HHHHHHHNH:!>>?7>!>7OSO?COCOQQO7>??OC7??C???777OQS?77C??7>C?>?QHQSSSSQSSQSNNHHHHNHNN?.:SS?;;--;;;>?;;:CMNNQHQO7>>7CCCCO777!>?C!>7?7777?C?7??>:7>??>ON"
	write-host "HHHHHHNHH>!>7?>!!!7CC?7COOOQS7!7CCCC77?777?777OC?>7???O?7C?7CQHHSSOQQOOSSHHHHHHHHNN>;-7HO;;;;;--?!;:7SMNHHHSC77!>7CCOSC?7!!7C7>7O7>777????>>>?7C?>ON"
	write-host "HHHHNHHNN-!!7?7>:!?C7>>?COSHO?7?OCCC77C?>7??>7?77>?CCOQOCCCCOQQQQQSHO>7CQQHHHHHHHNQ?;->Q7;;-::!>!;->:-QNHHQQO?77>?7?CSOO?>77?7>7C?>??7>7??777C7??>ON"
	write-host "HHHNHNNHH!:>C7777?OO??7CCCOC77C?7?>?CCC777?C777777SSOC???SHQQHQOCQHS!::7HHHQHHHHHNQ7::::;;--!!::;;!-. QHCOOC?C?7?C77OHQS?>>7!>>>>77??>>777?SOO7:!:OM"
	write-host "QNHHHHHNQ:7CC7?7?OOOCCCC?777>7?7?7!?SO???CC?7??77CSO??7?CSQHHHSOCSOOCSHHHHHQHHHHHNC>-:!-;;;-:-!!-:7;;-QS777>>7???COQHQO??>>7?77>???C7!7777?OOO7!:!ON"
	write-host "HNHHHHHNQ!CSC?CCCOHQOSSO7!>!>>>>?7!?C?7C????7C?!?SC>!>?QSCOSQQSSQC-?NNNHHHHNHHHHHNC--:-;----->NM:;:;:?MS>>>!>7CO??SQOC?7777?C?777SHQCCO7>777??>C77OM"
	write-host "HNHHHHHNQ7CC77CC?SQQSSSO7>7>??7777:??;-??>7?!SO -H?7?CSQS77?OS?CQQCHHHHHHQHNHQQHHNS:!:;-----;!77;-::CSNC7>!!!!>?77CSS?77>!>7?77?7?SOQHHC>77>7?>C?!CN"
	Start-Sleep -m 350
	Clear  
	write-host "COHHQHHHHHHQ?C?>?CCC???SSOCOQSQSSSOC???7?C??C?CSCOOOCOOCCOO??OSSO?7????????OOOCOOCCCCCC7>OSC?77??7??C?>77>>?7??COO??????7777!7?C??C?OC????C?C?????7Q"
	write-host "OCNHHHHHHNHS??7>7?77???OOOSOOOOOSOO?7COC???COC?O?CCOOOOC??CC?CSOOC?CC??C?777CCCOOC?C?CC77OSS?7????CO??>7???C7?7?CC?>777?7777>77?COOCC??C7????????7?Q"
	write-host "7OHHHHHHHNHS7?7>?>>777OCCSOCCCOCC777??SC???C???C??CC??C???O??SOCOC?COC??COC7?C7?7?7???C7>CSOS7?CCC7???777?C?7>7OC?!777?7>>7>!>7?OOOS?77?7>7>7>>7777S"
	write-host "?ONHHHHHHNQO777>??77??CCCC???CCCC??77?OC?CCCC??C???CCC????C?COCC????C7??O??7777?7????????OSSOC7????C77>7777???CQO?>77????7777>7C???????7777777>77?>S"
	write-host "CONHHQHHHNHO>?7>C??????COCC?C??O??>!>>CC??CC??7??7??C??7>OO?OOC?C??7??C?????77??77?C???CCOOSO?77CC77>7?7>77CC??SO??COOC???7>!>7?7>>7>777777777777>7Q"
	write-host "?CNHHHHHHHHO>777CCC??COOO????????>-::->??CCO???????C??????CCCC?7?777CCOO??77???CC?7777?CC???777??77>>7CCC77?77>CSO?C??7777>>>>77777??777CCC?7777??7Q"
	write-host ">OHNHHQHHNHO>?7?CCOCOOOOO7777??77::-:>!?COOOC?7????????C??7?????7?7?COO?C777??OOO?????C?C?>>7?7??777??OSOCC?777COC?7>>>77??7>??C?????777?COC?7777>>Q"
	write-host "7SNHHHHHHHQC7??C?OO?OOOOO?7777?77:>>?7>7OC??77CCCC??CCC??>>?????777????7??????CO?77?CC?7????77??C???C?C?C?C7>77?77777>777C7>7777777>77>>>77?????7!!Q"
	write-host "OSHHHHHHHHQO7CCCCC?7CCOOOC?77?7777?CC7>7C?7>7?OOCCCCOOS??77??C??77>>???7?????C?C77>?C?C7?7???7?CCC??C7?77>>??>7>77???7>77C7>7?7>77>>7?77777??C?C7>!Q"
	write-host "CQHHHHHHHNQC7C?>7777CCSCCC?>77??7??777777>>777C?77?CQSO???C??7>77777??C?7??C?C777>77COC?CCCC???OC?OC?7!>7??CC7?77COOC777777???7>>>7>77??CCOCC????7>Q"
	write-host "?OHNNHHHHHQO7??>7777COOCC??777???C?777777!!777CC77COSSC???CCC7>>77?7??????????77>>77OO?????C?C?CCCCC?7!77??OCC?77CCC???7777?7?777>777??CCCOC?77?777Q"
	write-host ">ONHHHHHHNQO?CC?7?>?CCCOC77777?CCO?7?C?77>!77??C>>?CC?777?CS?7777>7>7????7777777!7?C77???????O??OOCC?777???OOSO???7??OC?C777CC??77?C77?SOSOC7>7?7>>Q"
	write-host ">CNHHHHHHNHO7CCOCCCCCCC?7??>?CCOSSOC?C?????777777>77??7777??7??C?7>7777????77>77>7??77??CCCCOS??OSQ?7??????OO??7C??CCCCC?77?7?CCCC????COOOC?>>>!>!>H"
	write-host ">ONHHHHHHNQO?OOSSSOC777??CCCSOSQSQSCOOCC?OOOSC??7>?77>>7>77?7COC7?777?C??77?77777???777?COCSQS??COCC?OSC?77?C??7??COO?7?77?7??OSO???77?COCC??7>>>>>O"
	write-host "CSHHHHHHHHQO7SOCOOCC77>7?CSSOCOOSOCC?CC????OSO?7>!>>!!!>>7???CCC77?7777777??777>777>>>77777OO?77???O????7??>77?7777CC?>77?CCCOCCC??OC?7?COO77C?77?7S"
	write-host "OQNHHHNHHHQC!7CC?C??77>77?C????OOOC??OC?7??COO77>!7>!!>>7?CC7>>7>7>>7?77>????77???7>!!>7>77?7C?777?C777?7777777???77777>7CSC7?????OOC?>7OOC!>?CC??7Q"
	write-host "!CNHHHHHHNS7!7??CCOC??>????77?7?COOCCOSO7>>>>?7?>>>?777??C?77777777?7777?77>7?CO??7>7777?7777?COC7OO77>7777>7>7?7777>>77??O7>7?C7OSOC?7>?OC77CSSC?7S"
	write-host ":ONHHHHHHNSC>???COCC?C?CCCC>?777??CCOOC?777!>>??>>>7???77>>777>>>7??777777777?OCC?7777777???7?COOCOCC????????7?C?????>7??C?7>7???COOC???CC???SOSCC?N"
	write-host ">SNHHHHHHMQC!7?C?CC?777COC?>>7????C?7?77>7>>>>7?>!>7??7>>7!7>777>?7?>!>>777>77??>77?7??????C???CSCC??COOOOC7CC????OSSCCSS?777C?C?7OOCC?COC7?CO?7CCCH"
	write-host "7SNHHHHHHNS?>7??7?77>7>7?7>!!7?C?7???777>77>7>77>>77777!!777>77>7?77>:>7777>77777777?77?7??C?C?CC?C???CCC??7?C??C?OSQOOQS??7?C?C??COCC??OC?7?C7>?C?Q"
	write-host "!SHHHHHHHNO?777>77777>!77>!7777?7?7??777>?7777>>>???77>7777??7?7>7>7>!>7???!77?7777>>>>77C?O?77?C??7777?77777CCOOOOQQQQQO?C7OSC?OOSOOC?7?C?7??7>C??N"
	write-host "7SHHHHHHHNS?7??7777777!!>>>>>7>7???C?77777>77777??CC??777CC7??777>>>7?7C?7>>7???777>>>>77?7??77>>!>77777C7777?CCC??CCCCSOOCCC?77?7????7?CC?7>??CSOOQ"
	write-host "?QNHHHHHHNS7>??777777>>77???>>>777>7?777777?7777?7???????OO???7?>>77?CCOC>>77?7?7777777>!>>>7>>>>>>>7>>7C>!>77?77>>>??7SSOC????7???????COC?7>?OOSOOQ"
	write-host "CSNHNHHHHNC7>77>77!7777CCC7>!!>>7!!7???77???C77>7>??C?7OOOCCCC??7>7???COC?777777777>!>77>7CSSSSSOOOCOC77?????CCCC??77C?CC?7>7??CCCC?7?C???7>??CCC??S"
	write-host "?SNHHHHHHNO7>>777?>777?OOC7!!!!>7>7???777??CCC7>777C????C????C777>7?77?CCCC?77!77!>7>>>>7OHQQQHNHHNNNHO77??OCCCOCC?77??C????7?7?77??7?C7777?OOOOO?7Q"
	write-host "OQNHHHHHHNO7!7777777>7?7777!>!!>77?C?>777??>>??C7>?OC7?7!:>>!!77?7>>>??CSOO?77??>777>>>>7OSSSCOQQSHHHHHHQOCOOCCC?77?7?CC??7C????77777???CCOCC?OSO?>Q"
	write-host "?QNHHHHHNNC!!>7777>7>777>7?>??7?7777777?7>>7??COCCCOOC?7!:!>!77?77>7?CCOOCC>>7???7>:>?SSOQQQQSQQQSHQHHHHHHQ????C?77??COO?77??7??OC?7>7COOOC>>77?C7!S"
	write-host "CQQHHHHHNNO!!:>77?777??C?C77OCC?7>77>77??>>???CSO?7?SOC????C7??C?>?COOOSSC?!7?C?C?77CSQHQHHQHHHQSHHHHQQQQNNO???C?7COSQQCC?77?COCC?C7>?COC??7>!!>SO?H"
	write-host "CSHHNHHHNN7::!777?77COOOOOOCOO?????777??????7?7C?7?7OSO?7?C7777?CCOOOCCCOOC777?C??OQHQCSSSHQHHNNHHHHHHHQQHHHO?7????COQQC7>?7?COOC???7?C?77?C7!77C?7O"
	write-host "OSNHNHHHNN!:>>7777>7OOOCCOSOCC?C?C?77?CCCC??7?>?77?7OOO7!?C7777?OOSOOOCCOOO?77?OCOQHHSCSSSNQHQHQQHNNHHHQQHHMO777???OOSS?77C77?OOC????C?777?C?!77C7>O"
	write-host "HHHHHHHHHN7!C?>???OOSOOC???77?7COOSOSSQSSOC7?7>>7??COC>!!7??7:>>COOSC??C??C??77?CQHQCCSOSHNMH>;-!?CQNNHHQQQNH7>777?????7>>??7???COSOSSO?>77C7CC?>>!Q"
	write-host "CQHHHHHHNN7>C?7??COOSOC?7777>7>7COHQSOSQSSOO??7777CC??>!!7?C7!!>?????77?7CC??OC>CQHHSSCSSNNS>:;;;--!OSHHHHHHHC7>7?7777777>777??COOOSQQO?77777C??77>Q"
	write-host "?HNHHHHHHM7:7?7C?OOOOOOC7?77>77COSQSS?7OOCOQQSO?COC7???7CCOOCC?>O??77??7??C77SO7HNQQQSOSMH?;.;;;----:?HNHHHHNNO7>>77?7??777??SQQSOC77?C??7??7C?>>!7H"
	write-host "7SHHHHHHHN7>?C?OCOCOSSOC777??CCCOSQO777??CCOSOSOSO7777??COSSOCOOOC>7??CC?CC7?OOQHHHQSOOHM>;;;----;;---!ONHHHNNHO7>77??7????CCOSQQ??7?C?C?7>77?77?!>Q"
	write-host "CHHHHHHHNH?77?OOOOOOCC?7>?7???COOOC7777???CCOCCSOC7?77???SSSCQQSOC??C????CC77CSHHHHHQSONN:;;;-;;;;---:-?NHHHHNHSC?77??77?OSSSSQQSOOCOOOQO?!77?7???>Q"
	write-host "CQHHHHHHHN?7?COSOCOQO??????C??C?OSC77???7???COOOO?7>>7?CCOCC77CCCCOC????7CC77CHHHHHHHSQMS-;;;;-;---::!:?NNHHHHHSC7>77?77777CSHSS?CCC?7CS?77CC7!!?7!Q"
	write-host "CQHHHHHHNNOCOOC?CCSQ?7>CCOOSOOOOOSC?C?C?7???OOCC77>>?CSOO???!>C7OC7C??C?O?7?CQHHHHHHSSQMO;;;;;;;;:::!!:>QHHHHHHQC7>7777>!>>7CQOC>??7>>?OC77SO7!>7>>Q"
	write-host "?QHHHHHHHN?>7CC7?OQS?7?CCOCOSSQSSOO???SO?>>7?7!!!!>7?CC??7?C>>COC>77?CCC?CCCOQHHHHHHHHMMC;;;--;-----::7?CHHHHHHQO????77>>77??COO>?C77?7777?SC>!>7?7H"
	write-host "?QHHHHQHNH?>7??7?CQS7>???CCCSQQQSSO???SS?>>777!!!!>7C??77>??7>CCC777CCCC?CCCOQHQHHHHHNNH?.;;-;;;-:--!:7??QHHHHHHOC?C??7>>7??7?CO7C???C7>>7CSC>!>???H"
	write-host "CSHHHHHHNHSO>77???C?7?CC7??CCQQOSSC??7OCC7777?>>7??7C7777?7>-7OSC?OOOC?COOO7CHHQHHHHHHM?:;-;;-;-:--:-!:>>CQHHHHHSOOO?7?77??777?OCOS?OO?77>7SO7!7?COH"
	write-host "?HHHHHHHHNO?>7?????????77?C??CCCCOC?7>7?777>>>>77?C7777??77>:>OO?OS?7>7COSO>CHQHHQQQHHN?-;---;----:::!!!:?CHHHNHQOOC77?7>?????OS??7????7??C?777C?CON"
	write-host "CHNHHHHHHN?>7?7?C???7>!!7?7???77777??7>>>77!777777>77>>7>7>777?C7??7>77CCC??SNQHHQSQHHH?:;;--;;;-;-:!!;; !>HHHHHQO>>>7???CSC?OOO??77???7CC???7?SS?OH"
	write-host "?HHHHHHHNN7:>>>7CCCC7!!>C?77?77??7C?777>>>>7777!>>>>?7>!>7>77?7?7>>!7??????QNHHHQQHHNNQ7:;;;.;.;:!!!:>>COOONHHHHNS>>7?CCCSSS??OSOCC???COOOCC?7CSSSSH"
	write-host "OQHHHHHHNN?!>>>7OOOS?>77?>>!7???OCSOC??7777?7?!77>>!CC>77>77>CCC7!!>777CC77CNHQHHQNHNQO!-;:>>-OO:!7!7SMHQOSHHHHHNN>>?>>7?SS?>7OSQSSCOCOOCCOC?7??CSHH"
	write-host "ONNHHHHHHHC????COOOC?77?77>!>???SSSOCCC>>777>>>>>7!7C??>7>>?O???>!77777CC>>HNHSSSHHHNQ7>:!>?OSHH?!;>>QHS?>?NNNNHHN7:>!>>>7?C7?QQQOSOC?OSOOOC???>7OSN"
	write-host "CQHHHHHHHHSC?>777???>>7>7?7???COOCCCC?7>>>>!>!>>>>7?CC>?7?CSS???>7??7????77NNQHQSHHQHSS?-;-7OQCSC!;>NNNHMNNMS?NHHH?>?77?7>7CCCQHQQQO7?OSO??7!??!7CON"
	write-host "CHHHHHHHHNCC>:77??77>7>?CC?OSOC?>7??777?CSCC?>>7!7>77??CCSSQO?>7>!777>7777?QNQHNHQQQNQS7:CCNNHQO7:.:NHCQMCO?- QNHNS?77??C??OCCOQHQSSOOSS?>!!:!7>CCOH"
	write-host "CNHHHHHHHN7>>!>7C77?????CSOCO?7>!7???77?OSSO?>>!!777?77OOSQQO>!>!!7>>7!77??QNNHQHHHHNHO7ONNNH?SS::;;QS O>  ; -NQHNS7!??COO?OSOOOSSOOCCQS?!!:::7?SOOH"
	write-host "OHHHHHHHNN7!!!>77??CC??7?SC7?777>?C???77CCOS?77>7???OC7CSSSSC???77777?77CC?QHHHHHQHHHHQCQHOSS>7>:-..OC-7  .; 7NHHHO>:?COOOCOHSCCO77???SS7!>7!!?OQSCH"
	write-host "SNHHHHHHNN7!?777>>?C?C?77?>>7CC??COC7>77?77??77>?OSOOCCOOCCCCCOO???77?7?7?CHHHHHHHS7CQH7!:;!7>:--;-;OH7:;;;;!!>MHNC>!?CSQO?OS?>!>>7?77??>>>>!7CQHS?Q"
	write-host "CHHHHHHHNH>7??C7>7?O?77>7?77C?C?7?77777>7>7?777?CQQC7777C????OOSSOO??77?CCONHQHNHHQ!:?M;..:-:-;;;-;;SH-.---;>;;NNNS77COSO?>?7>!!7?7?7?77>>7>!?OOQS?H"
	write-host "OHHHHHHHHN?7C77>7?SO?7>7777??7>>7??>7>!?7>77?77?COC7!!!7??CC7COOCC?7C?77?CONHHHHHHS>!CM!;;;;;;-;;--;C7.;;;-7! -QHHS?7?C?7>>7>!!>7>7?>!>>>>>!>?SO?>7Q"
	write-host "SHNHHHHHNN?>7>>>>CSO77>77?7?7>77?C?>7>>?777OO77C???>>77?SOC77COO77?7C7!7??CNHHQHQHS>!?M?;-;;;--;--;;:-;;;:!:..OMHNS?7??>>!!7>!!>>>>>!>!::!!!!>C>!:>M"
	write-host "QNHHHHHHNH?77?7!>?CC??7???77?OC?C?77?777???O?777777?OOOSO?!>7OCC?77>C7>?CSQHHHHHSHH?-!O?;;;;;;-:-;;;-;-;-::..:HHHHC>7??:!>>>>???>>>!>7!!>>>>>7?>>7>S"
	write-host "QNHHHHHHNH7>7CC>>7??C??CC????SO77?7CCC??C??C?7?77COOSSSSO7!!7???777>?77?SQHNHNHQHH??--OS:;;;;-:!;;:-----:;;.-QHHNH777??7!>7>7?7>!>>>>7!>7>>77>7>>!>Q"
	write-host "OHHHHHNHNQ>!>7O?7!77OC??OC?>7OC7?OQSOOOQQC777?C?OSSOSSQO?7??7????7>>7???OQQNHHQOOH!!?!7N?;-;;!:-!NO;;-::;;.>SNQNNS?7?CC77>>7777>!>7777>>7>>77?77?7>Q"
	write-host "SNHHHHHHHQ>!?OO?7:!>OO?OOO?!7O??OQHQCCOHQOC>7CCCSOOOSSSC?7?O7777777>777?OHHQHNQ!7QC!S?7NO;--:!-;->-.--:-.;;OHHQNHQCCOOO7>>>??777>!>7777777??CC7???7Q"
	write-host "QNHHHHHHNS>!?OSC7::!CC?SCO?>7???OQHSOCSHHSO>?O??OOOOQSSO77CS?>!>>7?7777?OQHQHNS;?SO!??7NC-!::!;;...;;-;;.;:HNHHNNQO?CSO77!>??777>!7??7??7??CO???C??Q"
	write-host "SHHHHHHHNH7!->?O77?7C???C77?C?777COO?CQQSOOQQSO?COSSSSSSSOCO?!77?7>77???OQOOQNQ!;.OC!!7NO:-:!-;;-;;--:;-;?CQQQHSQSHHOC?SQC77??77>7OOOOOCOSOC7!!>>>7Q"
	write-host "QHHHHHHHNH7:.->?7?O????CC!>COC?C?>7?7CHSC7?QQOO?OOOCCCOQQSOOC77?C7!7>7??OQOCSHN7  >N>->HH---:-;;--;-;;;->HNHQHC?Q??HQCSQHS???!>77?CCCO??SQS7>!:>>!!Q"
	write-host "QHHHHHHHNS!>>>CO?7OCCOOCC>>CCCCO?!77>CO!!>7?7CSSOCCOCOSQSC?OOSSSSC77C?C?OSOSHHNM?!CNC777M?:--:-;--::---!HHSHHH7>SS7SHOOCO77??7CCOSOOSSOCSO?>>>>!>7>Q"
	write-host "SHHHHHHHNO>!CCOO?!?CSOC??7!77COC?>?>>?C>!777>CQSSCCOSSSSS?7?OQQHQOO?OCOOSSOSHHHNNSQMS7 >QO:---;;---:;-;:NQSSQN?7SOOQHSC77!>CSOQQOSQHHHHQC?>>?7777C?H"
	write-host "QNHHHHHHNO>>O??C!:!!???77>!7??OQQOO???C7C??>7CSQSOQQCCCO?77???SQHSSCOCSSQOOQHHHNNNNNO?::!Q>!-;-:;;----;.?QHQQO?CHQQNQC?>>>!?7C?CCCOQQO>?7!!7O??!>7CN"
	write-host "QNHHHHHHNS7?SC?77>:7CCCC???CCOSOSOOCC?7?CC?7??OSSOOO?7??C???>?OSQOCCOOOSOOSHHQHHHHHHQC:--77:-;::--;;-;-;OQQNH>!CQSOSO7777??777>7??CSS?:!7>7OOC7>>!7Q"
	write-host "HHHHHHHHNS>77:!!>77COOSOOOOOOOO?77777>>!!7777>?OO???CCC77CO7>7OSS??CSCOOCQHHHHHHNNNN?OO:-:>;----:!--;;;>HQQNS?>?77CSC?C?77?SS?77>777777?COSS?>>!>>7N"
	write-host "QHHHHHHHNO>!!!>>!!7COSQOOCCOOSO!!7CC?777>?7?7>CQSS??CC?7>?C77OQQQSQSQOOSSQQHHHHHHHNN!!?C>!-;;;;;:!--;;-CQQQHQC>7!>COCC?7>>7OS7>777!>77?C?7??>!!!>!?H"
	write-host "HHHHHHNHNC!!!77>!>>CSSOOOOCQQO7!>?OO7???????7>CSSO7>C?7?7??>>OQHSSQSSSOOSQHHHHHHHHNN:;-SQ!;;;;-;;::-;->HNHHQQ7>7!>OC?OO77!:7C?>>CC7!77?C777!!>7?C77S"
	write-host "HHHHHHNNNC::>7?>:!>7??7>OOOSQC777??O?7?777777>?O??7???CC7??7!SQQSOSSSSOOSQQHHHHHHHNH>-;ON!;;;;-;;!!:-:?QNHHQO777!>CC?OO?7>!777>>CO7>777??C?!>?7C?7?N"
	write-host "QHHHHHNHNO>->777!!?C??>7?OSQS?7??OC??7??>>7??>7?>!7C?COOCOOOOSHHOSSQS?!7OSSHHQHHHHNQ!-;>S;.;---;-!!:;>QNHQHSOC?77>77>OQOC777>>>>??>7C?!!???77C?77>7Q"
	write-host "HHHNHHHHN7:7??>77?OOC??CC?CO?7?7???7COC?777C7>77>7?SSOC??CQQQHHQOCHS?!-!CQQHHHHHHNNQ::-:7..;;;--;!7!COQHHOCOC??7?C77CSNOC7>>>7>!>77C7>!>>77OSO?7--7N"
	write-host "QHHHHHHHN!!7OC?77?COCC?C?>77>77>77!!CO?????C77?77CSSC?>?COSQHHHQCOSOOSHHHNHNHHHHHHNC;.!OH7;;;-----7>>QHNQ>>>!7????OSQQS?77!!?77>7CCCC>!7>77OOC?7!:CN"
	write-host "QHHHHHHHN>!7CCCCCOOHSSQO7>>!:77>77>7C?C????C77?CO!7?>!7CSO?SOQSOOC>:QNNNHHHHHHHQHNHO:>CHCNO;;-----::SNNH7>!!!!7CC7COSC??777>?7?77CSSSOOS7>>>>??7C!?N"
	write-host "HHHHHHHNN????7?CCCSHSOSS?>>>7??777>7?7C- >7>7O77S !C?COSS?77?SOCSQQOQHHHHHHHHQHQQHHQQQHSCOO! ;-;---!HNHO?>>>!!!7>>COOO777!>!777?>7?OSQQQ?>>77C?7?!>N"
	Start-Sleep -m 350
	Clear  
	write-host "CCHHQHHHHHHQC77>?C77???OOOOOCSSSOQC???C????CO?CSC?OOCOO???C?CCSSS?7?????????C?CSCOCCOOC7>?SO777C77?CC?>777?C??7CCOC>>7?77777>77?OCCC?????????CC???7Q"
	write-host "?CNHHHHHHNQO??7>7?77??CCCOCOCCOSCO??7COC???CC??CC?CCCCOC??CC?COCOC?CCC7??7???C?CCC????C77CSOO????C?OC?>7???C7?7CO?7>>>77777>>77?COSOC7???77>7?77??7C"
	write-host "7OHHHHHHHHHS77>>7?>77??CCSC??7C???7??OSC???CC??????????????7?CCOC??CC??CO??77>7>?7???7???OQSOO7?7?7??777777?7>CQOO!77??7777>7>7???CO?77?>>7>777777>Q"
	write-host "CCHHHHHHHHHS777>C77>7?C?CO??CC??C?>7>7?C?CC???????????????CCCCCC?7??????C?????7????????CCOSQSC7?????7777?77??7CSOC???OC77777>>77???7>777777>77>>7?7C"
	write-host "SCHHHHHHHHNN>>77CC???CCCCCC?????C?:--:7C??CC??7??7C?C??7>OCCCOC?C?!7?COO?7777?7??7>7???CSCCCC>77C?7>77?7??7?C7??OCO?CC7>7>7>!!7?7>7777???C?77777??7?"
	write-host "?CNHHHHHHNHS>7???CC??COOC?777777?!;:->!??CCCCC???7?C?????????7?7777??COC???7?7CSO???7???C777?777??7>7?COQOCC777?C7?777>7777>>77?77??77>7??C????7?77S"
	write-host "7CHHHHHHHHHO>7?CCOOCOOOOOC?>77777:->>>!>OCC????CC7?????7C7>7????>??7?OC?C?????CSC?????C?C7????7?????CCCCOOC7777?77>>!>>77??7>??C77??7?7>7??????777>O"
	write-host "?QHHHHHHHHQC7??CCCOCCCOOSC?>7777?7CCC?7?C??7>7CCCC??OOCC?>>?C????77777C?7????C??777?CCC>7???????CC????77>??7??>7777???7>???>777>77>>77?7>7?7?C??77!S"
	write-host "OSHHHHHHHHQO7?CC?????COOOOC7>77777????77?77>77CCC??CSQSC?7?OO?7777>>????7???????77>?C??77??C?C?COC??C77>7?CO?????7?OO??77?7?7?7>777>7?77??CC?C??7>!H"
	write-host ">CHHHHHHHNHS??7777>77?COOC?>777?CCC7>7C>7>>777???7?OSOO???CO?7777777???????C?C7>7>??CC??CCC??C??CCO??7!7C?CCCC7CCC7?C????7777???7777???OSOQO??7?7>>S"
	write-host "7CHHHHHHHHHQ7C7?77>77?OOC??7>7?CCCC77?C77777777777?OOC?7??CC?7777777?????????777!!??C?7??CC7?C???OSC?7>7?CCCOO?C??77CC????77???C7?777??CSOQC777??7>O"
	write-host ">CHHHHHHHHNH?C?CCOC??COC7??777COOOO??C??7777777>7>7????>77777777?77777???????777!!?C??77???CCSC?OQS??7?????COOO7C?7?CSC???77?C?COO????7OSOO?7>7>>>>S"
	write-host "7CNHHHHHHHHO?COOOSOC??????CCCOCOSQSCCC?C?CCCOC??777777!7777?7?CC?77777??????77777??77?7?CCCOSSC?CCOC?COO???C??C7???CC?77?7????CSOO?7?77?SOC?77>>>!!O"
	write-host "CSHHHHHHHHHO7OQOCSSC777>?COCSOSSQQQCOCCC?7?SQSC?7>77>!!>>7????CCC??777?77???77>>7777>7777?COSO7?77?C?CCC777?77?777?C?7>7?7??CCCOC??CC???OCO?7?77>>>Q"
	write-host "SSHHHHHHHNHO>7CO?OC?77777?OOOCCOCCC???OC?77?CC?7>>>>!>!>>7??77777>>7??7>7??77?77C?!!>!!7777??77??>?C?777777777777?7??7>>7?OO??????CCO?77COC7>????C?S"
	write-host ">CNHHHHHHNO::>?7?OC7??7?????7???OOCC?CSS??777C777!7>>>777?C?7777>77??77????777??CC7>77>7>777??7??7?CC7!7C>>>>>7?7?7777>>7?CC????CCOOC?7>7CC777CSCC>S"
	write-host ":CNHHHHHHNQC>C?7COOCC?7?COC>7?????OSOOO?777>>!7?7>>77??777>777>7?7?C7777?7777COO??>7??77?????7?COOOOC??????????????77777C??777???CSOCC??CC?C?CSQCC7S"
	write-host "!CNHHHHHHHNN!77?OCO?77??COC>>777??CCC?C?>??>>7??7>>77??7777>7?>>>??777>>>7777???7777777?C????7CCOCCC?CSOOOOOO??C??OOC??CS?77>7????OOCCCCOC?COOO?CO?Q"
	write-host "7ONHHHHHHNSC!77>?7?777>>777!!7??777????777777>7>>>>?>>!>!77>77777777>!!7??77>>C777??77C>7???????CC??7?CC?????C?CCCOQHQHQSC?7?CCCC?OOSO?CCC?77?7>?C?O"
	write-host "7CNHHHHHHNSC>77>777>77!>>7>!>??C7??????7>>>>777>>77?77>!!777>7777777>!77??7>77C77?77>>777????7????77>7??7?????CCCCOQHQHSOC?7?OCCCCSOOC77CC?77??>CC?S"
	write-host "7CHHHHHHHNSC777>77777>>!>>!!!77?7??777?7777777>77CCC???77??7C7?7>77>77C?C7>7777C?>>>>!!>7?CCC?777>77>>7777777?CO?COOOOCSOCOCO?77??C??7>7?C??77?7OOCQ"
	write-host "7SNHHHHHHNO?>?C?777777!7777?7!>77777?7?7777?7>77>???????7OO?????7!>7C??C?>>!7?77777>>>77!7>>77>>>!>777>7?7>77??77777??COSOC7??77????????CCC7>??OQSOQ"
	write-host "CSNHHHHHHNSC>?7?7?>7>>7????7>>>77>>7?7777?7??777?>77CC??OSOC??C?>!>7CC?CC?7>777?77777777>>>??COCCC?777>7?777???C??77>?CCOC?7??CCO??COCCC??777COOCO?Q"
	write-host "?QNNHHHHHNSC>77777>>777COC?>!!>>>>7??7?77C?OC?7>7>?????CC?C?C7?77>>7777?OCO?7!777>>>>>>>>CQQQQHHHNHHHHSC7>>?CCCOCC?77???C7??C7777>?C7??77777COOCC?>S"
	write-host "?QNHHHHHHNQH!>7?777>77?????!!!!>>7?C77?7???7?C777>??CC7?>!!77>77?>>7777?COOC7?777!>7!>>>7COOQSCSHHQHHNNNOC?OOO?OC??7>??C????C7777>??!7?7??CCOCCOO?>S"
	write-host "?ONHHHHHHNS7::??7777>777>7?77>>777>7?77777?>?CCCCC??OC?7>:!7!>7??77?7?OCSOC7!7???77!!>?OSOSHHQSSQOHHHHHHNNNH???C?7??CCOOC?77??7?CC??>7COOSO?777??>>S"
	write-host "?SNHHHHHHHSC::77777>7??????????7?777777?7>>7??CSO??OOOC?>!!?>77?777?COCOSOC7>>7C?7>>>7SHQQSHQHHHQSQQHHQQHHNH77?C?7??OOS??7777C?COO?777OSOC?7>!>7CC>S"
	write-host "?QHHHHHHHNO7::>77?77COCCOCOOO?C??77777???77???77?>77COO?77???777C?CCOOCCCO?77?C?C?7CHHHQQSSQHHNNQQHQQQHHQHHHQ?7777?CSQSC?7777COO???C??C?77?C7>>>CS?Q"
	write-host "CQHHHHHHNN?>>>777?7?OSS?COOOCC????C?7CSOC??7?7>>77?7CSO777???777OOQSOCCOOOCC?>?OC?OQNNSOSSHQHHHHOHHNHNHHQHQNHC777>?COOO7777C7?CO??CCCOC7>>?O?>?C77>C"
	write-host "SQNHHHHHNNC7>?777?7CSSSCCCCCCCCC?CC??OSSSC??77>>7>??OOC>>>?7?>>7OOQQOC?CCCCC?>?CCCSHHHSOSSHQHHSSCSSNNNNHHHHNHO77>>7CCOC7777C77?C??CCOOC7>>?C?7?C7>!O"
	write-host "OQHHHHHHNN?7C?77?COOSOC?77777>7?COHQQQSSQOOOC?7????C??7!!>?C7:>>???C77>?7????CCC?SHQSSSSQHNMHO!-.-:>OQNNHQQHHHC777777??7>>77????SOQSHSO?77777C?777>H"
	write-host "?SHHHHHHHNO7777?7COOOOOC7?77>777CONQOCCCSSSSSOC?C?C??7?77?OOC777???7?77?7?C?7OS7CQHHQSQSQNNO>-;;;.;;:>OHNHHHHNQ?7?7??7777777?OOOSSC?COO??CC7?C777>7S"
	write-host ">SNHHHHHHNO77CCCOOCCSQQ??7??7COOOSSO?777?CCOSSOOOO77>7>7?SSSOOCCC7>7?C??CCC?7SS7HNQQHQOSHN7;;;;;--;-;-:7HHHHHHNQ?>77?7777???COSQSC>>77COC?>>77?>?>!H"
	write-host "CQHHHHHHHHC?7?OSOOOOSSC?777??CCCCSO?77777??CCOOSSO?777?7?SSOOOQQOC?CCCOCC??77OCQNHHHQSOSNQ:;;;;--;;:-:--QNHHNNHHO?777777?COOOSSHQCCCOC?SC7!>7?77C?!O"
	write-host "CQHHHHHHHHC7??OOSCSSCC???77???CCCOC77>?7????COCSOO>>77?7?OSOO7CCOCOOCC?7?CC???SNHHHHHHSQM?:;--;;;;--!:::CNNNNNHHSC>!7?7777?CSQSSCOOS77?SO?7OO>77?>!Q"
	write-host "?QHHHHHHHNSC?OOCCCOQC?>?COOOOOCOOOOC??C?7???CCOC?777>7CSSC??7:7CC?CC????7?????SNHHHHHQQHM>;;;;-;;---:::77HN77HNHSC>>7?>>>777CQSO7?O7>>?CC?>OO>>!77>O"
	write-host "?OHHHHHHNN??7CC7?CSQC?>?OSOSSQOSOSCO??OC?777??77:!>77?OCO7?7!!7CO77?7?CCO??OOCHHHQHHHHQNM?;;;;;;;---:::>7HH.;NNHHC???77>77??CSSO>?C77?7777?SO>>>777Q"
	write-host "7SHHHHHHHNC777777CSS777???CCOSQQSSOC7?OO??7!77!>>>77?C777???7!CCC77?COC?7CCOOOHHHQHHHHMNH:.;--;-----:>!>O7> ;NNHHOOC?77>7??7>7?C??CCCC77>>?OS7>>???Q"
	write-host "?SHHHHHHHNO?777?7?OO77???7?COQQSSSO?77OSC?7>77>>>777??77777?>>CCOCCCOCCCCCOC?SHHHHHHHHNNS-;;-;-;-:--::!>?!:.;NNHHSSOC?7>7??7>>CO??CCOC77>>7OO7!7??CQ"
	write-host "?HHHHHHHHNO?>>7C?77777C7777?COCOOSO??7??777>77>77CCC?777??>>!7COCCOC77>OSSO77QQQHHHHHHMHC---;------;::!>!;.;;SNNHQOOC7777??C??OSC777CC?7777C?7!CCCOH"
	write-host ">SHHHHHHHNC>>>77CC???7>!>??C??7??CC7>>7>>77>77>777?7>>777?>>>!?C?CC7>>?CCCC7CHQHHHSSQHNQ?----;;---::!!!:;;;-;:NHHQ??77?77COCCCOS??7>???????7?7?OOCCQ"
	write-host ">SHHHHHHHHO>7>>7SO??7>!>?C77777??77C?77>!>777?77>>7777>7>7777777?7>!>777??CCSNQHHQSSHHHS7----;.;-:--!!>-;;;-.:HHNN?>>7C??SQSC?SSOC?7C?CCOSC??C?SSCOH"
	write-host "7QHHHHHHNN?!7>>7CCCO?7!7??7!777CCCCCC?7777777?>7>>!>CC7!>777???C?7!>77??C?7?QHHHHQHHHHH?!;.;;;--!!>!>7:;;;;.;QHHNNC>>7??7OS?77OSSSCCOCOSOSOO77??CSSN"
	write-host "CQNHHHHHHNC7???OOOOS?77??77!>7?OOOSSC?C?C777>?>7>>>7??>77>77?CC?7!!>777CO7!CHHQSSOHHHHH!!:!>7OQHS:::?7:;;;;;!HHHHNS7:>>>>?C77?OQQSOOO?OOSSOOCC?>7COH"
	write-host "7HHHHHHHHHOO?77???C?7>>7>?7>?CC?CCCOO??>!>>>>7>>>>>7????777OSC?>7>>?7??CC>!ONHQQQSHHHHQC77:>?OQHQ>::>:;;;-;7QNHHHHH?:7>777>CCCSQHHSOC?SOSS?7>?O7>CON"
	write-host "CQNHHHHHHNQS?>:!7???>!>777??SOOO?????7777???C>77>77777>CCCOSSO77>>>7?77?77>OHHHHHQHHHHQC!.:OSNHSS7;;:;;;;-:HNHHHHHHC>77??7?CCCOQQQQSOCSSC7>7!>?7?CSH"
	write-host "?HHHHHHHHNC!>:>??777????OOOOO??7>777?7??CSOO?>>>:777777COOQQO77>>:>>7>>77?7OHHHNHHQQHNHC7SNMMHOH?7;;;;;;.:?NHNNHQHNC>77OOO?OSSOOSSOOOCSQ7>!!!:>>OSON"
	write-host "?QNHHHHHHN7>!:>>7?7?CC?7?OC7777>7??C?777?CCOC?>>7?7?C??OSSCSO?CC77?>?77?O?7OQNHQHHHSSSNSQHQCHC:O!:;;;-;;;OHNOQHHQNHC!7?OSOCOQSOCC7??CCOS7!>>!:7?QOCQ"
	write-host "SQNHQHHHNN?7777>>7?COCC77?7!7?C??COO7>>77??C??7>7OOOOO?OSOCO??CO?7C7?77?C??SHHHHHHHS?ONCC?7:>?>>:-;.;-;;>QHQ?CNHQHHS:?CSQO?OSC7>?7>7??CC>!>>!!CSHCCQ"
	write-host "OHHHHHHHHN>>??7>!>7CC?7777>>7CC?7??7>7777>7?7>777SQO?C?7CC7??COOCCO?777?C??QNNQHHNHC.-N?!-;-:!:-:;;;-;.!C7>!!SQHQHHO!?CSSC7777!:>77?7777>>>7!>CQQO?Q"
	write-host "?SHHHHHHNH?7??C?77CSC7>7777>?>>>77?>77>777>??777CQSC7>!>7?C?7COSSOC7?777C7?SHNHNHHMO ;QC.;;;-:;;;-;;-;:SC::>:CQNNHHC>COC?>777>!!77?C77>7>>7>!7OOSC>H"
	write-host "OQHHHHHHHNO??>>>!7OSC?>777>?7>77???>7>7??>7?C?7??C7!>>>7COC?7?CCC???C?>7???HHSHHHQMO;-QS>;;;;--;;-;;;-OS:!>7>CQQHHNS7?C7>>>>>7!>7>77!!!!:!>>>7CC!!!S"
	write-host "SHNHNHHHHNC77>>>>7OS?7>7777??7??OC?7?7777>7OC77?77?>?COSSC777COC?7?7C7>7CCONHHHHSSNS--?NO-;;;;-;--;-;!O!!!!>?OQHHHQO7?7>>!>>!!777!>>>>>!777!!>7>>>!S"
	write-host "SHHHHHHHNNC77??>7777????OC77?OO?C?7???7??CCCC77?>?COSSSSS7!!7?C???7!777CCSSNHHHHSHQC?:-HC;;;;-;;--;;--!>!!>77SQQHHO?7777>>7>7???>!>7>>>>7>!7777777!Q"
	write-host "SHHHHHHHNN7!>?OC>>77?C?7??77?OO?7?COCCOSQOC??7??COQQSSSOO>>>777?777!>77?CSQNHNHQSH?!?7!QQ.;;---:--:;;!!7>::?CQHQNHC???C?7>77777>>>!!>77>7>>7?7?>77!S"
	write-host "SHHHHHNHHN7!7?OC?!:7OO??CO?!7OC7COHQOCQHHC?77?OCSSSOSSSC?7CC?77777>>77??OSQQQHNQ7CQ>?C!SQ--;;;--;;--!OO??7?COHQSNNO??CC7?>7??77>>!7?777>??77???7?7?Q"
	write-host "SHHHHHHHNH7!>COC?>!>COC?OOC>7C??CSNHO?SHQSSOOCO?OOOOSSQO??COC7>>77?777??CSQQQHNQ-CCC??>ON--------;;;:SHC?!>SQQQQHHHSCOC?O7>?CC77777CCCCCCCC?C??7?7?Q"
	write-host "SNHHHHHHNH7!>?OC?7!!?CO?CO?77????OQSOCSHQQSSSSO7CCOSQSSSO??OC>!>?7?777??OSQSQQHQ.Q>S>!?OM>::;-:--;;;7QHO>:!QQHQQQQHHQOCCS?>7??7777?OOOO?CCO??>77777Q"
	write-host "SHHHHHHHNN?>-;?O77CC?????7>?OCCC?7???CQQO77QHSOC?CSOOOOSSSOCC?>7C?>77??7OSOOOHNM- ;OC7!OMO!-;-::::--OQHO7OOQQQQ?SSCSHOOQHS?77>>>7CCCCC??OSS?!!!>7:!S"
	write-host "HHHHHHHHNN7:-->O>>C??COCO>>COCCOC>>77CSC7!>OOCOSOCCC?COQQOOOOSCCCC!7>7?7CSSOSHHNC;.CQS>>NC-;;-!>-:-:NNQO?QSSQQO:?Q??QQOSS?7??777COOCOOCCOQC7!!!!!!!Q"
	write-host "SHHHHHHHHH>!7CCOC>?CSSOCC>!?7?COC>>7!7O>!>>77?SQSOOOOSSSO77COSSQQS??CC?CSSOOSHNMNNOHNQ!:S>;;-;-!-:7SNNHQSSSSQNQ!?QOOQQC77!!COOSSSSQQHNQQSC?>777??C?Q"
	write-host "SHHHHHHHNQ7>OSOOC!!!CC???7!>77OSOC77>?C7>CC77CSQOSSSOOOOC7>7CCSQHSCCSOCOSSOCHHHHHNNMMQ!;O-;;-;;--:ONHHHHQSSSHNHOSQSQHQC7>!!7COOOC?SQHQOC?7!>?C?7?CCQ"
	write-host "QHQHHHHHNQ>>O?7?!>:>CCCC??77?CSQQOOC?CC?????7?CQSOOOC??OC?C?7?OSQSCCOOOOSOOQHHHNHHHHHQ7CS-.;-;-:->QHHHNHSSQQQQ!>SSOQS??77C?777>>C7CSQS>->!!?SO?7>>>S"
	write-host "SHHHHHHHHQ7?C7>>77!7OOSC?COOOOOS????C7>?777??77SOO?CC??77CO777?CSC?COOCOOOSHHHHHHHHHSSS?N-.;-;-:-7HHHNNHHSSNHS>7C7CSO?C?7?CCC?>777?CCC>>?7?SO77>>!!Q"
	write-host "QHHHHHHHNS>!!:!!>>7CSSQOOCCOOSO7>7>?O!>>!7?77>>OSS?7???>>?C7>7OSSSOSQSOSOSSHHHQHNNHNSSCCQ!.;---:>QNHNQOSHQQNQC7!!!?SO?C?7>7OQC!>77>>>>7CC7?O7:!!>>>Q"
	write-host "SHHHHHHHNS!!!>7>!!>?SSOOCCCSQQ?>!?OOC7??????7>?SQS????7?77?7>?QQSSQSQQOSQSSHHHHHHHQQ?COCOC-.;-:!CHNNQ!!OQHHNS?7!>7?SSC??77>7OC>>7?7>>77?7>7?>>>>??>Q"
	write-host "QNHHHHHHNQ:-!??7:!!7C?7?COOSSC?!7?OC??C7777?7!7?C?7>77OC?CC?7OSQSSQQHQCCSSQQHHHHHHO?OSSCSS7.;!CCHHNQ-.>OHHHQSO?7>>?7?COCC7:>77>>CS7>??>?7?C!>?????7S"
	write-host "QHHHHHHHNH!:!?77!!>??7!7?OSSQC7>7CCC?7?7>!>??!777!7???OOCCCCCSQQSOOQQC>7COOSHHHHQQCCSQSCSQ?-;>SQHQNC.-7SHHHQOO?777?>>CSOC7!>>7>>7C7!CC:>7?C77C?7777N"
	write-host "QHHHHHNHNQ>-77>>77CO??7?CCSSO777?C??CCO?>>>?C>77>>7OQSCOCCSSSHHHOCQQO!-:?QQQHHSQSSSQSSCCCSH7!CHHHHQ!.?SQHSOSCC??7??77OHQO77>7>!777>7??!!>77COOC7:->Q"
	write-host "QHHHHHHHNS!!CC?777OOC?CCC>7?7!7?>?7>?SO??CCCC777>7OHOC7??OQSQHHQOCHQCCSQNNNHQSQSSQSOSOC7QHHHNHHHHNQ?QHNHH?7>>>????CSSHQC7>7>>7?7>?COC>:7>>7CC?C7>:7N"
	write-host "QHHHHHHHNS::COCC?COSQOOOC7>!!77>>?>!????CCC?7>???C>>??>CSSOSQSQQOO?>SHNNNNHQS?QSCQOCCCCONHHNNHHHHHHQHHHNO>>>!!>C???CSS?7?77>7?777?SSO?7C77>777?7?>7H"
	write-host "QHHHHHHHNS!!??CSCOQHQSSQC:!!>????77>777?- ;?>>OS?S; ?C?SQO7??SSOSQCCQHHHHQQQCCQOOQCCCCOHHNHHHHHHHNHHHHHH?7>!:!>>77?CCO7>77!>77>>77CSQQSQC7>>7C?7?77S"
	write-host "HHHHHHHHNS7>7!!777?C??COC!!7?C7??777??CC>:>C?C?>!C::OSOOC?>>7OCCCSHHQHQSSSQCCCS?QCCCCOQHNHHHHHHHHHHHHHNQ>7>>>>>!>7OOOOO>>>!7>7??7!7?OOSQC77>?OO?C>!Q"
	write-host "QHHHHHHHHS7!!:!!!!!>!>7??>!7??7?C??OCOO?>NMCC>. O7OHOCC???777OSSSOQHNQSSSQQC>CQCC?OONHHNHHHNHHHHHNHHNHNO>77777??7CSOCOOC?777>COO?>>7??O?!!!!?SS?C?>Q"
	Start-Sleep -m 350
	Clear  
	write-host "QSMHQHHHHHHHQCC?CSCC?OQOQSQQQQQHHQSOSQQQ?OSQQ?SSQ?SSQQSSSOCSOHQQQS7SQS??OQ?OOOSQSSOSSSSC>SHQQOOS7C?QQO?CO7OOOOOQQOC??CCC77CC?OOOOQHQOOOOOOOOOC?OOO7Q"
	write-host "OQNNHNNNHNHQOCC>OOCOCOSSSQSSSSSQSSSOOSQSOSOSS?SSOOSOSSSSOOSOOCSQSSSSQOOSSSOOOOOOOOOOOOOOOQHQOSOOOCOOOO?7OOOOOOOHQSC>COCCOOOCCCSOSSSSOSOCCCCCOC?COCCC"
	write-host "CONHHHHNNNNQOOCCOOO77OOSQQS??7O??SSC?CSSSOSCO?OOOOSSOO?SS?QOSQOOOOOOOO?QOOOOOCOSOSOOSO?SQQHHQSOO7OOOOC777CCOCCQQQOOOSHHOCOCC?>CCOOCOCCCCCOS?77???C?Q"
	write-host "QOMNNHHHHNHSCC7CSSOOOSQQQQ??OOO?SC777?SO?SSQSOOCO?S???SOOSQQQSSSOCCOSQQQCO?OOOSSSOCCOOOSCQQQSOCCOOOCC7OOOOO?OCOSQS?SQOOCCCC??>OOOOCOOCOOOSOCO7COOCOH"
	write-host "QONNNNHHHHHO?>7OQQQOSQHHCSOOOCO?O?777??OQQQHSOOOS7OSSOSSOOSOSSOOOCOOSQSQ?77OCOSHQOOOOO?SSCCC?OOCOOCC7OOQHSOOC??SQCOCC??COC???CSSSOOSCC?OOOOSS7OOOO7?"
	write-host "OQNMNNHNNNNQCOOOQQSSQQHQQSOCOOOOSC7??C?CSQSOOOOSSOSOSSSSO?COOOOOOCCOOSSSOO?OOOQSSOOOSSOOOOS7CC7OOOOOSSSSQSSO7CCCOCCCCCC7OSS>>COOCCCOOOC7OCOSOCOOO?CS"
	write-host "SHHHNNNNNNHSOSSSQQSSQHHQQSOCOOOOCOCSSO??OCSCCOSSSOSOQQQSO?>OSSOOCC?OCOSOCCOO?OSQOCOOQQOOOOOOOOCSQSSSOSOOOCCC77CCO?O>!CC7OSO?>OCCCC??OOOCCCCSS?SS7?>O"
	write-host "QHHHHHHNNNQCOOSOOCOOOSQQQQSC7OOOCCSOOOCCSOCCCCCSOOSQHHSSOCOQSOCCCOCCCOSS?COSSC?OCCCCSSOOOO?SO?SQQSSOOC?C>OSSOCOOOOQSSOOCOOOCC7CC?CC?7OSOOQQSOOCOCCCH"
	write-host "CQHNNNNHHHQOOSOOSOCOOSSSSSSCC7OOQSOCCOOCO7CCCCOOOCSQHHQSSOSOSC??CCCC?OSSOC?OOSOC?7OOSOCOSOOOOOOSQCSSOC?O7SSQQOOOOSSSSSSCC?COOOOCCCCOCOOSQHHQOCCOCCCQ"
	write-host "CQHNHNNHHNHSOSOOOCO?QQHQOOO??OQQQQQOOQSOOCCCCCCOOCSSSOCCC?SSO?COO7CCCCOOOCCCCCCCC?OOSSOOOOSQQQSSQHHQO7COSSSQQQSCSOO?QQ?OO7OCC?SSSOOOOOCHHHHSC??CO>?Q"
	write-host "CQMHHHHHHNNHCSSSSOSOQQQSOOOCCSQQQQSOOQSOOCCCCCCCC?OSOOCCOCOOOCOSOCC7CCOOOOCOCCC7??SOOOOOOOOQQQSOQHHS?CCOSCSQQQSOOOOSCQO?OCCCCOSQQSOOO?OQHHQOCC??C??H"
	write-host ">HMNHNHNHNNH?CHQHHQSSQSCCSSSQQHHHHQQSSOSSSSSSSCC7C7CCCC?77OOOOQQCCOC7OOOOOO?OCCCCOQOCCCOSSSHHQSOSQSO?SSSOOOSSSCCOOSQCSCSOOOCOSQQHQOOSOSSSQQOO>?????Q"
	write-host "OHNMNNNHNMHQOQQHQSHQOCCCOQQHHQHHHNHSOQSSOOSHHQS?C7CC????CCOOOOQQOOSC7OOOOOO?7C7C?SC???OCCOSHHSOOCOQSSSSSOCCOOSO7CSSOOOCCCOQSOSQQSSOSQSOOHHQOCOCCCOOQ"
	write-host "SHMNHHHHHMNH?OQSOHQSC?COOSQQQSSQQQSOOCQQOCOHHHOOCC????!??OS?OCOOC?OCOCCO7SOOOOCOOO?C>??CCCOQQSOC7C?SSOCO7CCCCOSOCOOOOC?CCSHSOSSSOOQQOOCCSQSC?SOOSSCQ"
	write-host "CQHMHNNHHMHS?COO?SOOCCCOOOOOOOOSQQSSSQHHSOCCOSOC?>?CCC?COSSOOCCCCCOOSO7CCCOCCOSSSSCCCC?7COOOOOOO?OSQSCCCOC?7CCCOCC7CCC>CSSQSCCOSSQHHSS?COQCCCSQQSSCH"
	write-host "?QNNHHHHHMHS?OO7QHQSSO7?SQS?7OOSOQQQSSQSOCCC??CSC?7?SOCCSOOOC777CCS?CCCCCCO?CSQQSSCCSOCOOSS7CCOSQQQQSOCCOCCOOOOSOOSOCCCSOOS?COCOSQQQSO?OQSSOOQHHCSOH"
	write-host "7QNNHHHNHNHS?OOOQQOOOO7OQQS?CCOOCOSSOSSOCO7??COS???7OOOC??CC7C>CCOSC???7?C??COSOCCCOCCOOOSOO?7SSQSQQOSQSQQQQQOOSSOQHQSSQQSO?COS??OHQCSSSQS?QSHQSSSSH"
	write-host "?QMNHNNHHMHS?7CCOOOOSO?COOC??COS?OCOOOOOCCCCC?CO??COOCO??7CCOCCC>OSO???COCC?7SCCCOSOOSOOOOSOOSSSSOSOOOQSOOOSSOSSSSHNHHHHHOOCSOSSSSOQQSSSQSOCCOOCSSON"
	write-host "CHNHHHHHNMHOCSC?CC??CC??CC?!!CSOOSOOOOCCC7C77?O?COSOCCC??CCCOOOCC?????COO?OOOOOOCO????CCO?OSSCOOOCCCCCCOOOCCSSOSSQHHHHHHQSSOQSSSOSQQSSCCOOO?COCCQSSH"
	write-host "CQMNNHHHHMHOCOC>CC??CC???C?!>COCOOOOOSOCC>>C7CCCCSSSOCC?COOOOOOOCC??CCSSOCCCOSSOCCC???CC7OOOSOCCO??C>CCOCC?COOOSOSQQQQQQOSQOSSOOOOSSOO?OSO??COCOQQSN"
	write-host "CHMHHHHHHNQC?OOOCC7C???CCOCCC???CCCOOOS7C?7OC7>7CSCS??OCOQQSSS?O??7OSOSSS???OSOOOOO?>?CC?C?COC?????C??COOC?CCOOOOOOOOOSHHQSOOOOOSCOCOOSOSSSCCOOQHHSH"
	write-host "SHNNHNNHNMHOCOOOCCO7C?CSSSO?C!?7C??COOOCC7OSOC7OCCCOSSOQHHQOSSSO??OCCSSQSOOCCCC?CCCOCCC?C?OQHHHHQQQSSOOOCOOOOOSSSOCCOSSQQSOOO?SSSSSSOSQSOOOCOSQQQQOQ"
	write-host "CHNHHHHNNNQC?CCCCC??>CSSQQO????CC>?7OO77COSSSOCOC>OOOOOSQSQS?SOOCCCOOCSSOQSOCCCCCCCC??CC?OHHHNHNNNMMMMHQCCOSQOSQQSOCOCOOOOO7OOOOCCCSOOSOOC?OSHQSQSOH"
	write-host "QHNNMHHNHMHC?OO7C7CC7COSOCO????CCCOOOOC7COOCOOCCCCOSSOCO??C?C?CC7>CCCOOSQHQOCOCCO??C??C?CSSOHHHQNNHNQNMMHQQQQSSSSOC?CO?SSOOOOOCC7COO?COOOSSSQHHQQO?Q"
	write-host "QQNNHHNNHMHC??CO77CCCCCCCCOCC??C?COOOOCOOCCCOOOOSCSQQSOC?7????7O??O7CSSSHQQOCCCOOC??7?OQQSHHNNHHNHNQ7OMMMMMHQOOSOCCCOSQSSCCCOOOCSSOO?COSQHQOOOSSQC?H"
	write-host "SHNNHNNHHNQQC??CCOCCOOSOOOOSSSOSO7OCCCCOOCOOOOSHQOSSHHQS??OOOOOOOCOOSSOQQQS??OOQOOC?COHNHONNNNNMHHMH7>HMHNNMQOOS?OSQHHHSSOOCCSSOQQOOCCCHHQOC????QS?S"
	write-host "SHMNHNHNHMS????7COCCSQQSQQSSQQSOCC7CCOOSCCCOOOCSSCCOQQQSCCOOCCOOSSSQQQQSQQSCCCOQSOCSHHHHHHHNNNNNQNNS77QMNNNMNCOOO7SQHHHSOOOC7SQQSQOOOOSSOCOOC?>7SQOH"
	write-host "QHMNHNNNNM?7??OCCC7SHHHSSQQHSSSSOSQCSQHQQSSOCC?COOCCQQQOCCO?OOOOHHHHQSQQHQQOOCOQQSQHMMHQQHHNNNNNNNC?7CSHMHNNNS7CCCOSQHQOCCSSCOQSO??CSQSC7?OQS>SSOC?H"
	write-host "HNMHNNHNNMO?OOOCCOSQHHHSOQOOOOO?QQHQQHHHHQQSSOCCCCOOQQO???OOC??CQQQQSSSSOSQOOCOSOQHNHHQOHHMNMHQO?777?QSQMHHNNNC?7COOSSOC?COSCOSOSSHQHHHO?COSCOOOCC?C"
	write-host "HNMHNNNNNMO?OSOOCOSQHSQSSSCCCCCOQQNHQHHHHQQSSOCCCC?OQSC??>OCC???QSQQSOOOCSSSSOSSOQNNHHSHHHMMNHO?7777SHSQMHHNNMC?CC7OOOCC?CCSCOSSQQHHHHHOCCOOCOSOC>CO"
	write-host "OHHHHNHNNMOCOOOOOSHQSOQQO?C??OCOSHMQHSSHHQQHHQSOSOSOOOCCCSQQOOCO?OCC?COSCOSCOQQCQMMHHHNHHNMHC7777777QNHHHMNNHMMQC7COOOSCCCCCSQQHHQSOOQQSOSOOOQCOC7CH"
	write-host "CSNHHNNNNMO?COOSSSQQOOHS7OOCCSSSQHNHSOCSSSQHHHHQQQSOOOOCOQHQSSSSSSCCCOO?OSSOCOQCQNHNNHHHHNH77>7;;77?HNHSHMMNNNNHSCCOOCOOCOOOSQHHHOOCCSQSSOCCOSCCC??S"
	write-host "QQNNHHHHHMSCCOQQOQQQQQQQ?CCSSCQOSQQOOCCO?SSQSQQSOQCCC7COOHHQHHHHHQOOSQQSSSSC7QSHNNNNHQOSHM?7777;--7QMHH7SNMNNNMMHS7OQOOCOQQQHHHNHSSSQQQHCC?CC7?>QS!H"
	write-host "SHHNNNHHNMQCCOQQQQHHHQSOOOOSOOOCQHSOC7OCOOOOSQQHQSC??CCSSQQQSOQQQQSQSSOOOOO7OSSNNHHHNNHQMH:;;7;--;CMMHHCCNMHNNHNHS?COOOCCOSQHHHHHQQQOCOHSOCSQCCCOS?O"
	write-host "SNHNNNNHNNHQQQSSQSSHQSCCOQQHQQQQHHQSOOSOCCOSQQSQSO??C7SQQQQS?7COQOSQQSSSSOOOSCQNNHNNNNSHMQ7;-77;;7HHHHQ??HMNNNHHHQ?OOOCCCC?CQHHQCCSO???QSOCQO>??C>?H"
	write-host "OHNNNNNNNNQCOSQOSQHHSO?OQQQQHHHQQHQSOSQSOOOCSCO????COSQSQOOSC?QSQCCSOSQSSOOQQSHNNNNNHNQNMO;;77777?NNHHO??QHMMNNNNH?OO?C??OOOSQSQCOSSCOOCSOOHQC??OCCH"
	write-host "OHNNNNNNNNO?COSS?QHHOCCOSQQQHNNHHHHQ?SQQQOC?O?????COSSSOOCOO?!SQHSCCHQQSO?OQQCNNNNNNNNMMM?;7;7777HMHHH?7OQSNMNMNNHSSSOC?COOOCOCOSSSOOQ7CCCOQH?C?CSSQ"
	write-host "SSNNNNNNNMHQC7COOSQS77OOCOOSSHHQHHQSCOOSSCCCOC??COSOSO?OSOCC??QQO7HQQSCSHQQOOQHHNNNNNHNNS?7;7777SMHHHQ77CSSNNNNNNNHQSOC>7O?CCOSQSOSCCSC7COOSSC>OSQSQ"
	write-host "SSNNNNNNNMHQCOC?OSOOOCOOCOOSSSQQQHQ?COOOOC?COCC?COSOOC?OSSCC?OSSSSHQOOCQHQQCCHHHHNNNNNNMO7777777QNHSHS7??OSNNNNNMNHSS?7C7CO7OSQQSOOOSSCOOOOSOCCSQQSH"
	write-host "?HNNNNNNNNQC?COS?OOOOC??C7COOOOOOSSSC?CC??CCCCCC7COCCC7CCO????SSSSSCC?CSQSSOSNNHHNHQHHNMS777777?NMSOHS7??7?QNNNNNNSOC?OCOOQSQQQSSSCCCCCCOSSSOCOHQCSQ"
	write-host "?HMNNNNHNMSOC>?CHQOOC???OOCOOO7OOOCOOCC>?CCCOCC??C??CC7?CCCC?COCCOC?CCCOSSSOHMNNNNHHNNNS7777777?HNSQHO77??7SHNNNHNQCCOSOOQHHOOQHQSSOSSSSHQSSOCSHQQQN"
	write-host "CSMNNNNMHHO????CSS?SOC!>OCC77COSSSSQOOOOOCCOOC7?????SSC?C7C7OCOCOO??OOOOSOO?QMNNHQNNNMM?777?777?NNSHQ??QMMMNNNHNNMHC?7SOOQQSCCQQHHQSCOQQHSQOOOOOQHHN"
	write-host "QNNNNHNNNMSOOCCOSCQQOCCCOO?!7OSQQQHHQSOOCOOCCO?C?C?CSOC?C77OQSSSO7??CCOOQC??SMHHHQNNMMN7777CO7?SNHQHO?NMNCCHNNNHMNNC????CCOOCOHHHHQSSSQHOQQQOSOCOQSN"
	write-host "ONMNNNMNMNQSSOSQQQQO??7OCC7?CSSQHQSHQOOC?????C???>?OSOCOCCOQQQCO??COOCOOS7?OHHNHSHNNMMH7777SQ777HQHHOHHNHSSHNMNNNNMQ??C>>?CQSQHQHHHQOOQHQQQOCQQ>CSHN"
	write-host "CNMNNNHNHMHQS???OOSO???COOOQQQQSSOOSOCOCOSOCC?CCCC?C?OOQSSHHHOOC?>??OCCOCOCOHMNNNNHNMH?777:QQ777OQN??HMNMMMMNNMNNNMHS?COSOOSCQQHHHHHCSHHSC????O?SQQN"
	write-host "SNNNNNHNHMHSC??OOOCOOOCOSSSHSSOOCCOSC77SQHHQSC??C?CC7CCCQHHNQCCC???C?C?CCOSSHNNHNMNMNQ7777CHHO77?QS7?HM?MHHMMMNNHMNHSCOQQQOQQHHHHHQQSSHHS???77?CQHQH"
	write-host "SHMHNNNNMNO??:>OO7OOSSS?OQQCOCCC>SOSOCOOOSSQSOCCCOSSSQSSHHQQSOSSOCCCOO>OSCCQHMNNNNNN?7777CQNNNOOOHH;7SO?SQHMHSNNHHMHOCOHNQQHNHSOCCCOSSSHO?????CHHHSH"
	write-host "HNMNNHNNNMO>CCC>CCCSSCOCCC??OOSS7SQCOCCCCCCSCCCCOHHQQQQHHSQSOOQQSOSOOCCOSOOHNMNQHNMQ77777SQHNMSCHH?>7SS?COSQCOHMHNMSQCSHNSOQQO?7C?COCOOS??>?!?SHNHOH"
	write-host "QNNNNNNNHMCOOSCC>OSQSCOC7C??OOCOOOOCC>CC?CCOCCC>OHNQSOOSQOOSSQQQSSQOOCCOSOOHHNNNHHMQ77777SHHNNHSHN?77SH?>??O?CHMNNMHSSSHHSCCC???OOOSCOSOCC???CSQHHOQ"
	write-host "QNNNNMNNHNOSSQSC?CQQSOO7OOCCSOOCCCOCCC7CCCOSSCCCSHHSC??COOOSOSQHQHSOSO?COOOHNNHNNNNC7777?QNNNMHHHMS77CHCO?C?CCHNNHNHSOSQOCCCC?!COOCO7O?C?>C??SSHHSCH"
	write-host "QNMNMNNNNMSSOOCC?SHSSOOCC7COS??CCSSC?OOS77CSQSO7SSOC?>?COQHOCSOSSSCOSO??SSSHNNNNHMS7777CHHHHHHHNHMQ7>?MC????CCHNNNNHSSOC??O?C>!!O?OC?7??>????CSO???H"
	write-host "HNHNNNNHHNSOC?>C?OQQOC?COOOOOOOSSSOCC?CCCCCQCCOCCCCCOSQQQSO?C?QQOOOSSO?OSSQNNNHHNQC77777OHQO?7?OHMS777HC7!>?OOHNNNNH7CC??????COOC?????????>CCCOC?!?H"
	write-host "HHNNNNNNHMSC7OO>?COCSSOOSSOOOSQSSSCSOCOCCSSOSCC?COOSHHHHH???CCSQ?OC?CCCCOQHNNHNNHN?7777CHQS??777SHS7>?N?7!?COHQNNMHO?CCC??C?COC??!C>CCC?OC7??CCOCC!S"
	write-host "QNNNHHHNNN??CSQOC7CCQSOCSOOCCHSOSSSQQQQHHQOOOOOOQHHHHHHQSC?COOSOOC??OOOSQSQNHHHHHN77777CHHO??777?HMSOHMS7!??CHHHMMQOCSSOCCCCOC????>CCC>?O??OO77?OC?H"
	write-host "HNNHNNNNMM??CSQOC???SSSOSQO?SQSSSQHHHSHMNQOCCOQQHHHHQHQSOCSOOCOOC7CCOSSOQHQNNNMNOM7>777SQQC7-7-7CQMMMMMH77?OHHNHNMHSOQSC?C7OOCCC???C?7?CCC?OQSOCSOCS"
	write-host "SNNNNNNNNNC?CSQSO?7?QQOSSQSCCOOOQHNHSSHNNHQQHQSQQQQOHHHQSSSQS?CCCOC>?OOSQHQHHNMHQN?77??QHO?77777SHO?7OOC?7OCHNQNNNNNHQSOSO7OQSCCC?SQSOSSSQSSSOOOOCOQ"
	write-host "SNNNNNNHMHSC7?SSOOOOSOCOOOCSOQCOQOQSSQSHHQQHNHSSSQHHHHHHHQSOO??COOC?CCOSQHHQQNNHSQC77??OHO?777?CHS7777?7?OSHHHQHHHQNNHSQHQCCOOCCCCSSQQSSQHQCC??CC?CQ"
	write-host "QNNNNNMNNMS?77OOOOQSSSOOOO?SQQSSSCSSOQHNHSSHNHQOSQHQQQQHHQSOS>?CSSC?CCSOOHHSSHHQQSQ?7??SQOC777OSN?77777??OQHHHHQHHOHMHQHNHCCCC??COSOSHOOHHHOC???C??Q"
	write-host "NNNHNNHHNNC777?SCCSOSSQQSC?SSQQQ?COCCSHSC?CSQSHQQSQQQQQHNQQHQQSSHSCCCO?OOHHQHHSSHHMO??OHHQ???QNH777CQQHHQQHQHQH?CNSOHNQHHSCOSCOSQHQQQQSSQHSC?!!C?CCS"
	write-host "HNNHNNHNNN?7??QQCCOSQHHQQC?OCSCQSCOCCOQC??COOOHHHQQQQHHHQOCSHHHHNHCSQQOSOHHQQSSHHHNNSSQHHOO?CHHH7OMMMMNMMHHSQQQ?ONSSQQSOO??OQSHHHHHHNMNHHSCCOOCCOSOQ"
	write-host "HNNNNNNNMNC?QHQQS???OQSOCO?COCSHHQOCCSSCOOSOCQHQQQHOQQQQSCCOSHHHMSQQHQQQHQSSSSSQHNNMMMNNNMHHHMMNSQ7??COQNHHHHNHOQHHHHHOCC!?OSSQSSSQHNHSQOC??SSCCCSSH"
	write-host "HMNNNNNNNHC?QSOSO?77OSQSOCCCSSQHHHSSOSQSSSOOCOQHHHHQSOOQSQOCCSQHHQQSQQHQHQQHSSSHNNNNNNNNNNNMNNMMC?777SSHHNHHNNOCHHHHHQO7COOCCCCOCCSHHQ??CC?OHQO?C?CH"
	write-host "HHNNHNNHNH>>QCCC?CCOQQQQQQQQQHHQSSOSOOCCCSSOC?OQQSOSQSOOSQQO?OSQQSOSHQQHNQSSSHHNNNNNNNNNNNNNMNMMHQNNMMMNNSHNMH??OSOQQOSOOSQQOOC>COSOOOCCOOSHQOOC???S"
	write-host "HHHNNNHNMHC?O???C?OOHHHQQQSQHHQOCCCOOC???OOOC?CHHQSOSSOC?SSCCOQHHQQQHHQSQHQSQHHNNMMNMNNNNNMNNNMNMQSHNNHHHHHNHSO???SQQSSCCCOSHC?7OCCCCCOOOCOQO?????CH"
	write-host "HHNNNNNNMHC??CC?C??OHHQHQCSHHHQ?7OHQSCOCSOOSCCQNNH?COOSC?OC7CQHHHHQHHQSSHQSHHHNNNNNHMNNMMNNNNNNNMQ>777CQHHNNQOO??!CQHQQ?C??CQO?>SOCC>CSSOCCC???COOCQ"
	write-host "NNHHNHNHNH?7!OO?7!??QSCOSCQHHQO?COQQQCOSOCCOC?CQQOCCOOSSCOOC?QHHHHHHHSQQSSHQHHNNNNNNNNNNNNNNNNNNMH77?7!QHNNNHOO??COQQSQSOCCCCCCCOQC?OOCCSOOOCCOSSCCH"
	write-host "HNNNHNNNMH?7?OCC??OSSC?COQHNHCCOSSSSSSOSC??SOCCC??CSHHHQQQQSQHNNQQHHHSCSSHHNNNNNNHNNNNNNNNNNNNNNMN?77?SHNNNHHSSSCCCCCSHHQCCO??>>CO?>SS??CCOOOQOC??CN"
	write-host "HNNHHNNHMH?7?OCC?CSQSOCOSSQNQCOOQSSOSQQSC?CSS?C???CQNHQQQQQHHNNNQQHHHQQSHHHNNNMNMNNNNNNNNNNNNMNNNN77?SHHHHHHSSOCCCCCCQHHOC?C?CC?CO?CSO:?C?OQSSS?77CM"
	write-host "HHHHNHNNNQ??SOCCCOQQSOSSCOCOCCCCCO??OQQOCSQQQOOC>CQHHQOOOQHNNNHHQQHHHSSSQHNNMMNNNNNNNNNNMNNNNMNMNHHSQHHMNOCCOCOQOSQQHNNSOC??COCC7CSQSC??>?CSQSC7?-ON"
	write-host "HNHNHNHHNQ?OHQQSSSHHHHSQC?????CO???>OOOSQH?7?7COSHQ777OSHHQHHHQHHSHQSSHHNNMMNNNNNMNNNNNNNNNNNNNNNNNNMNMMQC????CQQSSSHHOOOCCCOOO7CQHHQSOSOOCOCSOOO?SH"
	write-host "HNNHHHHNMQ??SOSQQQHNHHQHS??!?OCOO?>C?CCOS77?OCSH?7C>7?QHHQOOOQHSHHQCHHHNNNNNNMNMNMNNNNNNNNNNNNHNNNNNNNMMO?C????COCCOSSC?C???CCC7CCQQHHHHSC?CCCOO??CH"
	write-host "NNHNHNNNMS??C???COOQQSHHQ:!OSSCSOC7CCOSOCCQMSSS?7HCSHHQQSO?CQCHHHSHHHHHHMNNNNNHNHNHNNNNNNNMNNNNNNNHHHNHH?CC!?C???CQHHHSC?7??7OSSO?CSOQHHCC?COQQSSC?S"
	write-host "HNNNHNNMMQ7C??7????CCCCOO?7OSCOSSOOSSQQO??CHOQ77?MOHHHSOC?OQQCHHHSHHHHNNNHHHHHHNNNNNNNNNNMMNHHNNNNNNHNNQ?CCCOOCOOQQQQHQSCOOCCSSQC?7OOSQS????OHQQSC?Q"
	write-host "QNHNHNNNMS?????CCOC?77?OC>?SQOCSSCQHQOSCC?CNHO??QNOHHSSOQQHMNHHHQSHHHHSSNNNNHNHMNNNNNNNMMMNSHHHNNNNHNHNH???7CSOOQHO?CQHSOCSSOQQOCOOQQO???C?OQHHQOCCQ"
	Start-Sleep -m 350
	Clear  
	write-host "CQQNQHHHHNQC??777>C7C?OCO????OOS?C7?COQC7CC?CCCC??SCCCO7?C??COOS??C????CC?????7???O?7?S??SSOO?7C7CCC777C?7OOO7OQO7>?7?????C77OCCCCCCOO77?77?777O7>?N"
	write-host "CSNNHHHHHNSC?777??C7??SCOC?????CC?>7>?SC??O?????C?SC??C??C??CCCCC???CO?OC????O?CC??C??CCCSSOO7O????77?>>?77CO?OSO?COOOC???O>>C77???77S?7?7CC7C7>O>?H"
	write-host "7SNHHHHHNNS?>77????C?CCCCOC?CCOCC!:-:>??C?CC??O7?7??OO???OOOC?CC?>?7?COC?77777??O?>7??7SOOOC?>7O77777??C7??????SOOC?CC?>>7C!?>???7??77???????777>CCH"
	write-host "7SNNHHHHHNQCC77?OS??OOSOC?777O???:;--?7?OCCCCC??O?S?????C???C?77777?COCC?O????OOO?C?OOOCC?7??>7?O77C??OSO???7>7CC7?7>777??7>77?C?O77?7>???C????O?7?S"
	write-host "?SNNHHHHNNS?>7C?OOQ?SSHHC77>7C77>:>->>!?OOC???CO?????????>7?7C????7?CC??7777?7OOC?O?C?7????7?O7??7?CCCCSO??77?7777>7C>?77?77>???7??77C>7??C??COO?>7H"
	write-host "CQQHHHHHHNSC7CCCOCCCOQOCO??777?77>CCC7!?CC?77?CCC??CSOCS7>7CC?7?>7C7????O777??CC7>O?OC7OO?C?7?CCCC?????77??7777777777C777S?>>??7>>>>7O7>???S?C?77:7H"
	write-host "OQHNHHHHHHOS?CO7????COOCOS?>O7?77?O???>???7>CCCO?CCOSSO?7??OCC777>77C??7C????CCQ7CO7C?7CO?C?O?CCOS??77>>7?CCC?777?COC?777S777?7>>>?77?C7?CC??C777>7Q"
	write-host "7QHHHHHHNHSO7C7?77??OOOCCC?>7?7CCC?77C7777777?C?77CSSSS???OO?>77?O77??CS7?????7>>7?C???????SCC??CO??7777??CCC?CC?CCCCC?7?777??7>7777???OSOSC777O?77H"
	write-host ">SNNHHNHHNQOO?????7?OOOCC?777COOOC???C?7>>>C7>7O7>CQC????CCC?77777C777CCO7??777>>7????7?COC?CO??COC??77?CCCQQO??????OS????77?C???????OCSSQO?7!77?>7H"
	write-host "7SNNHNNHHNS?7CSOCCC?CCC?7???COOOOOCC?C?????777>77!77?7>7>77777CC?7CCC7?????CC7C>77?7>7?C?7OSOC??OSC????C?CCOOO??S?CCC??C?7>?CCOOOO?COOCHSSC?C?::>!7H"
	write-host "7QNNHHHHHNSC?CSSOOO???C77CCCOOOSSSOO?C?CCCCC??7?>?7777!777??7?CC?777C7?????77CC7>???777C?7?QSCC?QS???CCC7??CCO????COC?7?O77??COOOC?????OOO??C7!?C!7H"
	write-host "CHMNHHHNHNS?COSSOOO?7777COSSOOSQQQOC?CCC?OOSQOCC>?77>!!777???CCC??7C77?77??77CC7C77>77C?7;:QHO???C??COOC>>7???7???CCC77???OCCOC?O??C?O?SOCC?O?7>77?H"
	write-host "CQHHHHHHHNO77CQOCOC?77>77COCC?COSOO??OO?7??COC?7>!>>!!>>7??77777777C7777???7?C7??>>>>>7!>!-:CC7777CC77???77?>??77777>7>7CCO??CC?C?COC7>7OOC7CCCC???Q"
	write-host "7QMNHHHHHN?>!??SCC??7>C?7????7CCOOO?COSC7777??77>>77!!77?7??7777C777??C?7??77??CC?7>>7>>!::!!?7???CO?777?>!7C>SO7O7777?7?OO777C?CQSSC7C7COS7>?OCC??H"
	write-host ">NHHHHHHHN?>>???OO?C????CC?7?777?COOCOOC>77>77??7>7?77??7777777?7?C7?7?7777>7CSS????C?::>!>O:!OOCCOOC777??7???7????77>????C>>7???SOOC??C?????SQO??CH"
	write-host "?SNHHHHHHM??7???SO?C?77COS?>7777??OO?OC77>>>>7C?!!7????77777777?77?7>>7?7>>?7CO?>777SC:!!>O?>-CQO?CCCCCOCCCOO??C?COOC??OCCC>??????SCCC?CC??COSSOCCCH"
	write-host ">QNNHHHNHN?>7O77????7>7?7?7!>??OCO7C??C7777>>7>>7>7?7>>>7?CC7C>>77?7!!77?7>?7??77C7O?7:::CQCC?CO???77?CC??????COCCSQQQQSO?7?CCCC?OOOOCC?OC77??7>C?CH"
	write-host "7QHHHHNHHN?>77C!7?77>>>7>7>!>????77???77C77>7?>!7?7?7>>7>?7>7?7>>>!>!>???777?777C?>7!:;-:SHS??CO7?77777??>>???COCOSQQQHSO??COOO??COOCC77CC?>7?7?CCOH"
	write-host "?SHHHHHHHN?OC7??CC??C!!>!>>7!>>7?77??7?777777?????CC7777?CC????7C!???CCC77>>77?777>>:;::>QQCQO?7>>>777>?7>>C????7??CCCCOOCCC?77??7?7??77CC?>7O?OQOOH"
	write-host "?QHHNHHHHN7>C7??77?>>>!>>777>>>7777?7??777?77777?7??77???OCC???7>!7??COC7>>7???77C>>:--:?QQ?OC?C!!!77>>?>!>C???7????CCCOOCCC??77?77?????CC?77OCSQOOH"
	write-host "CHMHHHHHHN7!7O??777C??7?C?77>7>?C>!7O777C777777?77?S??CCSSOC??7?!!77CCOO?777?77?7??7::--CHQ?COQSSOC??777>7????????7??CCSOC7??COCC?C?COOCCC?>?COOOCCN"
	write-host "CHHHHNHHHN77>77777>777CCC?7!!!>7>>7?C77>7CCC?777C7CC77CCCCC7?C77>77?7??QOC??7>77777!;;.!OHO7OSQQHHHHHHS??77?C?CSC?7>>???C?7??7??77?77C??777?SOCOO7?H"
	write-host "CQNHHHHNNN7!>?7777>>?7CCC?O:?>?>>7????77??S??777C7CC7777>!7>77777>7!7??CCOOOCC7?C7!:--;>OH?7OSOCHQHHHHNHQ?7CSC?QO777>7C???C???7777?77?77??7OSCOOO77H"
	write-host "OHHHMHHHHN>:!>?77?>777O77??>7!>7777777??7777O?????OSSO?>::>>!77?7>7>?CCOSCC77O???C:-;-:OHS?7OQQHQSHHHHHHNHNQC7?C?????OSCC7777??CCC?>77OCSO?777???!7H"
	write-host "CQHNHHHHHN!::!?>77>7??7?7?C???777C77?7??7C7??OOSC?COOOC7!>77!7??777?CCCSO?7>7??OC7;;;-!SHC?7?HHHHSHHHHNHHNNQ?7?CC?COOSOC?7>>7??COC?777SOOO7>7>>?C7?H"
	write-host "CHHHHNHHNN!:!>7CC?7?CCCCCCC?OO?S77OC>?CO7??O77?O777?SOOC77??7???O?OCOC?OOC?77OCO!>--;-!QOC?!SNHHQHNQHHNHHHHNQ7???7COSQSC?777?OCCCC77??C?77?C>?>7OCCN"
	write-host "OQHNHHHNNH:-!>??7?7CSSCSOOOOOCC?C?77?COCC???77>7777?OOC7>CC7777?SSQSCOCOOCC?77O7:--;;-?QQC7>OHQHQQNHNHNQHHHHN?777??COSC7>?C?7C??CC?COC7>>?CC>>???77N"
	write-host "QHHHHHHHHH7!??O7??COHHO?C????>?COCSSSSHSSSC?7?>C???COC>::7??>!>7OSQS????????7C?--:;.-:CHQC7?HN?7!7>CNHNHMHNHHQ>7>7??7C?>>7??>?CCCOSQQQO77??77?7?>>7H"
	write-host "SNHHNNHHHH7>C?77?COSSOC?777>>7??QQSSSSSQSOOCO?????????7!>7CC7>>C??C?77?7OCC?OQ>::-;;;:CQO?COHC-----:CSHNHHHNNNO?7C7777777777?COOSOHSSSOO77???C?77>?H"
	write-host "SNHHNHNHHQ7??77??OOSOOO?77>>>77CCQQSSOOSSOOOSC??7????77>7CC??777?7?7?7?7?C?7OH>-::-.-:7SCCCQQ>;;--7->?HHHHHHNNQ>CC777>777777COSSSOOCCOO??777?CS77!CN"
	write-host "OQHHHHHHNN>!77?OCOCOSOS??7?7?CCOSQSO?7???OOSCOOOOC??O77?CSSOCCCCC77??CC??OC?OS>--!7:-!OS7!7H-.;777;:;--?HHHHHQMS?77?????C?7CCSQQO?7>?CCOO?>7O?C?7!7N"
	write-host "CQHHHNNNNH7>??OOCOCOOOO?777??OCOSSO?77CC?COOOOOOSC77>77?CSSSOSQSOC7?CCCCCC?7O7:-;:?:;-7O7!?>.;;;;7;---->QHHNHNNHC?77??77?CCOSQQQOC?CCOSSC7!C?7?CC!>H"
	write-host "OHHNHHHHNQ?>7OSSOSOSSC7777????CCOCC7>?7??CC7COOOO?>>777?OSOOC?OO?COC????S77?C-;;--O?.;-?O?SC;.7;---:::!!OHNNHNMQHC77?7??77COHQQSOSOC7?OO7>7SC7>77>7H"
	write-host "OHHNHHHHNHC?OOOCCOSQC?>OCOOSOCCOOHSO7???7???OOCOC7>???OOOC?C!>CCO7OC???????CC:;;:7CO:-->OCS>-.;;.;-!:-!!>HHNHHHHS?7777777>7CSQO?7CC7>7?C7>7QC>!>7>7H"
	write-host "QHHHHHNHNQC?COC7?OQQ?7>COOOQQSSSQOOSOCOCC77??7??>!77??OOC7??!7OOC777?OC?CCCQ?;-;!??OO?:7?7O!-77;;;----!77HQHHHHNOC7???!>C7C?QS?7?CC7>77??7CO7>7777?H"
	write-host "OHNHNHHHHH777S???CQO777?CCCOSHQSSSC???OC?>>?7>!:>!7?CC?????>!7OSC>77OOCC?COS>:-;:CQQHS?C?7C!7;------:!!77OSHHQNNQOOOC?7?77777???CO??C?77>7CSC>?>C?OH"
	write-host "SNNHHHHHNHO?>777?COC77??7??COHNHHS??7?CC?777?>????7??7>??77>:?QH7OQOO??CCOS?-;;->SHSNHQSSCO:;;--:--:-:!7OQCHHHMNNHOO?77?C777>?CC?OCCOC777??C?>!?CCSN"
	write-host "OHHHHHHHNN?>>7?????????77?????CCCCC?>777?77>7>>??C?7777??77C!?CCCSOC?77OSCC::;;:?SCCOOSQSSQ:77-----:::!!>>?HNNNNHHC7>7?77?C?COOQ??77??7?C???7>?CCCOH"
	write-host "OHNHHNNHHN7!77???????7>77??7?????CC?>77777777777???77>77777?>?CC?OC?777COC?!-;-:?OC????HSSH!.7-----!!!!!:!>SHHHNHQ?>>7?77?OCCSOO?C>7????CC??7COOC?OH"
	write-host "SNHHNHHNHH7>?>7CS?CO>!!>?77?7??O77??7>C!!>>7?C>>>>>>CC!>>7>7?7??77>77>7C?OS>-;-!OS!!:--?QSHQ.7--;!!:7!:!!>>OQNQHHN?>7?C?CQSC>OSSOC7?C?OOSO?C?COSSOQN"
	write-host "ONNHHHHHNQ7!>!>?OCCCC>?7?7>777??7?CC?77>>7?C777>!>!>CC7?77777????>!>777???7>-;:7OC>::-;:COQH:.;-!!>!!>7SHHQHHNNNHNO>>O??COO?>CSQSSCCCCOOSOO??7??OSQQ"
	write-host "SHNHHHHHHQ?>?77COOSO777???!77??OOOSOC?????777>7>77>7C?>>C7CCC???7>?>O7?7C7>7:.:>7>!:::;->?QQS7OQ?:!!:?MNS??QHNHNHM?7:>>>>??7>SQQSOOOCCOSOOO??C?>?OQN"
	write-host "SHHHHHHHNHOC?7COCCO?>>777O7>7??SOCSO??O>>7>>>>>>>!>?C?>777?OO??7>>7?7???C7?>-;-!7?>::---:?OHOQQQH7::?ONHSCOQNNHHMNQ>?777>7OC?SQHQQOC7?OSOC?77C?>7CSN"
	write-host "ONHHNHHHMNQO7>>>??C7>>>O7??OOOCCC?CC7?777?777C77?7?????CCCOSOC77?>??77?7?77-::!7??!:::--:COSNSQQQS-;OMHNNNNNHHHHHNN?>>?7C77O?CSHQQSO?OSS?>7!!C77C?SN"
	write-host "SQHHHNHNHHC7!->???7?777??CCSOC?777C?7COCSOSS?!>>>?>7CC??CSQS?7>>!>!>>>>7?OS!-:>>7?!!--->?SQNNNHNO7;;?NO7NQQHHHMHQHH777CSO7CCOQSSQQOS?CQO>!!::>7CQOSN"
	write-host "SHHHHHHNNQ>>!!77?O?CC?7??O?7?>7>7CC?>77CCCOS?C>77??COO?OSSOSC???>77>77??CQH>-:C>>7!:::-OQQQQNO:Q>!;;!Q>!SQQNSQNNQNNC>??SQOOHHQOC?77C?CSC!!>?!>CSQOON"
	write-host "SHMHNHHNNQ7?7>7>>>?OSC?777>>??C?7CO?7C77777?7O77CSSOOQCSS??O?COO?C?7?7?COQHS--77777:?C?QNH7-!C?!--;;:CO77COC7?QNQNNC>?CSQ??C??>>77??7???7>>>!?OHH?CN"
	write-host "QHHHHHHHNQ7>??7>C7CO???777?7CC??7??7>C77!7C7>>7C?QQ?77>CC??O?OQQOOCOO77CCSQM!-?COCC>OSSHQ>:-:>:!:-;>:CO7::>>:OHNHHNO?CCQO7?7>-!>????7777?77?!?OQQ??N"
	write-host "SHHHHNNHNS77CC?C>?OC??7C7C>7?777>77>>>7?7>7?777?OQS7>7!>7??C?OOOSS?O?7OOSSSHS>COOCOOHQQNQ-;;;!--;:;7-?H7>!>O!7QNHHNO7COC?>77>:7777??>777!!7?>COQO7?N"
	write-host "QHHHHHHHHQ?777>>>?SO?7?>777?7>>7?C7C>C7?7C7CC7??CC7>>>>??CC77OOO?C7??7OCSSSNNOOQQQQQHHHNH..;-;-----777HC!>C?>CHHHQHO7?C7!!>>>!??>!?7!>>!>>>>!CC?>:7H"
	write-host "SHNHHNHHNH7777>!!SSO7777777????OO?7777>77??C?>7?77>7OC?SS?7!CCSO7?7??OCCCQQHHHQQQMHHHHHHN. ;-;------.:O>:?!>7CQQNHQO77>!!:>!77??>>>!>>>!>>>77?77>!>N"
	write-host "QHHHHNHHHQ?77??>>?CCC??CC7?O?OC7??7??777??CO?77?7?OOSSOSC!!77?CC77>7OSCCCQQHNHNHNQHHHHHHM:.;----;;..;>H>!!>??SQHNHC7777!>7>?7?7>>>777>??>>7777>7>>7N"
	write-host "HNHHHHHHHQ7>7CC777????7CC7?7COC?S?COCCSQSC?C?7?COSQSSSQC?>77>7??77!7CCSSSHHHNHHHHQHHHHHNMN;.;-:!-;::CHMO7:>?QSHQHHC7??7?>>???7>!!:!77>7>77>?7C!!7!7H"
	write-host "QHHNHHHNNO!:7OO?C!!CCC7?OO?>?CC?OSQQOOHHQ??>7COSSSSOSSSC7??C77??7>COHOSOQHHHHHHHNHHHHHHHNNC;;7!!-7MMMMNO->7CSQQHHNO??OC?7>7?7>?7>>?7>777O>7CC?7?O77N"
	write-host "QNHHHHHHNO>!?SSC7!:>OO??OO7>?C??OQHOCCQHHOCC???SCOOOSSSC???C7>7777QHSCOQHHHNHHHHHHHHHHHHHMH.;-!-;;77CSQ7!?CQQHQHNHHSOCC??77?C777>>?C??7???CCC?7C?>CN"
	write-host "QNHHHHHHNQ>>!7C?7???CC??C77???????OC?OQQSOSHQSCCCSSOSSSSSCCC7>7?OOSCCSQHNHHHHHMHHHHHHHHQHNNC-!:--;...;-!7COQQHQ?HSONNQ?SQC>??77>7??COO?CSQO?>!>7!!?N"
	write-host "QHHHHHHHNQ>:-:OC7??????C?>7CO?CC77???OHO?7CQSOO?COSCCOOSQOCOC???OOCCSOSQCSSHHQHHHQHHHHHHHHMH:::-;.;;:!?>7OOQHHO!OS7ONQSHQC>?7!77?C??OO7?SHC7!!?>>!?Q"
	write-host "QHHHNHHHNQ>--:CC>7Q7C?CC?O>CSCCC7>>7?OQC>>7SO?O?CCS??CSSQOOSOOCOOCCCQQQS7SSHHHHHHHHHHHHHHHMH!-:-. ;:CCQS?SSSQHO:?H>?HHQHS?>?>>77OOOCOOO?SO?!!!!!>??Q"
	write-host "NNNHHHHHH?!>7?CC7??OOOOC?>!?7COO7>7>>CC!!>7?7OQQSCOOSOSSO77OSSSHOCSOQHHHHHHHHHHHHHHHHNHHHHNC:-:-!?MNMNHNSSHSQNO>?HOOQS??>!7OCCOOSSQHHQQSC?7??77>??CN"
	write-host "HHNHHHHHNC77SSOO77>?OC???>>77COSCC?7!??>7??77OQQSOOOOHSC?>>CSQQSCCSOHHNNHHHNHHHHHHHHHHHHHNN?;:::HHQ?OCNQMQSSQNO?SHSSHS77>:!OOOSSOSSQHQOS?7!?C7?7?CON"
	write-host "HHHHHHNHN?>7O???>::>??O??7?7CCSHOSOC?CCC?C?O?OSQSOSOCCC??C?OSSSS?OHHHHHNHHHHHQHNHHNHHHHHHMH:-?CC77:;7COQHSSHHQ7CQQOOOO?77?77777?7?SSQC:>>>7CSS?>>>?H"
	write-host "QHHHHHHHN?7?O?>!7>>?OOSC?COCOCSCC??C?C?????O77OHCCCC???7?OOCQQQQCSHHHHHHHHHHHHHNHHHHHHHNN7?::COC7OHSQHHHHSSHHS>?O??CC??7?OCC?7>77?CCC?!?77COC77>>!7N"
	write-host "HHHHHHNHN?>>>!!7!C7?SSSC?COSOSO7!>CC7!>!>??O7>?QQO??CCO!7CSHCC??QHNNNHNHHHHHHHHHHHHHHNNNC--7:?7?>OHHNQQQHQQNH?7!>>?OCCC7>7?QO>>>>7>777?CC??7!:!!7>?M"
	write-host "HNHHNHHNN7>!!>>>!>7?QQSQQCOSQS7!>?OO77?777O7>>OHSO77???>>CSHC?QQQHHNNHHHHHHNHHHHHHHHNNHSO:->!!!>-::>?>?SHHHMS7>!!!CQCOS7C>7CS7?777>>?CO?77?>>!>>C>CN"
	write-host "QHHNHHHHM>::>??!!!?7??7?COOQQC??7?HCC?C?77?7C>?O?7>7>7OOHCSS?QQSQHHHHHNQQHHHHHHHNHQHMQ7;CO>:-7::;;-:777CQHHHS?7??!?COCC?C!>7C7>7OC7C777????>7C???OCQ"
	write-host "HHHHNHNHN7>:>??>!!7??>!7COSQO7?7CC??????>>CC?7777>7OSOOQHSOCQHNHQSQSQQHHHHHHHHHHHHHNNC.;7NNC??:-;-:-!>OSHHHSCO?77C777OSS?>C7>>>C77C7?7>>???????>!!CQ"
	write-host "HNNHHHHHN>:!?>>C7COC??>CCQSS?>????77CSC?C??C?7?>>7OQOOOHHCCSQHHHQSSQSHHHNHHHNHHHHHNNC>;--CNHNQ?7::?CCSHNQCC??C77???CSHQSC>7!!7>!>7CC?>!!C77SC??>--?M"
	write-host "HNHHHHHHN::>O?77>COOC??C?7??7>?77?>>OOC??C7!77?>7CQ!:7HHS7CQHHHHHQQQHHNHHHHHHHHHHHHN7:--!>HHNHQSCCOQQSHNO7>>7???COCSQHHC?>>>77>>>?CO?>!?C77OSC7>::?N"
	write-host "HHHHNHHNN!!?SCC???SOOOCC7!!!>77>77>7??7CO7- ?7?O>!7 :7HSCCCHHHHHHHHHNNHHHHHHHHHHHHNQ!--:!7CQHNNNHHNHHHHN?7>!>7?OOCQOQO7CC7>???CC7OSS??7C>>77?C7??7ON"
	write-host "HNHHHHHHN!>??CCCOOHQHHSS7!>!77?7?7>777?777?HC?OC-!>7OSHCCONHHQHHNNHHHHHHHHHNHHHHNMHN7::!!??SQHHHHNNNHHNQ7>>::!>7?7?CO?!77!!!777?7?OSSSHQ7!>>7?7??:?N"
	write-host "HHNHNHHNM?77>>>7??OSOOOS?!7?C?7C?>>7???7>>CHCS! -MOHHSOC?HHNHHHHHHHHHHHHHHHHNMHMHMHH7!:::>7SSHHHNNHHHHNO>7>>>>>!>?OSSO>7>>>77???>>CSOSHS77?7CO?C?!7N"
	write-host "HHHHNHHNM777!::!!>>>!>C?7!!C7?7OC?COCO?7?:!SOO>;?MSHSC>CQNHHHHHHHHHHHHHNHHHHHHNHHHHH7>:!!>!SSQNNNNHHHNH??>77???7CSSOOQS?7??>7OOS>!77??C7:!>>OSOCC>?N"
	write-host "HNHHNHHNN7!>?!>7>>>!!!C?7?!CC?7C??SSO?????CHQ:?Q:QSOCCCOQSSSHHHHHHHHHHHHHHHHHHHNHHNN?>>:!>7SQQHHNHHNHNNO>>>77??7OS?>?SSC?????OC77>CCC?7>!!!7SQOC?7?N"
	write-host "HHHNHHHNN7>>?7CC77777>?77>>O7!>!!>COO????CSNQ?OQ:SHOCCONHSSSNHHHHHHNHHHHHHHHHHHHHHQNHS7>!>7SHQHHQHHHNHHNQ>!77OOSCC>>?SSOCCOO?OOCOSOC7!!!?>!7??7>>7ON"
	Start-Sleep -m 350
	Clear  
	write-host "QHHHQHHHHS?77?7?7777C?CCC??7??CC?7??OOC?7??C?????C??C?7C?CC?OO????C?C?CCC777?77::?OC?7?OOQOO?7?C?CC7?77??7O?7QQS>77OO????7>777?C?7?7??77777777>O>7QN"
	write-host "SHHHHHHHHO777>??77????CCCC??????>!>!?C?C????????C???????CCCCCC??7???C??C??7?>!!::>7>C??COOOC?????777??7?????7COO?COCC7?777!>777?77?7?S??77777C777?HH"
	write-host "OHHHHHHHNO>>?77CC?COSOCO????7C?7::-:>7C?CCCO?7?7?CC??C??C?CO?7777??COO??????!-:!!?-:?OC??7?7777O7>7>CCOOCCC77>OOO?>>>777>>C77??7?C?7>7??C?C?77?77?QN"
	write-host "SHNHHHHHHC>77?COO??CSOCC?77>777!-::!!>CCC???????C?C??????7777???7??COC?????>-:!COC>->?O?7?7??7??777CCOSCC??777?C?7>>>77??7777?77??7?77??CC??????>7QN"
	write-host "QHHNHHHHNO77CCOOO?COQSOOC7?>7?7!>>?C>?COO?7???C?C?OCCC?>>>??7777????O?77?CC>-:>OSO7!CCC?CC???O?C???C??C??77>>777>777777?C7>7C?77>77?7>77??C??C77>7QH"
	write-host "QHHHHHHHNC7?CCCCC??OOOOOC7777??7??OC7!??777??CO?7?OOOC?>>?CCC77777C7???7?CC-:-C?OO:>CCO??C???CCCO???7>777??77777?CC??C77777777>7>>77?O7?CC?S?7?7!?QN"
	write-host "HHHNHHHHHC???7?7?7?OCCCOC?7>??????7777??>77?CCO???OSOC???CC??>777777C?????7:-!OCC?:>?C?7?CC7?CCCC???7>?>?CC?7C?C?OC??7777?77?7>>7>77C?OCOOCC7777>OQN"
	write-host "SHHHHHHHNC????7?>77OOOC??777?COOC??????777>7?777?SOO?????CC777777>7???CS?7!;-7OCCC:!OS?????CC7?COO??77CCCSSCCCC?7CCC?????77???7?????CCSOSSC7!7??>7HH"
	write-host "QHHHHHNHHC???CC???COOOC?7?77COOOO??CC?7777>77>7O7C??77?>7??777??77C7777?S>:;-?HCCC:!SCC??CCOOCCOQC??77C?COOOO???7CCO?7?7?77??OCC?C??7CQSSC?!!>77>7HN"
	write-host "QHQHHHHHNS??CSSOOC??777???CCOOOOSOO?C??COSOC77>7>777!!>>>??7?O?7?77C77??O>:;;?SCO?:CSS??CCOSO?CSS??COOC??CCO?7?C?OC???777??C?SSOC?????QOC?C7>!!>!?HH"
	write-host "QHHHHHHHHO??OSSSSO?777?CCCOOOOSSQOC?CC?COSSOC?7777>>!!>>>???CS?7?77777??C>-;-CO7O7:CSS???OOSC??CC??COOC77????7???OC??77?7C?CCOSC??????OOO??77>>7!?HH"
	write-host "QNQHHHHHHC7?OSOOSO??77?COQSOOQQOCO??O?C77OSSO?7777>!!!!>????CC?7?77C77??C:-;!C>!C>-CSC77?COC?>77??OC?C?7?7777?????7?77>??OCO?CC??COC?7?OOC77???C7CHH"
	write-host "HHHHHHHNH7>>????C?777777CCC???CCCC?COOC77C?OC77!>>>>>>>?CC?77!777777777??:;-7O>:C>-?OC777?????77?CC>>>77>77?7?77>7>7>>7?OO?77???CSOC7>7CCC7??OCC?7QH"
	write-host "SHHHHHHHN>!!??CCO???777C77777?COCOCCOSC>77>?7?77>>777?????777>7777??????7;;-!C>?C7-COC7?777??CC??SC7>777>>>77?7O7?>>77?CC??77CC?SQO?77?OC?77OHC7??QH"
	write-host "QHHHHHHHN7>7?7CSOCC?7?OCC7>7?77??CCOCC?>>7>>7C7!>>7CC?>777>7?777?C7>77-::;;;>O>??:-7OC7??777?OCOOOC??CC?C?CC?C??CC?777CC77>7?C?7COOC??C???CCSOC?7CHH"
	write-host "QHHHHHHHN!>7?7CO?????CCO?7>7?C7???O??C777>>>777>!7?777>77!>7>77??7>!>!;;;--;7C7C?:-7OC???????CCCCO7?OCOOCCC???CCCCOOOSQO?77C?C?>COOOCOCCOC?C?7??C?HH"
	write-host "QNHNHHHHN>7???>7777>>>>77!!??C7?C?C7??777777>>>77?C7>!>>7?7>77>777>>>:-;;;;!SO>?O!:?O777?????CC???777???777?COOCOQQQSQQOCCCCOC?COOOO??7C?777?>?CCCHH"
	write-host "QNHHHHHHN>77?77777>>!!>7>>>7???C?7??7?77>77>7>>7????7>>7CC???7>>>>>?77-;;-:CSC>>?:!?O77???7??C77>7>777C?7>>C?CC7COSOCSSC???C???7CCC7777C777>7?COCOHH"
	write-host "HHHHHHHHN7>7??777>?7C>>7>?7>>!>7>77?7777777?7777CC?C7??CC??C??>!>>?C7-;:-;-CC>-:;:>O7?>777??!>7>!>7>>7?>>77777??7???CCSSCC?C7C?>??C???COC?77?OSQCOHH"
	write-host "QHHHHHHHH>>7??7777>>777?7?7>!>>7!77?777777??7777???????OO?????>>>7?C>;-!-;-CC>::;:>O?7>>>>?C?7??>77>777>>777?7?77???CCOS???C7CC?????CC?OC777?SSSCOHN"
	write-host "HHMHHHHHH!>77?77!>>C?CC??>>7!7!!!!?7>7777????7?77?CC?COSSOCCC?7777?C:;-7!;;:7O!:!7>O?7>>CQHNNNQQQQHQO77???77?OCC7>??CCO?C?7??C?7CC7?OO?7>>?OCCCC?CHN"
	write-host "HHNHHNHNN!!>77777>???CC??>!!!77>7??7?77?C?C?77777?C7?C?77?77?777>7?7;;-:?:;:!7?:7C777>>CSSOSOSQNHNHHHQO7?CCOC?O7??77???7?C77?77>7C>>??>???COOSOO>?HH"
	write-host "HHHHHHHNN!:!7777777????777!!?!777?C??7??777777?>7CC7777::7>:>77?777>-;-->>>>7-7-C?77?7>COSSHSOHHOQQHNHNHSOCCC?CC?777?C?7??C77?77??>>CCCCOC?CCCCC>7QN"
	write-host "QHHHMHHHN:::>77777>7?777???77777?77777?7>77?CSO??OSS??7::7>>77???7C>;;:!COO!>--!?!!?SQSSQSHQSQHQSHHQQHHHNQC?7??7?CCOSOC?>>77?COO?7?7COSO?7>>>7CC>7HN"
	write-host "HHHNHHNNN!:!!!777?7???7?C?CCC??77>777??7>????OSO??OSCC?>>??7???C?7O:;-:7?SQO7::!O>7CQQSSSQHHHQHQQHQHHHHQNNQ??C???COSSOC?777?CCCO?777?CO?C??>>>?S?CHN"
	write-host "HHHHQHHNH-:!>77>??COOCCOOSCOO?C?777??CCC????>>?7>>COCC77?C777COOCQO-;;>COOSHHQCSOOOQHHQOSHHNHNHHQHHQHHNQHHNO77???COSQO?>7C?7O?CCC??CC7>>CCC>>???77HH"
	write-host "HHHHHHHNQ-!77??77?OSOCOCOO?C??CCCC7?OSSSC???>>7777CC?7>>7??777SSSH?;;:!7??>7OQQOOOSHSSSSSHHHSOCCSQNHNHHQHHHQ?>7?7?COO7>77C?7????OCOOS?!>???77??7!7NN"
	write-host "HHHHHHHHQ>?O>77?COQSCC?7>>>>>>CCSSSSQHSSSC????77??CC>>:>7C?>!:7OSS!;;-!!7::::7QCQOCCQQSQHNNNC:;-77OQHNNHMHNNS:>>777??77777?7?OOOOSSQQO>7777?O77?>?NH"
	write-host "HHHHNNHHQ>?C77?COCOSSC7?777>77CSQQSOCOQSOOOCCC??CC7?7777COC777??CC:;-:!7!!!:;.!COSOSHQOQNQS>:;;;-;:!OSNNHHHNNO?7>77777?7777CSSSSOOCOOC?????OC777>?HH"
	write-host "HHHHNHHNQ>?C7?CCOOCOSO??777>77CQQQQC?CSOOOOOOCCCCC7?777?OOC7C7???C!;-:>>!::--.:7??OSQSOQN?>-;-;;-;;:7ONNHHHHNSC>>77>>7?7777CSQSOC??CCCC??77OC777>?HN"
	write-host "HHHHHHHHH!77?OOCCCOOOO?7??CCOCOSSOC?>7CCOSSSOSSSC?>7O??OSOSOSOCC??!--!>!:::---.:>?SQOOQNN...;;;777-:--CHNHHHHQQ??777????O?OSQQSCC7?OOOO7!>>??77?!7NN"
	write-host "QHHHHHNNQ777?COOOOSO??777?CCO?COOC77>7?CCCCOOSOO?7>7777OSOSOOQOO?C7:-!!!:::---;;>CQSSSHNC.;;.;;-;:-:::>QNHHHHNQC?>777?7?OOSQQQSSOCCS?OS7:>???7C?!7HN"
	write-host "HHNNHHHNH???CSCCOSQO7?7?C?C?CCOSC??77?7??7?OOSOC7>>>??COC??!>COOOSC;-:>!----;;::CSQHOSHQ7.---;-;;:::::>ONNNHHHQO7>77777777?QSOC7OC7>?CQ?>CQ?!!7?>7QH"
	write-host "HHHNHHHHH?OOOO?COQQ?>7COSOSSOOOSOC??7C?7??COCO?7>77?OOOC?C7>>CCC7O?:::!!------!>SQHHQQNQ>..;--;;;:::!:>OHHHHHHQS77777>>777?SS?7>CC>>>7O7?CS?>:7777HN"
	write-host "HHHHHHNHQ>>?SC7?OQS>>7COSOOQSQSSSO??CSC7>77?>!!!!7?C??7??C7!>O?C>C7:::!--::;:!?CQHHQHNNS:;;--7;--;:!:>COQHHHHHHQ?C?77>>7?7?C77>?C?C7777>?OOC7!7C7CNH"
	write-host "HHHHHHHNH7!7?7??OSC77??7??CSQQQSSO77CO??7>77!>!77>??>>7??7>!7CO?CS?-:!!:;::-!7SQSHQHHHMC:;;-7;---:-:!!??OHNHHQNHOOC?7>>777>77CCCCCCO?7>>?CO?7!7CCOHH"
	write-host "HHQHHHHNH777?777??7?CC?77?COOSSSO?C>???77777>>77????77??7>7!COCCSQ>;:7??>>>?CQHQHQNNHNN>-;-----:--!::>>>SQHHHHMNQO????>?????COCC?C???77?COC7>7CCCSNH"
	write-host "HHHHHHHNN7>>??CC??C77>7???C77??C???>777>7777>>7????>77777!>>???COHN!;7?CCOSQQHHHQSQQHHQ>;;------;:!>!!:::OSNQNHNO?>>7???CCCCOOC??77????C???77COCCSNH"
	write-host "HHHHHHHNH7>77?OO??C7>!7???C7?77?7?C>77>!?77?77>77777>>>77>>77???CHN?->COSOSSSHHHQSSQHHH>;--;-----:>7:::-:CSHHQHNO7>7??7COOCCOOCC?>7C?CC?7??7?OOCCSNN"
	write-host "HHHHHHHNQ>!>>>COC??7!!7C?!7?77C???77>>>>>77?777>>>77!!!777??77777ONNQOSQSSSSSQHHHHHHNQC!;;;;;;-:>77>!:?SSSSQHHHHH?>?OOOSQQC7CQOSOCCCCOSSOC?7?CCSQHHH"
	write-host "HHHHHHHNQ!77>>?OCOC7>>??7!7>7?C7CCCC???7>7??7!7>!!?C>>77>7?7C?COSSQNNQSCCOSOQQHHHHHHHS7:.;-::>7!!>>!CSNQOQHHHNHNNS!7?77?CC?>CQQOOOCCCOSSCOC?C7>CSQHH"
	write-host "NHQHHHHHH??CC?OSCO?>????7!!??COOOQOC??>77!!7>>!!!>?C>>>>>?OO?CCOQQQHHHHQSCSSHHHHHHHNSO7:->CHQMMN>!!7QMQC7OSHHHHHNQ!!>!7>>??7OHQSOCC?COSOCOC?C?>?OSHH"
	write-host "HHHHHHHHHCC7>77C?C7>>7>7?7?OCCCCCOO?77>>77>>>>>>77????777CSO?COQSQHHHHHHNHQHHHHHHHHHSSS>!7CSQQQS7:!SNHHHHHHHHHHHNH>>77777?CCOHHHQOC?COSC77>!?7>?CSHH"
	write-host "HHHHHHHNHOC>!!77??77777??COSOC?>>??77??OOCC7>C777>7??CCCSSS77CSSSQHHHHHHHHHHHNHHHQHHQS?-:SQNNNQS!;7SMQQNQHNHHHQHNH7>??CC7?C?CSQHHQOCOSO>>>!:!>?SCSNN"
	write-host "HHHHHHHNQ7>!:?7?7?CC???COCC?777????77??OSOC?>:>>7???C?COQQS7CS??SHHHHHHHHHHHHHHHHQHHHHC?QMNNOSSC!;;7N>??SQQSHHQQNH7>?CSOCCSSOCC?C?C?OSO>!!>:>7OQCOHH"
	write-host "HHHHHHHNS!7:>>777?OC?77C?77??77COOC7777?CCC?7C7COCSSCOOOCOOCOQQOQHHHHHHHHHHHNHHHHHHHHNQQQ7!Q7C7!-;.:S?>CNQO?SNQQHH>!COHHCCQOO7?7>7?CC?O>>>!!7SQQOCNN"
	write-host "HHHHHHHNS>77?7>>7CC?77777!7?CC?????7!C7>>??7777CHSC?7?OC?7COS?SSHHHHHNHHHHHHHNHQHHHHNNH:--:>>!-;;;;:QC::>7>:CNHQHN?7COSC?7?>>!??777>>7>!>7>>?SHQC?HN"
	write-host "QHHHQHHNQ????C>>?OO?>7777>7C7777?>>>>77777?7777CQC?>!>77C?7OSQSSHHHHNHHHNHHHHHHHHHHHHNN:.;:::!---;.-HC!!>>>>ONHHQNC77OO>777!:>?C7C?777>>>>>7?QSO7?HH"
	write-host "HHHHHHHNQ????7!:CSO?7777>77?>>>?O>>>>7?77?CC???OO7>!!>>CCO?OSSQQHHHHQHHHHHHHHNHHHHHHHNM!.;;-;-;;--..SO!!>!>7CQNHQH??C??>>77>:>777C7:>!!!!!!7?S?>!?HH"
	write-host "HHHHHHNNS7777!>>COO7>>7777??7??CO7?>>777>?C?7???77>7??CO?7?CQQHHNHHHHHHHHHHHHHHHHHHHHNH:;--;;;---;-;OS!!!!C7CQHHQH?777>!!>77>777>>>>>!!!>>!>>?!!:>HN"
	write-host "HQHHHHNNO7?7>>!>???C7>7C?7??C?CO77C7!7777CC77>7?77OOSSSC>?QQSHHHHHHHHHHHHHHHNHHHNHHNHNM:.--;;---;- .?7-:!>!?CQHNHS77>7!!7>>7??>>>>>7>>!>7777??77>7HH"
	write-host "HHHHHHHNQ?77C?>>?7CC???C7??COC????CC7?OC?CC??77COSSOQQO77SC?SHNHHHHHHHHHHHHHHHHHHHNH7>M!;-.;--::.;;!SQ!!>77COHHHQ?77777>>7>7?>!>>7777>>77??7?>7?:7HN"
	write-host "HHHHHHHNC!!>CO7>>>?C777CC77CO?CCCSSOCQHQ?777?COQQSSOSSCCSHCOHNHHHHHHHHHHHHHHHHHHHNNS;!M>;;--;!!!:SHNMM7->>?OQHQHS7?CC?777???>>!!>!7>7>77!77??!7O!7HH"
	write-host "HHHHHHNMC!7?OOC>:!?OC?COC>>?C??SHHSC?HHQC???CCSSSOSSOOCCHCOQHHHHNHHHHHHHHHHHHHHHHHSC!>QC-:!-!7;.COSHNS>>COSSSHHNHQOOC7?777??7>>!>?C7??77?7?O?77?7CNH"
	write-host "HHHHHHHNC>!>CC?7!>7COC???77????OSS?CCQHQSSSSO?OCSSOSOOSOS?SNHHHHHHHHHHHHHHHHHHHNHN?>7?HQ!::!>!;.;;;>C?:>CSSSQNQNSHQOC?OO?>?C77>>?OO?OC7OOC??>>77>?NH"
	write-host "HHHHHHHNH>--!??7C?C???C7>7CO?7???7??SQQ?7QHQOC??OSOCSSSQQQHHHHHHHHHHHHNHHHHHHHHNS>S?:7SNC!!!!-:;.;.;:!!7COSQHO7SC7HQOSHQC7?7>7?7CC?C??COOC7>!>7!!>HN"
	write-host "HHHHHHHNS!.;>CC>?CC?COO?>7CCCOO>!777OS?!!?COOCOCOCCCCOOSSHHHHHHHHHHHHHHHHHHHHHNN:.QS!>CMO!>!!;; ;:!??CCCOSSQHO!OS>OHQQSO?7??!?CCOOCCCCCOC?7>>>>>!7HH"
	write-host "HHHHHHHNO!-!7?O>?CCCOOO?77?CSSC!-777OC!!>77?COOSCCCCSOSOSHNHHHHHHHHHHHHHHHHHHHNH-;SH>!?MS:7-!;  :>HHHHSSOSSSHO>CS7OQHSCC>7?C>COSSSSQQSOO?77>>!!7>?NH"
	write-host "HHHHHHHNO!?OCOO7>>COCC??>!77CC?77?>7C?!77777OHQOOOOOOQQSHHHHHHHHHHHHHHHHHHHHHHHHHHNH7:-SH>:-;:7OHNHQHQNHSSSHHC7OSQQHO77>:7COSSOOSQHHSSQC>>>??>>CCCNN"
	write-host "HHHHHHHNO7OOCCC>!:7??77?7!7??OOC?????C7CC77?OQQOQSC?QQQQHHHHHHHHHHHHHHQHHHHHHNHHHHNQO7;CNC:-:OHQC7>7CCQHSQHNQ7OQQSHS?>>>77???CC?OSHQC?C7!!?SO>>?7CNH"
	write-host "HHHHHHHMO7C?77>>!>?COOCCCCCCOSS??C?CC?CC?777CSSOCCOQQQSHHHHHHHHHHHHHHHHHHHHHHHHHHHHHO7-:??!:OOC?77?SSQHQSQQNS:CQC7SC777CO?7?7>7>7OOO7:!77?SCC?>>!7NN"
	write-host "HHHHHHHNC??7!>>>77CSOOCCOOSOOSC77??77>7??777>OSOC7CHSSQHHHHHHHHHHHHHHHHHHHHHHHHHHHNSOC:-:>?7CCOQQHHNHHHQSQHHC!7?77C??C??COOC77?7777?777?COO>>!!>!7NN"
	write-host "HHHHHHNH?>>>!>>:77OQQQOC?OSSSC!>?CO?>>7>777>7OQHC?QSSSQHHHHHHHHHHHHHHHHHHHHHHHHHHHNC->S?!>7!>?!:>?CS?CSQSHNO7!!!>OOCC?>!!7CO7!77>>777?C7C?>!>>>?7?NN"
	write-host "HHHHHHHN?!!!77>!>>OSCCOCOOSQS7>7COS?>?777??7>CSO7?QSOQHHHHHHHHHHHHHHHHHHHHHHHHHHHHNO;-CQ7::>>:--;!!>!7SSHHHC7>!!>CCOO?77>>7C7!?C?7>77??7?77>>7?C7?NH"
	write-host "NHHHHHHN?:!>??>:!>?7::7OOSQO7!>CCCO????>>7??>77!>SSCSHNHHHQHHQHHHHHHHHNHHHHHHHHHHNHC;;>HNS?7>:;;-:--:CSQNQSOC?7?7>>COOO?!7>7777C7>??>!>7C?77CC7?>CNH"
	write-host "HHHHHHNN?->77>>>7??C>77COSS?77?C????CC?>C>77>77!?H??HHHHHHHHHHHHHHHHHHHHHHHHHHHQHNHC-:!7HNNSC7:-::>COSHHSOC???77?77SQQS?>>>>>>77>>C?!!>7??OOO?>:!CNH"
	write-host "HNHHHQHN7!CC?>7>?CO???C?7CC77?777!7OOC7C> ;????:?COHNHHHHHQHHHHHHHHHHHHHHHHHHHHHHNQ>;-!>?HHHNQCSCSQSQHM?7>>>?7?COOSHHQC7>>>7?777COC>!!>>?COCC7>::ONM"
	write-host "HNHHHHHN>?OOC?7>?OOC??O?>>>!77777!>O?7?C!;!C7O?>77OHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHNS!:::>>QQQHHQQQQHQHHM7>!!:7?OOCOQHSCC77>7??>>>CSO?>777????C77>>SNH"
	write-host "HHHHHHHN>7OOCOOOSQQSOOO7!!!>7>7?7>??7????HN??C--QOHHHHHHHHHHHHHHHHHHHHHHHHHHHHQQHNQ>--!>CSSHHHNNHHHHHHH7>>>!!?C???OSC7?77>>??>C7CSSOOSO7>>>7?7C7>OHN"
	write-host "HHHHHHNH???77??7OSHSOOS>!>>??77?7!?77?7!-QQ7S- OHHHHHHHHHHHHHHHHNHHHHHHHHHHQQQQHNNQC-::>>?SQHHQQHHHHHNO>>!!!>>!>?OSSC7>!!!!>77??>?OSQHO???7C??C?!;NH"
	write-host "HHNHHHHQC?>!!:>>?7??COC>:>7C?>?777??C?7>-?SOC:;QQHQHHHHHHHHHHHHHHHHHHHHHHHHQQQHHHHSC-::!7OOSQHHHNNHHHH>>7>>77>>7OSSOC?>>>>77C??7!7?OOO?>>77OOOCC!7NH"
	write-host "HHHHHHHH?>!::!>!!!!:7?7!!!?C7?OCCOOOO?C?CNMQ!7NNHHHHHHHHHHHHHHHHHHHHHHHHHHNHHNNHHHHO>>!!!CQSQHHHNNHHHH>>7>>7?7?OS??OSOC??C7?OC77>7CC77!!!!7SSOC?>CNN"
	write-host "HHHHHHNH?>!>!>?7>7>!7??>!7?77>>7?CQOC7?7CHNS??QHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHNS>>7:-CQSQHHHHHHHHNQ?:>7?C?CSO77OSOC7?C?CC??7CCO?>>!!>>7OOC77>CNN"
	write-host "HHHNHHHHO7?C?C7?777777?7!>C7!>!!7?OC?C?7?NC:CSSHHHQHHHHHHHHHHHHHHHNHHHHHHHHHHHHHHHHNHO>C7?OSQHHHQQHHHHNQO!!>OHOO?77CSSSCCOC77SOSHC!-!!!!>!!>>::7?SHH"
	Start-Sleep -m 350
	Clear  
	write-host "HHHHHHNSC77777777???COCCC???C?C77?OO????7??C?C??C??C?????CC?C???OO-->OQ7C7:>SC7??????COSSOC???7??C7>?77?C77SSS?7>7?????7777??C???7??77777777>7>OQHHH"
	write-host "HHHHHHHS?7777?777???COC?C??CC?7>>>?OC????????C????????CC?CCOC??7CS--7SC>C>:7OO7???C?CCOSQO?????77??77777???OSO77CSO???C7>>7777???777777777777?>7QNHH"
	write-host "HHHHHHHS7?77C?C7??OOCCOC?C???C!:-:?CC???C???C?7C????C?CCCOC77>77C?.;?O?>O::OQC??7?C?CCCCO77??77?7>?77777???7OQC?C???>77>!!!77???77?7CC??C7777777HHHH"
	write-host "HHNHHHNS>7???CCO?OOSOC?77777?>----:>?COCO??7???C?7?????C?C?7777?C>;;C?!?C::CSS7???CCOC?7777???7>77?COOCC7777?SC?>>>>>7?77>7??77?777?CO??C??77777QNHH"
	write-host "HHHHHHNS77?CCOO??OSSOCC>>777?!-:->?!?OC?O?7?C?7C??C??77>>77C7777C!;-SSCCO::OQO7???????C?7777?????OOCSSO??7777?77>>777???7>7?C777?77777?C?C????>>QNHH"
	write-host "HHHHHHHO77CCCCCC?OSSOCC7777??>?OC??!CC?777?CCC?CCOCC?7>7CC??777?7:;!S?!?7::OS?77???777?C??C?CCCC?C??777??777777?7?77>?C?7777>>>7>??7>77???C??7>7QNHN"
	write-host "HHHNHHNO??CCC????COOOOO??77777CC?77>7?77>??OOC?COSOC?7>?CCC7?777!:-7S>:7!-:SQ?77?????77??7?COCCC?C77>77?O77777?CC??77CC7>??7>>>>7?C???CC???7?7!>QNHH"
	write-host "HHHHHHNO?77?777?7?OOCCC?777??CC77?7>777>77????7COSOC???COC777???!-:!O>:C:-:OS7>??C?7?????????CC???>!7?CCOC?7?C??CC????77???777>77?C?COSSC777?7>7QNHH"
	write-host "HHHHHHHSCCC??77??COOC??77>?OOOO7>7C?777>777??77COC???CCCC77>??7?:.-:O>>7:;-?O>>?CC7????CCSC7?SOC??77?C?COOO?CC???C?C?7??????????77??OSSOC7>77777QNHQ"
	write-host "HHHHHHNS7COOOCO??CC???C7??OOOOCCC?CC????7??>7!>7??>!777777?C?.;.-;-7S??O-;-OO>7777?7???OSOO?COSSC7??C?CCOOO???7?CO????777??COC?C?C??SSC??7>:!>!7HNHH"
	write-host "HHHHHHNS?COSSOOC??????C?CCOOSOOOOC?C??CCCC?77>>77?>!7777??CS?;.;;;!CH7CO:--OQ7?777?????CSSOCCSOCC?OCC???CCC?????CC????777??OOC??????OSOC?7>!!7!7HHHH"
	write-host "HHQHHHNS?OSSQSSQ?77???COOOOOHSSOCCC??CCSQOC?7C?77!!!>77?CCCM>.;.;:OHO>>S!::OO77?7?77???COSC77C?CC?OOC?77C???7?COC?7?C7?CCO?OCC??CCC7?OS??7777?>7HHHH"
	write-host "HHHHHHNC>?OOOOOO77>7??COO?CCOOOC7CCCC???OOC?7!>!>>!!77?CC77C:;;;;CO>:-:!::!CC?7>>!!>77??SC777>?OO777?7>77777777777777??SC??C??CCOC777CO?>????C?>QNHH"
	write-host "HHHHHHN?!>???7CCC?7>7?7C?77??COCCCOOC7777C??77>>>>>>7??C???7;---:SO:::-;;:>OQ?77>!7>777?C????>7CO7>777>>>7?7?>>>7>>7??OO77?CCCSOO?7!7C??>>CSO??7QNHH"
	write-host "HHHHHHM>!7??7CO?O?7?????777??C?OCCOOO777>777>7>777??77?777?!--::;-77!:--:77SS?7777????7????CCOCOO???C???777??7??7777??C?!77??COOSC??????7COSOC?7QHHH"
	write-host "NHHHHNM>>7???SSCC??COOOC>?7???COOOOC?777>77C?!!>???7777777>:---;;!7?C!::7!>HS>7>???7?77??77CCOOSC?CC?OOOOOC????OC?7CSC?77??O??OSO?COOCCC?COCCO??HNHQ"
	write-host "HHHNHHH7!7????????>7?7?7>7777C7???C?777>7777>>77?77>>>>77?!.;-:!>>:::!?C::!OO?77777?77?CC?7?O??C????CC???C??COCSQQQSOOC7?C?C??OSOCC??C?7???7??C7HNHH"
	write-host "HQHHHHHC>>?7>7777>>!7>>!!>???C77CC?77777?77>77?7?7!>>>>7??7;;:::7!::;:C?!::OC?77>!77777?C?????77>7777?77???COCOSQQQSSSCC?OCC?C?COCC?7?C7!77>?OC7HHHH"
	write-host "HHHHHHM?7?C?77>7>>>!>>>>>!>77?7???777777777777??C?77>7OC?C>;-!7CO7:--7?- -!HS7>7>>7>777?7?>>>!7>7777?7!>>7?C?>7?C??OQCO77O7????7?7?7>?O?77>?OQO?HNHH"
	write-host "HHHHHHM7>7CC?777>>!>>>777>!77777?7777777>77777??C?77?CSC?O>--!?CO?>::C?:;:7NS777>77>>>!>77>>>>7>777>77>7>7?77777???OSOC7?O?7C?7>???7?CO?77?COQO?HNHH"
	write-host "HHHHHHM>>?CC??7>>777C??77>>>77!>7???77777?7777?7????COOOOQ>;;:>?OHHS??OCC?CQ?777777>>>!7COSOO?77?>77?77?C?77?7??7?COCOC?C?CCC?CO?7OOOC?7???OOSO?QNHH"
	write-host "HHHHHNN7!777>7!!77??OOO7!!:>>>>77?7777??C?77777?C??CSOCCOO>;-!7>>COOC????COQ7>77>!7!7?SHQHHHHHHHHHQO?77??C?COO????7??C???777?7?O7>CC77>7CCOOOS77QNNH"
	write-host "HHHHHNM>:77777777???CC?7:!>>>7??C?777????C?>777?O?>?77>7?7:;::!!:::>O?C77?OQ7!>7>!>!7?SOOSSOHHQHHHHNQC?OCCCCOC?777??????C??7?>7C77??77CCOOSOCC7>HNHH"
	write-host "QHHHHHN7:>??7777>7?7?77?7>!77777C?7777777?C?C77COO77:--77!:;:>!:-:;;-!>7>?OO??7>!>CC??OQQQSSHSSQHHNNNNNQ7CCCC????CCSO?77?77?CC??7!?COSO???7?CC7!QNHH"
	write-host "HHHNHHM7-!77777777?7777C????7777?>777777???OOC?COSCC!:-77>:-:!!!::;;;-!>7COSC77>!>OQQSCQQQHHHSQHHHQHQHHN?7???7?CCOOOS77>>???CO???7COOO?777!>?S7!QNHH"
	write-host "HHHHHNN>--!>7?7>??CCCCCCCOOC?>7>>7?C?77777??OC?>?OOC777CC7:-:!:-:--;;-:>?QHS??7>OQOQHHOHQNHNHQHSHHHHHHNNQ77?7??CSQSOC??>7COO?CC7>7C??7?C777>7SC7HNHH"
	write-host "HHHHHNN!!>777777COOOOCOSCOCO?7C7>7COOC???777777>?OO?777CCC7;:::-:--;-:>CQHQOCCOOHNQSSSQHHHHHQHHHHHHHHHHHNC?77?7?OSO?777?C7CC7C????C7>>?C?7777?>>QNHH"
	write-host "HHHHHNN>>?7777CCSSSOC?C?777CCOOOOOQQSOO?C7>>>7?7CO7>!!>???:--:--:;;-:-7SHHS7??QNHQC7SOOHHQS?7QSOHMNNHHQQNQO>>7>????>>7>??77C?SSOQSSO7>??77???7>!QNHH"
	write-host "HHHHHHH77?77?CCCSSOC??7>>>>77OSQQSOSQQOOCC?7????O?7!:!7???>-:----:-:>>!OHHQ?7CQHQSSSQQHNNSC-;!::7OQQHHHHNHQ?>>77?77?777???COOOOSSSQO?77???C??777HNHH"
	write-host "HHHHHHH77?777COCSOOC777>>>777OQQQQCOQQOOOOC?C7?CCC7!!>??CC>-:------:7?CQHQQ?>OHHQSSSQHNHQC>-;-:-:?SQHHQNHNNC7>7>?77??77???OSSCOSOOSOC?7?CCO7?7>7HNHH"
	write-host "HHHHHNN!!7?COCOCOSOCC?7??CCCOSQSCC>7CCOSSSSOCCC?77777?OSOOC!!!:-:::CSQQQHOO7?HHSQQSCQHM7-;;.;;.7.::!QHQHHHNNS7>>?????????COSSC?77?CCOC?>>??>7?!>HNHN"
	write-host "HHHHHNH77?CCOCOCOSOC??77??COOSSOC7>>CCOOOOSSOSO7>77??CQOCS7!7C>>??CQQQHHHC?OQNHHQQOOQNH-..;;;;;-:---CNNHHHHNSC7>????C?CCOOQQQCCC?OOOSC>!77?7?C7!HNHQ"
	write-host "HHHHHNN?7?COOOSSOOC7>7?CC?7??OO?7??????7?OSSOS?>>>7?COSSC7!-CC?CSQQHHHNHO7?HNNHHHHOOMNC.;.;--;-:-::-7QNHHHHHQO??7>77??7COSQQOOOO????SC>?CC?>7?!:HNHH"
	write-host "HHHHHHHOC?COCCSSQS77?CCOOCCCOOO?7??C7???COOOCC?>77?OOOCOC!-!SHQQQQQQQHHQO??QHHHHHHSQMQ>;.;;;-;-::!::>ONNHHHHQO?>777>>777CSQO?7CO7!77OC>COC7!>C>!HNHH"
	write-host "HHHHHHNCCOSO7COSQC!7OOOOSSSOCQSO??7CC?7?CC?777!>7>COCC7???-!SHQHQQQCSHQOOCONNHHHNNQHMQ>.;;;-;7--;-!!??HNHHHQHS77??7>>7???OSO>?C?7>7??C>?OC?>>C>7HHHH"
	write-host "HHHHHNN7!?C?77CSO?7?7?OCCSQQQQSC77COO?>>777>!>!>???7???7OQ:;!>7>??OSQHQOCCSHHQHQHQHHMS:;;;;-;;---:!!CCQHHHHHHQC???7>>>777>?C?CCCCCC77>7CSO7!>?C?HHHH"
	write-host "HHHHHNH?!7?777CS???C7????OQHQHO?77?CCC77777!>777?C7>??7>ON!;:!77?OQQHHHH?OQNQQHHHHHNHC:--;-----:-:!!>?OQNHHQHHQOC7?77777>>?CCCCCCC?777?CC?7:CCOONHHH"
	write-host "HHHHHHH?>7????C?7777777??????S???7>77>77777>>7???777??7>OMC;-?OSOQSQHHNHSQQQHHHHHHHNC>-;--;;----::>!77?SNHHHHNSC7>7????CCCOOC???7??????C?777CC?ONHNH"
	write-host "HHHHHNH7>7???C????>>777??777?C???777>>777777777?77777777SMQ:-7CSSSSHHHHHQHHQHHHHHHHN?!-;--;;----:!>!!>>OHHHHHNO?>>7????CCCOOO??777?C??C??77?OO?SNHNN"
	write-host "HHHHHNH?7>>>CSC??7!!CC???77?77???777>!>>?777>>77!7>!!>7?HHMMO?QOSSHQHNNHHHHHHQQOQHHNC7;;--;;;-::!77-:--?QHHHHNQ7>7CCCCOSC?CSSC?7CC?CSOC??77SSOOQHHHH"
	write-host "HHHHHHQ7!>!!?OCCC7!!7??>>777???C???77>>??77!>>>!777>77>CNHHNNHSSSHHHHHHHHHNHHQQQHHHQC>;;;;.;:!!!!>>7SQQQHHHHHNHC>7?CCCSOC>?SSSOOCO?OSOOC7??7COSQHHHH"
	write-host "HHHHHNH7>777CC?OO777??7>!??CCOOQSOC?7?777?7!7>>!7?>>?7!SNHHHNHHHHHNHHHHHHHHHHSHHHHQC!: -:!7?O>::!:CNNSCSHHHHQHNS:>>>!7???>CQQOOSCOCCOOSO????>?OSHNHH"
	write-host "HHHHHNHCC?7?C??OC77777?>!??COOCQOC?77>7>7>>>>>7>7C?7777QHHHHHHHNHHHHHHHHNHQSQSQNHHQC?>:>?SHNQO!:!CSNHO?OHHHHHHNN>>>>>77?O?OHHQOSC?CCSO?C>77C77CSNHHH"
	write-host "HHHHHHHQO!!>77?C?>!>77???OOCC??CC??7>>7??>77>>777?CC77OHNHHHHHHHHHHHHHHHQHHHHQQHHHSQ7!>7CSQSQS>:!SNNNNMNHHHHHHHH?777C?77?7CSNHQHOCOSO?>>>:>>!CCSNHHH"
	write-host "HHHHHHHC?!!!7?7?777??COCOOC77>7?7?7??OSSO>>!!77>7???COQQHHHHHHHHHHHHHHHHHHHHHHHHHNSS7!>OQMNNQO:;;OMO?NQQHHHNQSHH?>?COOCCOOSSSSQSOCCSS?>!!!->?HOCHHHH"
	write-host "HHHHHNH7!:!>?C77?CC??CSC????>???O?7?7CSOO77>>>?CCOC7OOQHHHHHHHHHHHHHHHHHHHHHHHNQHNQQCSQMMM!OS7!-;?N>-CHQHSQNQSNH?>CCSSCCQQSCC?????CSS7!!:!!CSQC?HHHH"
	write-host "HHHHNNQ>>7>>>>7?OC??77?>>?CO??OOC?>>777C?77777SQCOCCSSHHNHHHHNHHHHHHHHHHHHHHHHHQSSHHOSS:>O>?!-;;;:S>!?OO>>7HHHHH?>COQSC?OCC!777??????>!!!!7OQHO7NHHH"
	write-host "HHHHHNQ77C?7>>7COO77>>>>>CCC???77>!777>7?>7777QQ?7>7CSHHHHHHHHHHHHHHNHHHHHHHHHHH?-QN!---:>7!:!-;.:NC!-7?>>CNHNHNC?CQQC?7?7:!????7777>>77:>7OQSC7HHHH"
	write-host "HHHHHNH??CCC?>7?O?7?7>7>7?7777?>>>!777>??7>>7CQS?7>7SQHHNHHHHHHHHHHHQHHHQHHHHHHN?.SM:--;->:-.;-;.-HO:::>>7CNNHHNO7?OS?>>7!:7777??>>7>>77!>CQQS?>HHHH"
	write-host "HHHHHNH??777>>?OOC?7777777>>7?C77>>7?7>?C?7??CC?>>>CQHHHHHHHHHHHHHHHHHHHHHHHHHQN?.CM---;;--;----;;OS!!!!>?CSHNQNC7???>!777!7?!7?>!>!!!!7!!7C?!:>NHHH"
	write-host "HHHHHNQ??>7>>>?OO7>>??77?????C?C77!>!77CC7777>>>>?CCHHHHHHHHHHHHHQHHHHHHHHHHNQQHC;SM:;;;--;----;;-?S:!-:??OQQNHH7?7>!>!>>777?!77!7>>>>!!7>!7>>!>HNHH"
	write-host "HHHHHHHC7777>!7??C?7CC????OC??77??77??7CC777?7??OSOSHHHHHHHHHHHHHHHHHHHHHHHHHOHHC>>QO7;--;.---;;..??::!>7CSQHNHS>?77>>>7>7??>>>7>7>>>>7>777777!!HHHH"
	write-host "HHHHHNN7>?OS7>77?OC??CC??COC???SCC?OSSC?C??7?CQQSOOSHNHHHHHHHHHHHHHHHHHHHHHNSSH7?O-OHC;;;;-::-..-:QQ>!7>7CSQHNH?7CCC?>>777>!>>!>777>>7!7?7?!>!>!HNHH"
	write-host "HHHHHNO!!?OO?7!!?C77CCC?>?C??CQHQCOQHQC77??OOSQOSSQHHHHHHHHHHHHHNHHHHHHHHHHN?SHQ7S!CNC--:--7!:SNNNMM?:7?CSSHQHHS?C?7?>77??>7>!>77777777?CCC77C?7HHHH"
	write-host "HHHHHHH>>?SO?7:!7CCCOCO7>??77SQHQCCQQSC?CC?COOSSSSHHHHHHHHHHHHHHHHHHHHHHHHHN7?SN>?C7NO--!-!>-!OSCQHH?!?OQSQHHNHNQC7?C?77?C777>7CCC??7?CCOC?7C?77NNHH"
	write-host "HHHHHHM7:>7????7??CCC?7>7CC7?CCCC?OQHOOSNQSC?COSSSHHHHHHHHHHHHHHHHHHHHNHQQHM>-;>O7CCNHC::!>:;--..;-!!>?OQHHS?HCCHSCOSHO>>C7>7?CCOCOC?CSO7>:!?>!>HNHH"
	write-host "QHHHHHH>--7??7??C??C??>7?C?????77?SQQ?7OQSSC7COO?CHHHHHHHHHHHHHHHHHHHHHHQHHMQ; ;H?>CNNS::!!-;;; .;:>>?COHHHO>OO>SHSSQQS7>?>>?COCC?O??OS?>!!!>>!!HNHH"
	write-host "HHHHHHM>-;7??>?C?C??C?77???CS>7>7?SQO>>?SCOOCC?C77HHHHHHHHHHHHHHHHHHHHHHSHHHN- .HQ7CHNO>:::-... :-7?7?COQHHC>CQ7CNQHHSO?77>>CSCC??OCCOO7!:!:!!!>HNHH"
	write-host "HHHHNNQ!>7?OO?7?OOOCCO?!7CCOC7>7>>??>!>>77?QQQOCOQHHHHHHHHHHHHHHHHHHHHHSSHHHNHO7HN!-SHQ>::--;!CHNNMNHQSSSQHO7CSCONO??>!7COCSQSSQQHHQSO?>?777>??7HHHH"
	write-host "HHHHHNQ>COOSO7>7?SO???7!>7?OCC?7>77?>>?77?OQQSQQSHHHHHHQHHHHHHHHHHHHHHHSQHHHHNNNHN?:7SN?!---:NMHSSQHHHQSQHHCCSQSQHC>>>!>?OSOOOSQQHQOOC>!7CC???C?HNHH"
	write-host "HHHHHNS>CC???>!::??C???>7C?OSOOO??CCCCC???CQSSOOQHHHHQHHHHHQHHHHHHHHHHHQHHHHHHHHNNO>:7HO7::OO?---7?CSQQQHHS>CQSOQS?777?77>7>7>?OQS?>:!>7SSO7!>!7HNHH"
	write-host "HHHHHNQ?O?>!7>>>?CCOCCCCCOOQQC?CC????????7?OSOC?SHNHHHHHQHHHHHHHHHHHHNHQHHHHHHHHNHO>-:?C7>CSC???CSQQHQQQHQO!??C?SC??7?OCC?7>77?CCC?!!>7OSO7>>>!>HNHH"
	write-host "HHHHHNS>?!::>>>7COQSCCCOSOSC?>77?7!!!>>77!!?SSOSHHHHHHHHNHHHHHHHHHHHHHQSHHHHHHHHNH7?>::777COO?HMMMHQQQQQNOC!>!!?OCC?77>CSS?!77>>7>77CC7C?!:!>7!7NNHQ"
	write-host "HHHHHNS:>!>7>!>7CSSOCCOCSQS?>>COS?>?777??7>CQQSSHHHHHHHHHHHHHHHHHHHHHHQQNHHHHHHHNQ!7SO>>?777!-:!7?7CSQSQHC?>!!>?OOC?77>>?S7>7777!777C?77>!!>7C>7NNHH"
	write-host "HHHHHMS!!7C?!!>!?O77OOCCSQ?>>?OOS?7?77!CC77CC?QMHHHHHHHHHHHHHQHHHHHHHQSSQHHHHHHHHQ--OHQ!!>>--;;;->;:OSNNQCC>7!>7?COC??>!77777S7>77777?C77777?O?7HNHH"
	write-host "HHHHNNQ:!7??7!!777>>7?OSQS?>?C?CC?C??7>:>777>?QNHHHHHHHHHHHHHHHHHHHHHHSOQHHHHHHHNS-;?OHQCC?-:----:!?QHHQOCC?7777>?SSSC>>>>7>>?7>7C7!>?77?C??7>!7NHHH"
	write-host "HNHHHNS:>?>7>>?O??7?C??OS???CCC77CSC?7!;7?7??OHHHHHHHHHHHHHHHHHHHHHHHHHQHHQHQHHHNO::!>ONHNQ?!::!>CQSHQCC?7?C?7CC?QHQQC>>>77!>C77C?!!777?OSOC!:-7HHHH"
	write-host "HHHHHNS!??7>>7?CCC??C??C?77?7?7!>COC??>7S>>C7SNHHHHHHHHHHHHHHHHHHHHHHHNHHHHQHHHHHO-::!CNHNQO??CCCOQQNO7>!>7???COOHQSC?7!>7?7!???C?>!>>7CCOOC>!:?NHHH"
	write-host "HHHHHN?!SOC????OOSCOC?!>7>>7>?7!7??7CO?HN!>> CNNHHHHQHHHHHHNHHHHHHHHHHHHQHHHQHHHNC;:>7CSHHHNNHQQHHHHNO7!:>>?OOCOSHS?777777??!?SQSO?7?7??7?C???>?NNHH"
	write-host "HHHHNHO>?7COOCQQHQOSC7!!>>777?777???77-7S7C> ?NHHHHHHHHHHQHNHHHHNHHHHHHHNHHQQHHHNO::7>?OSHHQHNHHHHHHHC>!!!!>?>7CCC?>>7>!>777>7CCSSSQS?!>>>7>7?!7NHHH"
	write-host "HHHHHNO>7>!77?CCSOOSO?>>?7?7?7>>777?7!:CN7>7:HNHHHHHHHHHHHHHHHHHHHHHHHHHHQQQHQHHHO::!:7OSQHHQHHHNHHHO>>>>!>>!>?SOSC7>!>>>77C?>>7COOQS?777CS?CC!:NNHH"
	write-host "HHHHNHC7>:;:!>>!>!7??7!!7C?7??????C?C77QH?>7NNHHHHHHHHHHHHHHHHHHHHHHHHHHNQQHHNHHHO!:>>>CQQQHHQHHNNHH?:>77???7?SQOOOOC777>7CC?!!>7C?C!>>!7OQCOC>7NNHQ"
	write-host "HHHHHNO!>!>>7>!7!:>777!!7C77C??SSOO7??CNNSOCCHHHHHHHHHHHHHHHHHHHHHHHHHQHHHHNHHHHNQ77>!>CSQHHQHHHHHHHO>!>?????SS??CSOC???7?OC7?77?O7>>!>!?OHSC?>>HNHH"
	write-host "HHHHHNO>7777?7>77!7?7>!>7?>!>>7OCOO7??CO7:>OQNHHHHHHHHHQHHHHHHHHHHNHHHHHHHHHHNQHHNSS77!CSQQQHHHHQQHHNQ>>>7COOOO>7OOSOCCOOCCC?SSSO?>!!!>>>?C?>>7?NHHH"
	Start-Sleep -m 350
	Clear  
	write-host "HHNHC??>777777??COOOOOOCCO??7CCOO?CCCC?C?????C?CC?C???>-7OSC?>!OCOO?????CO?CO???7?CSOOC7?CC???C7777??77?OOC?777?77?7>77C?CSC??7?77777777>77>HNQHHHQ"
	write-host "HHHHN?7777??777CCOOCC???OCCCC?COOO??C?CCCCC???C?C?7?CCC!-OOC??>!?COC77?C??CC77C???CSSSO?7?CC???777???777OSS7>7777?7777>7??COO?77777777777??77QHHHHHH"
	write-host "HHHHN?>?>>77777???C?7???C??C?7??OC????????????OC?C??CO?::SH7?7>!CO?CC?77???C??C???CSQQOCC??C7?77?>7>77?7SQS77?CCCC????7>??77??7?777777??>777>QHHHHHH"
	write-host "HHHHHC777?C??77??OOC??C???C?!:>>COCCCC????????C????COO?!:OO77C!>COOC?7???CC?7?7C??OOSOO??7?7?77>7777777?COOC?OOC???7>>!!7777777?777?7>777777>QNHHHHH"
	write-host "HHHNH?>77?CC?7?OOOCCCCC7?C?:;::>77CCCCC??777????77C?CC7-!OO??C!!?OC77?77CCCC?77C?CC7?77777?>7>>7??????7>?SSO?C7>>>777!7???7?7777??OOCC?77???7QNHHHHH"
	write-host "HHHNH?7?7COOC?COSO?7>>7?7?7-:->7!7CCCC???C????????77?7!;:SQ??C>!?OC??7??OOCC7??C??????777?C77?C?OCSOC??777??77>7777??7>7?7?7?77777??CC?777?7>QNHHHHH"
	write-host "HHHHH7>CCCOSOCOSSOC?>777??7>>>?>!7SO??7?COC???CC?C7>?7:->SC!CC7!COO???C?CC?C?????>7?C?777CC?CCC?OCCC777??777>777>7???777C77>777?7>77???C?7?!!SNHHHHH"
	write-host "HHHHH?7COC?????OCOOC7777777?OC??>7???77?OC?CCCOSCC77??>->O?;C7:7COC7?CCC???>7???????CC??CCOC?C??7>77??7?7>>7CC??>7???77777>>>!7C?77?CC???7?>!QNHHHHH"
	write-host "HHHNH?7?C?77>7?OCCOO??>7???C?77?>7?7777?C??7?CQQC7??OC>:!??>C>:>OQC??????7777?CC???C???7?COC??77>>77CC?????OOO?C77?7777??77>77?C7?OOOC?7???7!QNHHHHH"
	write-host "HHHHH??7?7??>7?COOC?77>??OOO?7?CC777>777???7CCOO??OSO?:;:C?!?>>>??C7??777>>>77C?77C?7?COC?COCC?777?CCOOCC??C???O??77??7?C7?7?77??CSSOC7>7?77>HNHHHHH"
	write-host "HHHHH???????77CCOC??7777CCOOC7?CC7777777?777?CO?7?CC>>:;:O?7C>!>?OC7??777>>7?7??7?C???COCCCOOC?777C?COOC??7C??CC??77??7?C7C???7??OSSOC7>>777>HHHHHHH"
	write-host "HHHHHCCCOCCCC?CCC?C?7??CCOOOOOCCC?7?C??7?7777?7>7?>;..;:CQC?C>--?S?7??777777??7?7?CCOOOOCCOQC?C?C???COOS???C?COC?C77777?CSS?CC77COSOCC>>!>!7>HNHHHHH"
	write-host "HHHHQ?COSSSSO??777?CCOSOOSSQSC??CC?COSO?777>777>>7:.;;-?HS77C77>?SC7??77777777777??COOQO??CCC?COOO?7??CC7??C?OC7777??7CCOOC?C????COSC??>!>>7>HHHHHHH"
	write-host "HHHHH7?OSOCOSC?>7??OSQSCOSSQO???CC??CSOO?7>>>7!>7>-;;-!SC!-::::->O7??7777??7>7>>77??COQC>77?CC??CC77????7?????77>>7OOCOOCCC?OOO?7>CO?7?7>7?77HNHHHHH"
	write-host "HHHNH!>???CCCC7>77?CCC?C??CCC?CSSC?7??OC?7>7>7>!7!--::!S!-::-.:!COC?7???7CC7>>>>>77?????7777OC77>?7>777?7??>777777?CSO?>7?7OCC?C>!?CC77COOC?7SNHHHHH"
	write-host "NHHHH!>7?7CC?CC77??C77??>?COOCCSSO7?777?77>>7777?7-::-:C7:!:-;!>CS??7>?7?OCC7>77777???7??C??OO??>?7777>777777>>>7???C?7>?CCOSC??77C???>OQOCC7SNHHHHH"
	write-host "HHHNN>7?CCOQC7CC7?OCC?>?7??CCCOC?C777>>7C>>>>??O?:--;--77O7:!7>!>?O7>7?CO?77777??7????7?COOOOCCC??7CCC??CCC?C????C?C77>??77OSC??CCC?C?OSOOC??QNHHHHH"
	write-host "HHHNH>7???CC??777?OC>>!77?7?C??7?7?77>>7?>>!>77?7;;---:::>77??7!!7C7!>7??7777??C?????????OOCC??CCCOOCOC??C??COOOSQS?>77??C?CSOCCCC?C??CC?7CO?QNQHHHH"
	write-host "HHHHO>7?7777>7?!>!>7!:!C???7?C?C?77777?7>>>7??7?!;;:>>!:;;:CO!--?CO?>7777?777>>7777CC???CC?7?77>7????7C?CCOOOHHQQSC?7CCCOCCOOCOO???C??>7>>?O?QNHHHHH"
	write-host "HHHNO>?77777777!>>>!>!>???????7??777777>>>>?????!.-:77!-;;:C>-;;COS7!>?????7>!!>>7??C??7???>77>>7??>77CCCCOCSSSQSSC??COOC??COCCC?7?C77>7>7CO?QNHHHHH"
	write-host "HHNHO7?7?77>>>>>>!>7>!>>>7?77??7777777777??7?C?O7;:7CO?-;->?:.>COQO7>>7?7C?>>!!?7777??C?777>777777?!>>7?C??77??OOSOC??C??777C???7>?C?777COSOCQHNHHHH"
	write-host "HHHHQ>7??7??777!>7?7??>>>7>>>???77>777777777????>-;!OOOOOCCC?>??CSO7>7777???7>777!!>????777>77777?777777?77????7CSOC???77O?7??CCCCCC?7??SOSS?QNHHQHH"
	write-host "HHHNQ:>7>777>>77??C?7>7>:77!!777?7777777?777?CCC7::!C?CQQCC??>>?SHS77?7777777777>77?QHHNNNHQSSOC?7?CCC77CCC7?7??CC?????7?O?CC?COO??7!7CCOOOC?QHHHHHH"
	write-host "HHHNH:>?77?7>77?CCC?>!!!!7>7???7777C???777777C?C!::!77>!?SS?7>!!QQCOOC?7>7?>>?!>>7?OSSCQCHNHNNNNHOO??COCCOS?7?7?C???C?7777>7O>7??77???SSOOO7>HHNHHHH"
	write-host "HHHNH:!??777>>7???777>!!!7777?7>77??7777??7>7CCC!;::7!>-:777>>7!SQCOO?777?7>77>!7?C?OSOS7SHSHQHHNNHSSOOCCOC7777OC??????77????>>>?CCSCCCCOOC7!HHHHHHH"
	write-host "HHNNQ-!7?77?7>7>>777???777>!>77>77?>7?C?OOC7?OOO>;:!!:--:.;:>>OOHQCC?>!?CC?7>!>7QOOSHHHHSQQSQNQHHHNNNO?????7??COOO?>>77??CO???7>CSSO?7>!>7C7!HNHHHHH"
	write-host "HHHNQ!!>77??7>?C???C???OC?77>7777??777C?COO?7?OQ?::!::::-;;:!7OSNSOC7>>7OC?777?OQHQSHHQHHHQHQNHHQHHQHQ??CCC7?OSQCO?7>77?CCOC777?CCC7?7!!>7OO7HNHHHHH"
	write-host "HHHNS->!>7??7>CSCCOOSOOOO???7>7OOO7??7777??777CS?>!!!::-;-;!7SHHHOOO??>7OOOC?QMNQSSSHHHHHQQHHQQHHMNQNNS7?7???CSHOC77????OC7?7???C7!7C?7777C?>QNHHHHH"
	write-host "HHHHO:7?7?7?7?OSCCCCOC???CCCC7CSSSSC???>>7777?OO7::!--:--:!!7OHHHO?COC77C??OQHHSCSOSHHHQSOOQHNNHHHHQHHHC>>777?OO?7777O7?CC?OCCOOO?!7?777?77>!QNHHHHH"
	write-host "HHHHS!?77????CSSCC?C?7777COOO?OQQQSO???7>777?COC>::!--:-;!!:?OQHQC7?CC7??7?SHHQOSCOSHHNHO??SOHNNHHHHHHQO>>7>7CCC7>>>?C7??CCOOOOSO?>777???7?>!QHHHHHH"
	write-host "HHHQC7??>??CCOOOC777>7!>77?QQQSOSQSQCCOC7?77CC??!:>::---->7?QSHHS?7?COCOO77HNHSCQQQHNNHO:---:>QQHHHHHHNHC7777777777777?CSSSOOSSSSOC???CO???7>HNHHHHH"
	write-host "HHHHS>?77?CCOOOSC?777777??OHHQC??OOSOOSOOCCCC?7?77!>:-::>?QQSQHHS??CC??OC?CHHQQSSSHNS?::;-;;;-77?HNHHHHHH?7>777?777??7?OSSCC????OCC?77CC???>!HNHHHHH"
	write-host "HHHNS!7CCCCCOOSOO77?C?CCOOOQO?7>>??COSSSOOSSC7>7??7CO?7OQHHQHHHQO??C???OOSQNHQQSCONQ;.;;;.;--;;;-!HNHHNNNSO777?C77CCOCOSSHC???OCOOC7>>?7>7C7!QNHHHHH"
	write-host "HHHHO>??OCOOOOOO??>7????CCOC?77777C???CSOOSO77>>??7OSSSQHHHHHNQS7?CC?7CCQHHHHHQQSSMC.;.;;;;;-:-:::QNHHHHHQOC77?777?C?CSQQQOOOCOCOSC>7??777?7!QNHHHHH"
	write-host "HHHHS7CCCSOCOSS?7????CO?7COO?>7CC777??CSSOCC7>>?CO7OHHHQSSHHQHSO77O?CC??NNHHHHNHSHH>.;;.;;;-:::!::CNHHHHNQSO>>??7777??OQQCCOC>777CC>?SC>!>77>HNHHHHH"
	write-host "HHHNQCOOO?CCSHS77COOOOSSOSSOC7?C?C?77COC??7>!>7CSS>:QQQSSSSHQQHQO????C?OHHHHHHHQQMH>;;;;;;;-;--:!!?QHHHHHQQC777?>>>777CQS77C?7>>7?C7?OC7>77?!HNHHHHH"
	write-host "HHHNS>?OC??CSQO>??COOOSSSOSSO??CSO77>7?7>!!!>7?C?O7.COOOCSQHQHNNHO7?CCCSNNHHHHHQHNQ:.--;;-----:!>>SQNHHHHNHC????>>7?77?CC??O??C?7?77OSC7777??HNHHHHH"
	write-host "HHHNO>7?777?OS7?C?7???OQQQSOC???OCC77777!>>>77O?>C7.:7?OHQQHHQHHNQ?CSOCSHHHHHQHHHM?-;-;;;--;--!:!>CCHHHHHHHSO??77>77?7!7C?CCCCOC?7>7COC7!>CCCHNHHHHH"
	write-host "HHHNS>7?7777CO7?C?7???CSSQSCC??7OC??77?7>77?77C?>SC.>?CSHQQHHHHHHH?COC?SHHHHHQHHHN?:;;;;;-:;--!:!>77SHHHHHHQS??77>77?7>?C?COO?OC?7>?CCC!!7OOCNHHHHHH"
	write-host "HHHHS>7???CC??77?7???????COO?7>>7777>>>>>>7????77HC:COOSSQQHHHHHHHNCC7CQHHHHQHHHNN!-;;---:-;-!!!!77?QNHHHHHQC?>??7??CC?COO?777777?7?CC77?OO7?NHHHHHH"
	write-host "HHHHS7777OOO???7!7?7???777????>>77>>7>777>>>7>7>7NH?7COQQQHHHHHHHHHC>?QHHHHQQQQHHQ:;---;;---:!!!!!::>QHHHNNH?>77C?CCOC?OSOC?7777CCC??C77CSS?CHHHHHHH"
	write-host "HHHH?>>>>COOCO?>!7??>7??7????C7777>>?7777>!!7!7>?HNHQSOQQHHHHNHHHHNO>ONNHHHSSSHHQQ>-;;-;->-C!?7>:->7?SHHNHHHC>7?C?OSSO7?OSSS?C?COSSS????OOOQQHHHHHHH"
	write-host "HHNHC>7>>CC?CS?>>7?7!!7??CCCOOCC??7777?7>>>>>7?7?NNHNHHHHHHHNHHHHHNO-?MHQHHSQHHNO?!..;;;;::!!!>!7CHQHSHHHHHHQ!>777??C7>7OSSOCOOOOOSOOC???77OSHHHHHHH"
	write-host "HHHNS?C?CCCCCS?7?7??!!7?COOOSSCC?7>7>>7>>>>7>7C77NHHHHHHHHHNHQHHHHN?:CNHSQQQHHHHC7-.!!OOOOC::!>CNNSC?QHHHHHHQ!!>>>7>7C?OSHQOOOC?OSSOOC?CC7!CSNHHHHHH"
	write-host "HHHHQO?>?77CC?7!77>??7?CCOC?CC7777!>77>7>!>777??CNHHHHQHHHHHHHHHHHNO7ONHQQQHHQHHSS777COSQQS7!>SHHHHSSHNHHHHNHC777>77>CCCSHHSQOC?OOO777>77>>CSNHHHHHH"
	write-host "HHHHQC7:!7???7777?7?OOSCC?>???7?7?COOC7>7>>?>7??ONHHHHHHHHHHHHHHHHHHSSHHHQQHNQHQSS--?CQHNQS!::SNNHNMNHNHHQQNNQ>CCCOC7?CCOQQHSCOOSQC!>!:>!>OCCNHHHHHH"
	write-host "HHHHO>7:>?C?7????CCOC?C77>7C??77??COOO?!!>!>7C??OHHHHHHHHHHHHNHHHHHNSOHNHHHHHQHHSC?SNHNHSQ7:.-OHQ;HQQHHHHQSQHS>COOOC?OQQQOOOCC??SQC!>!:!7CQOCNHHHQHH"
	write-host "HHHQ7>!:>7???CC?77C???77?77SC?77777??O?7???COOOOQHQHHHHHHHHHHHHHHHHHQSHHHHHHHSQHHQHHCSQC!C>:;.?HC;OSQQOSNHQHHO!?OQSC?OSO77?>C????C7!7>!7OQHS?NHHHHHH"
	write-host "HHHQ?>7>>>777CC??7?7>>7CS??SC777>7777?7777>OQSC7HHHHHHHHHHHHHHHHHHNHQQNHHHHNHH?HQQCO::7C>!:;.;!O?!COSC>CHHQHHS7COQQC7CO?:>?77???7?7!>!!?SSHQ7HNHHHHH"
	write-host "HHHQ77?C?>>>?OC777>>>>?C????77>!>7?77?7777?QQO>!QHHHHHHHHHHHHHHHHHHHHQHHHHHHHQ!CNS-:-::>:--;;.!OS>:!77!ONHHHNQ??CS??77>!:7?7777777>>>>>CSQQO7NNHHHHH"
	write-host "HHHQC?C??777COOC77777??7!>7?777>>77>!CC?7CCSC>!?HHHHHHHHHHHHHHHHHHHHQQNHHHHSHQ;:MQ-----!:-----!OQ7:7>77CNHHQQS7OC?7>7?7!!777C>>>!!!>>>7CQS?>>NNNHHHH"
	write-host "HHHHO7>7!:>7CSC?>>777??77?CO777>777>?C?77??77!7QNHHHHHHHHHHHHHHHHHHHHHHQHHHQNN->MQ;;;;;-;;-;;.->Q7!!::7?QHHHHC7?7!!!>>>!>7>>7>!!!!!!>>>777!!-HNHHHHH"
	write-host "HHHHO?7?>>!>CC77>??7???CO???7?7>777>CC7>>777?>CNHHHHHHHHHHHHHHHHHHHHHHHHHHHHHS;7QN.;-;-;;;-;;;;:Q:!!>>?CQHHNQ?>77!>77>7?C?>!777>7>>>!!77777>:HNHHHHH"
	write-host "HHHHC7>??7>7??CO7?C????SO??>?C???OOCCC??C??OSSSHHHHHHHHHHHHHHHHHHHHHQHHQHQQHSCO-?M!;;;-;;:-.. ->O>-!>7?SHQHNO77C??!>7>777!!>>!7?77>77777>777!NNHHHHH"
	write-host "HHNQ7!>CO?>>7>CC7?OC77?OO??CSSCCOQQS7???COOQQOQNHHHHHHHHHHHHHHHHHHHHQHHHHCONQ;C7CM>:;;---:;-!:OQMO-!?7OQQQHNO??C??>>77777!!>77>7>77!7???!>C7!MNHHHHH"
	write-host "HHHS!>?COC>!:!CCC?CC7>>CC?CHHSCOQHQO?7?COOSSSCSHNHHHHHHHHHHHHHHHHHHHQQHNM7>ON:?S?M7-!:::>:-NMMMMNS:?OOSQQHHNHQOO?7?777?7777>?C?7??7C?CSC77C?>NNHHHHH"
	write-host "HHHH?>>CC?>!>7??C?C?777?77CSQC?OQHSSOSSCCC?OOCQNHHHHHHHHHHHHHHHHHHHHHSSHN-:>CC?OCNC:::!!!;;>>>OOS>77COSHHHHSQNS??OO?>7C?77>7OOCCOCOC??7>>>7>>NNHHHHH"
	write-host "HHNHO>-7C??77?7??7??????>7?OSC?CSHOOSQHC77?OSOHHHHHHHHHHHHHHHHHHHHHHQSSHM!::>S77CNQ>:::>!;;. ->!7-7>?SHHHSQOOQQ7?OS?>>C?!77CCSOCO?OOC7!:>>>>>NNHHHHH"
	write-host "HHHQ?-;!??7?7??7???>7?O?COC!?>?SQS?7?SSOCCCOOOQHHNHHHHHHHHHHHHHHHHHHSOHHNQ7  OQ>CQHC::>!!-;...;;!!>?OSQHO!>Q??HQSQSC?77>>?COO?OC??OQC7!!>>>::NNHHHHH"
	write-host "HHNQ>::>?C>77CCCCCC?>7COOS?->!7CS?!!7??CSSSOC?HHHHHHHHHQHHHHHHHHHHHHSOHHNNS;-QN7>7H?-!?:!;..-:??QO7COSSHC>>SC7QHOOC777?77OSSOOOHOSOO7>:>>>>7!NNHHHHH"
	write-host "HHNQ>7?OSO>>??OCCC?7>!7CCO?77>>?C7!777?OHSSOOSHNHHHHHHHHHHHHHHHHHHHHSCHHHHNNNNNQ--HQ>::-;->HMNHMNNNSSSQHOCCQQSQS?>>!!?OOSSOOQHHHQQO7!7C?77?CCNNHHHHH"
	write-host "HHHS!?OCCC>::!???777!>7?OOOCC7??C??C??7CQSSOSHHNHHHHNHHHHHHHHHHHHHHHSSHHHHHHNHHH!-SQC>;::SHSC?CCOOHSSQHH?OQHQSQC7>7>!7????7?OHQS?:7>!?QC7>777NNHHHHH"
	write-host "HHNC7CS?7?>!:!?OOCC???CCSQSCO?C?C7??7???SSO?SNHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH7;7O?7!>O?:!-:?CSSHQQQNQ!COO?OS??7?CC?777?>?SSC?>->7COO?7>7!>NNHHHHH"
	write-host "NHNS>C?>>>>!7?OQSCCCOOOOOC?77C77>>7?7777CSOOHNHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHNSC>:7>>-CS?CSSHHQHHHQQQN?>7>77OC??????OO?>777?77?7?C?OO7>>>>>!NNHHHHQ"
	write-host "HHNQ!::>?!!!>7CSSOCCOOSQS>>?CO?7>>>7O?>7OQQQQHHQHHHHHHHHHHHHHQHHHHHHHHHHHHHHHHQ>7S?>????C7>COQSQOSSSQHQ?>!!!7SCOC>>!>?S7:77777777C?7??:!:>7>>NNHHHHH"
	write-host "HNHQ::!7?>!>!7COCCOCOSHSC:>OCO7>??77?>!>OQSSNNHHHHHHHHHHHHHHHHHHHHHHHQHHHHHHHNQ>:CQ777!:!--;-:!:!CSQHQO?>>!!7OCS?77>!>>?>>CC!>?777>7?7:>?7??7NNHHHHH"
	write-host "HHHQ!!!CC!::!?C7!7OOSQQC7>?C?O??777>-;777?77NNHHHHHHHHHHHHHHHHHHHHHHSSHHHHHHHHQ>;:HNOC!?!;;-:::->OSQNQCC?77>>??OCO?>>>77777?>?CC7>7???7?77?7>NNHHNHH"
	write-host "HHNS!!>77>!!7??7!7CSSQQC7??????CC?7>-!O7?C>;CNHHHHHHHHHHHHHHHHHHHHHHHQHQHHHHHNQ>--SNQQCC>--:::->?OHHHQO??7777>7SSQC7>>>?>7>7>7CC>!>77?CC?>!!!MNHHHHH"
	write-host "HHHS-!?7>777CCC77?CCOOO?????77CSO?77?HO77..:HNHNHHHHHHHHHHHHHHHHHHHHHHHQQHHHHMQ:-!7SNNHQ!--!:>?CCQHO??77??7CC7OHQS?>7>>77>77????!!7>COOO?7::!NNHHHHH"
	write-host "HHNO-CS??77?CSOC?C?!77>!>!77!>?C?7C?>Q??:  OMHHHHHHHHHHHHQHNHHHHNHHHHHHHNQQHHNO;--?CQQNNNQSSQQQHHHM?!!!7COOOOSQQC??77777?>7OOS7???>>?CCC??7>?NNNHHNH"
	write-host "HHHC-OOCO?CCSQQOOS7!!!:77777>>??7?7>:SQ?>;-QMHHHHHHHHHHHHHHHHHHHHHHHHHHHQSQHHNQ::!7CSQQHNNNNQHHHNNQ>>!>>7??77CSO>7?7>>77777OSSSOOSC>77777??>>NHHHHHH"
	write-host "HHNS!?>77?COOQQOSO7!>>7????7>77>7C7>?NH>?M7>NNHHHHHHHHHHHHHHHHHHHHHHHHHSHQHHHHO7::!7OOOQHHHHHQHHNHS>>>!!>>>>?CSO>>>!>!>7>?77?SOOHHS>77??7?C!:NNHHHHH"
	write-host "HHNO7>!:!>>>7?C?OC7!!7C?77?7?7????77ONH?7?::HNHHHHHHHHHHHHHHHHHHHHHHHHHSHHHHHHS7!:>7OSSQQHHHNHHHHQ>>7>?77>>CQSSS?77>777??C7!7?CCOS?>>>OOOOS>!NNHHHHH"
	write-host "HNNS!!!!!>!>>>:!?7>:!>C?>?C?OOOO?7C?OH7CSSOHNNHHHHHHHHHQHHHHHHHHHHHHHHHHHHHHNNHC7??>QSSHHHHHHHHHQQ>>>>?????QS?CSSC777?7CO??>>CCC7?!!>7HQQOC?>NNHHHHH"
	Start-Sleep -m 350
	Clear  
	write-host "HHHSO???C?CC??CCOOCOOOQHQSO??O?????CCOOOCCCCOOSO;-OOCOO??77???7???COSC?COOOOCC?7?SO????7???CC??77??7?77CS???77?7?77>!77??CCCC7???7?CCC??7?7QNHQHHHHH"
	write-host "HHNC7?77??7???CSOOOOSSSSOOCC?COC?????CCCCC?COCQ>.;OOSOQOC??CC???????COOOCCCCC??7?OS???77???C?7777??7?7?CO??777?77>77>7?CCCO?7??777??????77?HHHHHHHHH"
	write-host "HHNO777>?>>>??CSCCSOOOHOSC?C7?CO?CC???CCCC?OSQC:->QO;->SC?COCC??C????CSC???C?C77?OO????7?C?CC>7?77777>CSO77!>7?>>7>>!77?COO??7??>7?7?7>?7?7QHHHHHHHH"
	write-host "HHH77?77?7>>?CCCOOC??COC????COO??CC?C?OC7?C?O>.;7OS: .!SC?CO?C??CO??7?????7????7?SQSC?7?C???77?7777?77SSC7>777??777>777?CO??7777777>7777?7>QNHHHHHHH"
	write-host "NHH777>>?7?7???CC?C??7??C?7>7OO?C>C?7????CCC?;-:OCO7--?SCC?C??CCCO??7?7??????C??OSQSC?????7777777>>7??OSO77SSCC???77!77????77?7>>7??77!77>>QNHHHHHHH"
	write-host "HHN77?7?C77??C?CCC???????:--:7???CCC??7????C?-7OQCSO??SC?>7??CCC?7?77?C??777???CCCCO???7777>>77??7?7?7?OOC?CCC?777>>>>7?77777?????777777777QNHHHHHHH"
	write-host "HHN7777?????COOO????77??>-;:-77>?OOCCC?77??O?-?HS7CS!7SC777??OOOC7?77?OO???7?C?O??7777?777>>7?CCOC???7>COCC?>>>7>77>77C?7??777??C?CC7777?7>QHHHHHHHH"
	write-host "HHH7777COO??COSOC77>?77?>>>>>>!COCC?7?C??CCO7;7HS?CC!!CS77??CC77?7????OC?????C???????77?C7?C?CCSSO?7777C?77>777>?77>>7C?77?77?>>7?CC????>>>QNHHHHHHH"
	write-host "HHH>??OOOCCCOSOOO777777?>!?C?!!COC?77?CCCC?O?-?HS?CQ!7CS7>77??77777?C?OC7??7???????7??7COC?CC???C7?777>7777777>7???77?777>7>?7>>7?CC????7>!QNHHHHHHH"
	write-host "HHH?7CO7??77COOCC?77?7?77CC??>>7?7777COCC??O?:?HSOOS!7CQC77>?C??7???CCC?777??O??7?C???CCCC??77!>7?CC?7>>7?CC??>7??>77??>>>7>???7??C?77?777>QNHHHHHHH"
	write-host "HHQ?7C?7???7COCCCC7777?7?C?7777777>>7CC????S?:?SSSSS>>CQC77>?C???7???C?7777??C????C???CCCC??77>>7?CC??777CCC??7???>777?>7>777??7CCC?77??77>QNHHHHHHH"
	write-host "HHH??7?77>7??CSCCC77>>?C?C?>??777>>77??7???S?:7SSCOH7>OSO77>CCCC?7?77?7>!77?????C?77CCCCCCC??>>>C?CCCC??CCCOCO?????????7777??CCCSSC?777777>QNQHHHHHH"
	write-host "HNH??CC77????OC??777??OOOC??CC?777?77777>7?S7-7QS>CO!7OSC>!77??7???77?7!>7???77?CC?COO?CSSC??77???COOC?C7?7?CC????7777C????7??CSSSO?7>>7>7>QNHHHHHHH"
	write-host "HHH?CCOOOSC??C?7C77COOOOOSOCC??7C?O?C7>7>77?>;CSC:CS>7OOS7777??????777>77??7777?CCOSOOC?CSCCCC?C??COOC??7CCCCC??77777?OSC?C??CCCOOC?>!>!>!>HHHNHHHHH"
	write-host "HHH??OOSSSO?777?CCOOOOSSQQC?C??COCOSSC??7??7>-7?O7CS>!7SC777??777?77>777>777777?7?OSOC?7?CC7OCOO7????7777??CC7777??COCOO???CC??7OO?7?7>77>>QNHHHHHHH"
	write-host "HHH>7OOOOOC?77>7?OSOOOOSSSC7?OC???OOS??7!>>!:;>7SOOS-->OS?>>777>?7??77??>77>>>>77?COC?7777???7???777??77>7?777>>?OSCCCCC?CCO??77CO77?7??C?7QNHHHHHHH"
	write-host "HHN!>7??CCC??>77???7????COC?CSC777?7??>>>7!.;:7CHQON?>>CC7>7??77?777??CO?77>>>>777??C???7?OO7>7777>>>??7>777>!>7?CC777??COCC?77>?O??>CSCC?7QNHHHHHHH"
	write-host "HNN!>??CO???C77??C?7??7?COC?COO?7>7!77?7?--;.!OQQ?>?7>>CS????7777777?CSC?7777????7?77??CCCOC777?777777??777>777??C?7>7??COSO?7?????7?OQC?C>QNHHHHHHH"
	write-host "HNS>???CSSC????OCO>>??7??CCCC???77>>>>777;;;.CS>---; -7CS??7>>77>777??O?>77?????77??7?COOOS??C??C?OO??7C??C?CCCOO?777?C77OSC?COO?C??SOCCCC?QHHHHHHHH"
	write-host "HNO>???COO??77CCCC7>777??CC?C??7777>7>77?;-;;SO:-::;.->?O??7!>>7>?77??C77>7????77???77?OCCO??C?CCCOO?????CCOOOOOO?777?C?7OSO??OOCC??CC7?CC?QHHNHHHHH"
	write-host "HHC!7?77??777>77?7!>?7?????7???77777!>>>7:--:MO;-7::::>COO7>!:>???7777777?777?7??C??C?7CC??77C??C??7C?CCOCOHQHQSC?7???OOOOOOOC7??C7???>7C??QHHHHHHHH"
	write-host "HHC>?7>>?>>7>>!!>>!>777??77?777777777777?::!-7S??O7:C7:>??!>77??77>7?7??77>>!>>>7??C?7777>77>>??7>777?CCCOOOSOOSC?CCO??7????C777??7>>7?CSO?HNHHHHHHH"
	write-host "HNC>???77777>>>7>>7>>>>777??77777777?77?7:-!;->?HS>7SC7:O?!?CCCC7>!7???C?>>>>>777777?7>>>!!7>>7?7>>>7???77???COSOC??C7?77?7???77?C?7>7?SQO?HNHHHHHHH"
	write-host "HN?!>??7?>>77>??7?7>>>>!>!7???77>>??777?!;-::7:-:7OOC:.!CC7?CCOO77777777777777>>>7?COOCCCC??7????77?77??7777?CCOS??????CC?C?CCCOC?77?COSSO?QNHHHHHHN"
	write-host "HNC!>7?7?7>!7??CCC>>!>>>>!>???777?C?7>?7!::7>>:;;-C?..;?CO7???COC?77777777>777>!7?SHQHHHHHQSSSC7?7????COC77>??CCCC77?7?C??C7?OO?777?COCCO?7QNHHHHHHH"
	write-host "HN?!??77?>>7??CC?7>:!!!7???C?777?C?77777!--?Q?-;:7--:!CCQO>777?CSOC?77777>>>>>>!7COQQSCQNQHNHNHHSOCCOCCC?77>>C?????77??>>?C>>??77??OSOOOC7!QNHHHHHHH"
	write-host "HHC:777777>777?777?>>>>7777?777?77777?CC>-:7SC7:>C7:77>SNO>>??COOOC7>?777>>!!7??C?OSHSCQHSQHHHNNHQQS?CCC>777?OCC?>?777?????7>?CCCSCC?CCCC7!QNHHHHHHH"
	write-host "NNC-777>7?>>77>77CC?7?C?>77?>>777>>7C?OSC-:>SHHQOC?C>:;CHO>7OCOOSO>!>???77>!!CQSSQHHHQSHQQHQQHHHHHNO>?????COOOCO?>>777??O?777?OOOS77>:>?O?>QNHHHQQHH"
	write-host "HNC:>>77??>>COCC?C??OOC?7777>?????77???SO-:>OCQOHQC?7>-!QCCCOCOOOC7>7?CC?7>7CQQHQQQHHHNQQQQHHHQQQHHHC?????CCSQO?7?77?COCC?>7??OO???7>!>?SC7QNHHHHHHH"
	write-host "HN>:!>7777>>COOCCCCCOOC?77>77C????>7?7?OC-:>O?OCQQOO>>:7QOOOOCCCOO77>7OO?77?SHQHSSHQHHHHHQHHHHQQQQHNO7??7??CSQO?7?77??OCC?7?CCC?77??7>7?S?>QNHHHHHHH"
	write-host "HH7!?7??>???OOOSOCOC?7CCCC?7CSSOOC7?7>>7?!!>?>7??>CC!>7OHSSSC?CCOOC?77CCCSSQHHSCCQHHHQSSQHHHHNHHHQQNHC!>>7?COO?>77C777C?COCCCO7>>7??7??7?>:QNHHHHHHH"
	write-host "HH7>C77C?COOSSCC???777?COSOOSQHSSOC??7>7C>!>7:!7-;!?7?OQHSCCC7???CC???C??QNHHOOSSQHHNQ?>7CCHHHHHNHSHHS>>777??77777C?7?OCOSSSSOC?777??C?7?>!QNHHHHHHN"
	write-host "HH>7C7777OSSOO?777>>>77>?QNSOCSQQOCCOOC?C7>>>7:>;-:7SQQNHO77?7??7?CCOSC>CNNQSOHSQNNNC7:-;;->OQHHHHHHNNC7>7?7>?7>>>77?CSOOCOOSOO??7CCCO?C>77HNHHHHHHH"
	write-host "NH>777CCCOCOOSOC?7777?7OSQQOC7CCOOOSSOOCS??!>7!>-:!>SSHHHO?>?7????C??O?CHHHQHQOSHN?:--;;;;;--?CONHHHHHHO7777???7???CCSSSOC7??CCO?777??77>>!QNNHHHHHH"
	write-host "HH>77COCOOCOOOC?7CCCCCOOSOC77>7??OSOOSSSHC?>?:7::>77OSNHQ77CCCOCCC???OOQNHQHHOOQNQ;.;;;.;;;:;-:!QNHHNHNH?????????OCOSSQQS??CSCOSC>>777?C?>!QNHHHHHHH"
	write-host "HH?7?COCOOCOSC?777?????COS?>77?C??7?OOSOO?7?C>>:>SQQQQHHQ77?C?CC???7?CQNHHHHHSSHNO;;;;;;;;--:---ONNHHHHQO?7????7??COQQQSOOCCC?CQ?>7O77>??>!QNHHHHHHH"
	write-host "NHC?COOCCSSSS??7?C?CCC7OSO?7??????7?SSOCC77>?S??OSHQHHQHHO??????C?????QHNHHHHHQHQ>;;;--;;;-:!:-:CNNHHHHHQ?7??777>?7COQS??C?777?O?!?O?>:>C>>HNHHHHHHH"
	write-host "HHC?OOO7?OQQC>7COSSSSSOSSSO?7CC??7?CC??7>>>>CHQHHQHHNHHHHHS77CC???CSCCHHHHHHQQQNQ:;;;-;---;;!:::7QNNHHHHQ?7??>7!7?77CSO77C?7>7???7OS?7>77>>QNHHHHHHH"
	write-host "HH?7COC7?SQQC>7OSSOSQQQSSSO??CO?777??77>!!>>CQQHHHQHHHHHHHH?7CC???OSCOHHQQHHQQHNQ!;;;-;---;-::!>CSNNHHHQQ?7??>7!??77?OC77C?77???77OSC?>7777HNHHHHHHH"
	write-host "HH7>??>7?OSS77C7?CCOQQQQHCC7?COO?7777>>>>77>?SHHQQSQQHHQQHNHO??CC?OOCQHHHHHQHHNNC:;;;;;--:--!>7>CCHHHHHHHOOC?7>7????7>?C?CC?O?7>>>?S7>>7CCOHHHHHHHHN"
	write-host "HNC>>?7?7?CC77C777?CCOSOSOC?>?C??7>7?>!7????C?OSSQHHHHQQQHHNQ7??QC?7?QHQQHHHHHHH?-;---------::!>>7SHHQHHHSS?777>???77?CCCC??C?77??CC7>7CCCOHNHHHHHHH"
	write-host "NH?77?7CC7??777777??77?7?CC7>77>77>777777??>C?OSSSQHHHQHQQHNHO7?SO?7CHQQHHQQQHNQ!;;-;;-;->-:>:!7>!CNNHHHNSO777???CC??COC??7????7????77CO??OHHHHHHHHH"
	write-host "HN>777>CSCCC7!!7C?7?7??77?C777>>>>7>?77!>>>!CC7QQQQQHHQQHHHHNH?CCCCCHHHHNQQSQHHH>;--;;;---:!!::::-!QNHHHNSC>7?C?CSSC?COOC?7??COCC???7?OSOCOHNHHHHHHH"
	write-host "HH>>7>>CC?CC7!:7C7!?77?7??C?7>777>???>>>>>>!OM?SQHHHHQHHHHHHHNO?7C7?NHHNQQQHHHHH>-;;;;;;-!>!7:--C?OSHHHHHQS>7OC?OSO?>7OSSS??COOSSOC?7??CQSQHNHHHHHHH"
	write-host "NH7>777C??OOC>>??7>>777OOOOOOC7777777>7>>>>7CNHQSQHQHHHHHHHHHHQOC7:7MHSQQQHQHNO7-..;:-;!!!:->7SQNHQHNHHHHNQ!:?>77??7!?SSSOOOOCOOOOSCCC?>OOSNHNHHHHHH"
	write-host "HH?7C?CSC?OO777?777!???OOOSC?7?>!>>>7>>>>>>7CHNHHHHHHHHHHHHHHNHQ?>-?MQQQQQHHHNOC!;-?QOQNQ:!:OHNMQ7?SHHHHNNN>:>7>>>?CCOQHQSO?7CSQSOO??CC!7COHHHHHHHHH"
	write-host "HHSC7:>77C??>!7>7???CC?C??C?7777>7?77>>!>7777SNHHHHHHHHHHHHHHHHN?>7SNHHQQHHHHNSS7>>?OOSQS7!>SNHHNHHHHHHHHHNO77?C?>COC?QQQSSCCOQSC77>>7>7OCSHNHHHHHHH"
	write-host "HNOC>!!7?7777>77CCOOOO??77??77?CSOOC?>>777777SHHHHHHHHHHHHHHHNNNC!?OMHHHHQHHNHSO-->SNNNHS>--ONQQNNHHHHHQSHNQ7?COOCCCCOSSQSSOOOQS7:>!:!>?SOONHHHHHHHH"
	write-host "HH?7!!77?77?????COOCC?>>>?7?>7??OSSO?!!!!7777SHHHHHHHHHHHHHHHHNNQ7?OHHNHHQQQQNQO:?HNNNNNO!;;SMC!QHQHNHNSSHHS>?CSOCCSSSSOSCCOCSQQ?!7>:!?OQOOHNHHHHHHH"
	write-host "HH>7!>77?7?CC???CC?777?77CC?7777?C?O7777?COOCQNHHHHHHHHHHHHHHHHNNC7ONHHHHHHQQHHHONHSMS!C?:;.7N!-CSQNSSNHSHNO>7CSSOCSQO?77>7?CCCO7!>!:>OQQSCQHHHHHHHH"
	write-host "HH!77>?7>7?O???7>7!>?CSC?OC?7>7>>>7C>7>>OHQS?SNHHHHHHHHHHHHHHHHHNS>SHHHHHNNH?QQN??:;?OO::;;.:H?>??SC>?HNQHNO??SSSOCCC>!7?7???77?77>>!?SHHOCHNHHNHHHH"
	write-host "HQ>?C?77>7COC777>>7777?77?>>7>?777??7>77OHQO:CHHHHHHHHHHHHHHHHHHHQ7QNHHHNQHQ:>HN-;;-!!:--;-;:QC>::>?!CHHHHHO??CS?7>77::7?7??77>>>>7!7CSSO?7QNHNHHHHH"
	write-host "NH7?O?>!!CSSC?>?7>?C7>!77C77777??>?OC?CCOOC7:ONHHHHHHHHHHHHHHHHHHHOHHHHHHHHH-;HN;;;;::-----;-QOO!!>>!?HHQHNOCC?C>>777!:7>7C>!!!!>!7!7OO7!!!HNHHHHHHH"
	write-host "NH?777>!>COO7?7>77????7?OC7?>!7777?O?777777>7CHHHHHHHHHHHHHHHHHHHHQQHHHHQHHH!!HN;;--;;-;;;;..CC7!!!:77QHHHH?77>!!!!>777?!>7!>>>!!!>>>777!!!QNHHHHHHH"
	write-host "HH7?>77!!??C??77C7?C?CCC?77??>7777CC7>777?7?COQHHHHHHHHHHHHHHHHHHHHHHHHHQHNH>!OM-;-:;;;--;--:?C!::>7?OQQHHQ7>77>>>!>!?C7!77>77>>7>>!>7777!!QNHHHHHHH"
	write-host "NH>>7CC?7?77??77C?C?COO???CCCCOQOCC?C??COQQQSSHHNHHHHHHHHHHNHHHHHHHHNHHQONO>O!?M>;;--;;:-...;SQC-!>7COQHHQO77???!77777>>!>>777>77>7?77:>?7:QNHHHHHHH"
	write-host "NQ:>7CC7>>>>CC7?CO77CCC?COQSCOQHQO>7?CSSQQQOOSHHHHHHHHHHHHHHHHHHHHHHQHNCONO.??>M?;-;;--:-:!?SMNH;:>?OQSQNQS7??C?>!7??7>>!:77>77>7>7?OC!?C7>QNHHHHHHH"
	write-host "NQ:!7CO7!>!>CC7OOO>>?CC?OQHQCSHHQO!7?CSSSSSCOSHHHHHHHHHHHHHHHHHHHHHHQHM?CNN:7?>MC;----!!-?MNMMMN-:?CSQHHNHQ7C?7?7!7??7>>!>7?7777777?SO7?C?7QNHNHHHHH"
	write-host "HH>77CO?7>>>C?CC??7>??>7CSQO?OQHQSOOOCC?COCOSOQHHHHHHHHHHHHHHHHHHHHQSHM:!OOC7OCNO--!!:!:;:-CSHOC>>SOQQHHHQQHSC?OO?7???777?OOCCCC?OC?77777>>HNHHHHHHH"
	write-host "HN7:-?C???7??????7?CC?77??C?CSHQOOSNHO??CSSSSCSNHHHHHHHQHHHHHHHHHHHQSQM7:;-HC7ONQ?:::!?;;;..->>!?7COSHHOHOOHQCCHQ?7???>77CCCOC?7OSC?!:77!!>QNNHHHHHH"
	write-host "NQ>--!??7????CCC?>7CCCCO?>7>7OS?>>7SOOOOCOOCOOQHHHHHHHHHHHHHHHHHHHHHQHNQ:  SH7>SHC!!:!!-;..;-!777??SHHO>CQOCQSQQO?7>7>>COOOCOO?COS?>:!!!!!!QNHHHHHHH"
	write-host "NS-!!>CC7??COOOC?7>?CCOO?!>>7CC!:!>C?OQSOOOCOSQHHHHHHHHHHHHHHHHHHHHHQHNNO77QM7-?NQ-!:!-;.;>?OSQQCO?QQHO>CQSCQHOC77?CCCCSSOSSQQSSS?7>77>>?77HNHHHHHHH"
	write-host "NS!?SOOC>>??CC???>!>??CC??7!7?7>??777SHQSOOSQSQHHHHHHHHHHHHHHHHHHHHHHHHNNNNNMQ--HQ>:;;;!OMMMHMHHNQSSQHOCSQSOHS7>!!>CCCSQOSQHHSSQC!!7C?77CCCHHHHHHHHH"
	write-host "NO>?OCO?!:-!????77777?SOOC?7?O??C?777OQSSOOQHQHHHHHHHHHHHHHHHHHHHHHHHHHHHHHNNH>-CNC:-;!QSC>:7C?OSQSSHQ7CHQSSQC>>777777>7C?SHQ?>>7>>CSC>7>>7HNHHHHHHH"
	write-host "NO7OS>>7>!!7CSOCCCCOCCSSCCCCC?7??7777CSSCC?OHHHHHHQHHHHHHHHHHQHHHHHHHHHHHHHNHQ7;:OC>:>S>--;7OQSHHQSHMO!7S?7OC7??COC?77>777CC?7::77CSC?7>7!:QNHHHHHHH"
	write-host "NS>77!>>!>?CSSOCSCSOOOS?>>??7>!>7???>>COOO??QNHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH?OC:>>>7CC>CNNMNHNHHSSHHC>>>>7OOC?77?CSS?>?777>77?C??OC!!!!7!>QNHHHHHHH"
	write-host "HC!!!>7>!>7COSSOC?OSHQC>>CCC>>7>7?C?77OQHQC?SHNHHHHHHHHHHHHHHHHHHHHHHHNHHHHHH7>QO!>7>:!C!?CCSCOOQSQHS?>!!>7SOSC?>!7CO?:77>77?7?C7??7:!>?C7?HNHHHHHHN"
	write-host "NO!!!7?!!!7?OSOCOCOQHQ?!7OCC77????!-!7OQHQS::QHHHHHHHHHHHHHHHHHHHHHHHHHHHHHNH!-?S>!7>!!!:-;:7:>CSSHQS77!>7?OOS??7!7??7>7C?!7?77?777>!!77O?7QNHNHHHHH"
	write-host "MO:!>?C>:!7??777OOSQSC?:7?O???777>.;C7CC!>>; ONHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH!--NQ7>>>:-;;;->;!7OHNQOC77!>77COC?7!>7777?OC>7C7777?7777?7C77HNHHHHHHH"
	write-host "MO:!7777!7?CC7>?SOSQC??7CC???CC77>7HS77:;77-!HNHHHHHHHHHHHHNHHHHNHHHHHHHHHHNQ:::OHHOCC7;;::!>7CQHHHSC?C77?7>CQSSC>>7!>7>>>7?O!!!7??OOO7!!-!HNHNHHHHH"
	write-host "NC->C777>7OOC7??7COC7>??C77>CO?777CQ77: 7QO?NNHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHS!:-!QNNHQO!:>>>O?QHHO7777??COC?SNSC?7>7777>7?O??!>>77?SOC?!:-7NNHHHHHHH"
	write-host "N?-OS7?7?COSSCOO>!>!>77>>7!???7>C7:S77>.ONC>QQNHHNHHHHHHHHHHHHHHHHHHHHHQQHHNC-:!>CQHHNNQQSSHHQHHN>!!!>?OOCOSQO>777>>7C?77OSOC??C7>?C7?C?77?NNHHHHHHH"
	write-host "MC!?CC?COSQHQSSS!!!!>777?77????O7>?HS>?O>SSSQQHHHHHHHHHHHHHHHHHHHHHHHHHQQHHHQ!:!!7OSHHNHQHHHNHHNQ>!!!!7?>7?OSC>??>!>77777OQSSSSS?>>7??7?7>>HNHHHHHHH"
	write-host "MO>7>>7?C?SQSOQO7!7?CC7??7>77???>7CNS?O7 SHQQHHHHHHHHHHQHHHHHHHHHHHHHHQHHHHHO>:::>OCSQNHHHHHHHHNO!7!!!>>>CCCSC>>>>!!>77777?OOSHHC?7?CO?C?!:QNHHHHHHN"
	Start-Sleep -m 350
	Clear  
	write-host "HQCOCCC?CC???OOCCCCSQHSSOSO??C?7?COSCCOCOSSCOOS?;.!OSSO7>77??>7??CSOCC?COCCC???CSSC?CCC??CC??>7>?????CC??77777777>>>7?COC?C?????OOOOCC??7ONHHHHHHHQ?"
	write-host "NS7?7??CCCO??SCOCOSQQQQQSSOO??7???SSCOOCCSOCSOQO;;CQOOS?7????????COOOOCCCCC??77OSC7????C?C???77>?????COC7777?777>>>7???OC?????7?CCOCO?7?>ONHHHHHHNQ7"
	write-host "NS7?77>??C?7CSOSSSSSQQOSS???C???77OOOCCCOSOCSC;!->Q7  !O?7CC?7???CCOCCCCOOCO?>?QSC>77??????7>7??7?77??OC?7?>7?7777!>?CCCC???CC??????OC?7?ONHNHHHHHQ7"
	write-host "NS?7>777>>77CCCOSOOOSOOO??7COOCCCC??OCCCCCCCS! ;?CS>.;!SCCO????C?7?COOC?CCCC?77OSC??7???CCC7>777?????CO?>>>7?7>777>77??OOC?7?7?7???77?7?7ONNHHHHHNQ?"
	write-host "NO?7>>77>>7?CCOCCCCOOOOC???CCO?C?C??OC???CCCC:;OCCS?-:?SCCC?CO?O?7?????7>7???7?CQSOC????CCC?77?7?7>7?SC7!>>7?77>7>>?7C?OO?7??7>>>7>>7777>ONNHHHHHHH?"
	write-host "H?7777?7777??COC?????????77CC??C???????????C?->QS?SS!>CC???7????C?77????7????7COQSOC?????777777>7777OSO?7??C????>7>77????7?77?>>7777>>777ONHNHHHHNQ7"
	write-host "MC7>77??777??COOC??CCCC77:>7CC?C?C?????????O?-?HS7SS!7O77C??C?????>7?CC77??CCCOOOOCC?????>>7>77>7777OSO?COSOC?>77>>>77?777?7?77?7>>7>>7>?OHNHHHHHHQ>"
	write-host "M?7>7?OC???COOCC????7??!;;->77?OCCO?7?7??CCC7;7HS?OC!?Q7>?COCOC??77?OOC7?77?COC??7777777>>>CCCOC??7>>?OC7??>7>7>7!>77??77?777?CCC?7777?77ONHHHHHHHHS"
	write-host "N777>?OCC7COSSC?7777??>:-.->!?COOCCC???C?CCO>-?HS>CO!7C?7??CCC?7??C?OOC7?77?C??7?77>77??77COOSQS??77>?C?77777>7??7>7??777??>>???CC???77>7ONHHHHHHNNC"
	write-host "MC7??OOOCCOQSO?C7>?7???>?CC>!?OC??7??CC??CCO!-7QSOSC??O777??????????OC?7?CCC?7?C?????CC??CC?????7?7777>>77>7>>7C777?C77>>?>7>>77??????7>>ONHHHHHHHQ7"
	write-host "NC7CCCOOCCOSSOCC7777777>?OC7!?C??77??OC??COS!-?SSOSO?CQC>>7?777?????CC77??CC?7???????COC?C??77????7>77>7777777?C777??77>>777>>7????????!!CNHHHHHHHS7"
	write-host "NC7?C7???7COCCOC77>7??7?O?7?>??7777?OC??CCOQ!:CQO>OO77SS?>7C?777CC??C?>7???C?7??C?7?OCCCC??>>>7?CC?777??CC??77??777777>!>>>C???COC????7>>CNNHHHHHHS7"
	write-host "NC7??77777?CCCCC?7>?CC?CC>7C?>7>>777????COOH!-CHO>CC??OSC!7OC????7??77>>7???77??7C???CCCC??>>7???OC?????OCCC?7??7???77>777?C?CCSOC?7??77!ONHHHHHHNQ7"
	write-host "NC?C?77?7?COOC?C7???OOOC?????>77777>77>>SCCO>:7SC:CO77OSC!>C?7???77>?>!7????7?C???CC7?SOO?7?77?CCOSC?C7????CC?7777????777?7??OSQO?>7>7>7>ONHHHHHHNO7"
	write-host "NC?COOOO??CC?77??C?COOOSOC?C?C??C???77>>??77::7OO?SC>!7SC!>77?????7>77>??7777?C?CCSOC??SO??C?????COO?7??COO?????777?COO??C77?SSO??7!!>!!:CNHNHHHHNSS"
	write-host "H?7COOSSO???>?C?OOOOSQSOSOC???COOSSC7?7??!:;;;>OHOQO:>7OC>7CC???7?77>7???7777CCCOSQO??COC?OOO?77?CC????CCOO77?777??COSO?????7COOO?C7>>!>>ONHHHHHHNHC"
	write-host "M?7OSCOSO?7>>7?COOCCOOOSO7?CCO77OCCC?7>>!-.;;7CN?>HO?>!OO>777>77?7>7?77>>>>>77>7CSCC7>?7??C???>>7???7?77?777>?C?OOCCCCC?CCO?7?OS?77?77C7>CMHHHHHHNQ7"
	write-host "N!77C??C??>>>7??C??C??COC?CSCC????C?7>7>!.;;-SOS7>:!>>>OC7?>7777???7?CC7>!!!>77??C?77?77?O777?77>>7777?7?>>7>>?SOC??C??COCC?7>COC77?CCO?>ONHHHHHHHSC"
	write-host "N777C?CS?C?777???77????OO?COS?777!>7C?7>:-;;7H!.-7;.!>7QO7???7??7>7CCOC777777>??????CCC?CC77777777?7??7777777??C?7!>??COSSC77?CC??7OQSC77SNHHHHHHNQC"
	write-host "N77?CCOSCC?77?C??777?7?COCCOO??77!>7C?>>!::;7N:.!7;;:!>SS7777777>>7COO??777777?7?777COCCOC777??7?7?7??7??77>7????>>77C?CSOO????????OHSO77ONHHHHHHNQ?"
	write-host "N>7???OO?7???OOO?>77?77?CC???77?7!>??7>7:!!-!N!-?7-:7>>CQ>>>77>>>77?OC7?>????>?7??7?SOCCSCC?CC??OOC?CCC?O??7CQO?7>77??7CSO???CC?CCOSO?C?7SNHHHHHHHQ>"
	write-host "Q>7??>7C??>777??>>77????????77777>77!>77-!!.->?SO>:??>-CS>!:>7?C>77??7>7777??77????7CCC???7C?CC?C???CCCCSSSSSSO?7?CCC?CCOOO??CCC??7?77OC7ONQHHHHHNQ?"
	write-host "S!??7>7777!!!>>>!>77??77?C??77777777>>?7;!-;:!>OHC?O7:-OO:!!>?C?>>7?77777!!>!7?CCC?7?C?777!77???7??CCCCOSQQHSSO?C?OOOCOCOCC?7?CC777?>7OC?SNQHHHHHHQ?"
	write-host "Q>>?C77777>!!7>>>>!>777????7777777>777?>;!!??7--77O?;;>CS!7C??77!777??777!>!>77?77?7>>>!!>>>77>7!>7??????CCCOSOCC??777?7??C?7?CC77>7?CQSOQNHHHHHHNQO"
	write-host "Q>>??777777>>?777>!!>>>7>7777777?77777?!-!!CC:;;:>>;;-7OQ?CCCC?7!>7?7?7?7777>7>>>7??>>>7>>77??77>7?7C?777???CSSO????7?C???CC??CO?77?OSQC?SNHHHHHHNSC"
	write-host "Q!>77>7!>>!7?OO?7>!!>>!!!7?77777CC?????!:!7OQ7--?C-!OOSHH>?C?CCC7?77>777!777>>77OQHHHHHHHHQQO!77?C???O???77?CC??7??7???7?7?CO?7777CCOOO??SNHHHHHHNS7"
	write-host "H!>??777>>7?CCO?7!!!>>777?C7>>?CC??777?!:!>OHCO?C?7?:>OHS>7??COOC777777>>>>!>!>?OQQQQQHNHNHHQC?C7?OCCOC?777????7?7??7?77?>7??>777OCSOOO77ONHHHHHHNS>"
	write-host "Q!!!777>>>7777777>>!!!77??7!7?7?7>>7?7?>-:>?OQQQO???:-!HC:>C?COOC77??777?!!?>?7S?CHQ7CHQQHHQNNNNQSOO?C?7?77OC??7O?7?777??>!7CCCOOOC?OOC>>ONHHHHHHHQ>"
	write-host "S>!>?77?>77777>7?77?7777777?7?77777?COC7-:>C?7?SQQ??7::HO>7CCOOS?>>7???7>!:7?OO?QQHHOOHSQHHHHHHHNHC??C?7C?CCOC?>>?7???CC?7>?OOCO??7777O>>ONHHHHHHHQ7"
	write-host "Q!!>777?>>7??77?C???777777>77?7>>7??CSO?>:>C?!7CCSCC>>:HO>?OCOSS?!>7CC?7!!!7CSSOSSHHQQHSQHHHHHHHNHC7???7CCCOO??>777??COC?7>?OSCC77>>77S77SNHHHHHHNS7"
	write-host "O::!77??>7?OOCCCCCCOC?7?7>>?C7?7?7C7CCCC-:!?:>7:;>CCC?OHOOSOCOSO?77>CCC7>?OHHHQSHHHNNNHQHHHQQQQQHNQC??77?OSHO??777?CSOOC>??COC?7?C7>!7SC?SNHHHHHHNO!"
	write-host "C:7!77777?CSSOCOSOCCCCCC?7?COCC????>>>7?>!7>:7!-;:??OSHHQSSOOCOOC777COCC?OHNQQQSQQQHHHHQHNHHHQHHQHNS>7???OOSC7>7??7CO?C??7?O?7>?CC7>77C7>CNHNHHHHNSO"
	write-host "C>C7777?CSSSO7?C7>7>7?COOCOHQQSOO??>>77C7!!>!7:-;;:7QQNHSCC??7??CC77CC?OQNHQO7SOQNHH?C?COQNNHHHHHHHH>>>>7??C7>77CO7CCCCSSOOQ?>>7???C?7?!!CNHHHHHHNSO"
	write-host "C7C?77?CCSSSC?7?>>7>77?QSQSOQQSOOCC???7C?!>>:!-;:>>CSQNSO???77??CCCOO77OHHHSOQSSHNQS::--:>?OQNHHQHHNO7>777777>>7?7??CCOSSSSSO?7?7??OC?7>>OMHHHHHHHHO"
	write-host "C>?7?C?COOSOCC7777>7??OQHSO?CSOSSSSOOOCSO!>C::-:CCHSQHNOC7?CC>?CCC?OC!CQHQQQHSOHNQ7:;;;.;;;>OQNNHHHHHS7>7?777777?7CSQQOCC?CCC??777?C7?7!7SMHHHHHHHHS"
	write-host "O>??OOCCCOSSC?7????CCOOSOC?>>??CCOOOOOQO?>7O?>7>OQHQHHNO>7C??C?CC7?CC7SNHQHQOQQN?;;.;;;;;;:-:>SQHNHQHHC77?7??C?CCCOSOQOC?7?COC?7>>??7??>>OMHHHHHHHHC"
	write-host "C>??OCCCCOOO??7?????CCCSC77!77?????OOOQC7!7SSSSHNNHHHHHSC????CCC?77COQNHHHHSOOHN!.;;;--;;-::!:?SNNHHHNS????C??7COOSQHQQOOCOCOOC?>????CO>!OMHHHHHHHHO"
	write-host "SCCCOOCOOQOC?7???CCC?CSOC77???????OSOOO77!!QHQQHHHHHHHHHHC7????????7OHHHHHHHQONM-;;;;-;;;:!-!-!QNHHHHHQO>7777777?CSQQO?CO?7?CO?>7O?>!7?>!CMHHHHHHHHO"
	write-host "SCCOOCCOQQO??7?CCCOOCCSOC??CC?7?7CSSOOC>7!>HHQHQHQHHHHHHNO77??C?7??7OHHHHHHHSQHN;;;;;-;;;-!:-:!SHNHHHHSS>7777>7777OHQC7CO7>7CO?!7OC>!>?7!OMHHHHHHHHS"
	write-host "S7OCC7?OSS?7>COSSSQSOOQSO?7COC7>>?O7>>>>777?SHHHQQSQHQQHHMQ7?C???OOCHHHQQHHQQHNN;;;;--;-;-:-!>77QHNHHHQC??77>>>77?CSS7>?C>>>7??7CQO>>7?77SNHHNHHHNHS"
	write-host "O>7C?77OSO77??CCCOQQQQHSO???OO?7>777!!!>77CO?SSSSQQHHHQHNNNS?CCCCCSCQHHQQHHQHQMQ-;---;-;---:!>??SHHHQHNSO??77777?777?C?OC???7>>>CSO>!7C?CSNHHHHHHHS?"
	write-host "S>>777?C???7??77?CCSQSOSC??7CC??77?7>77?7C?SC?QSQQHHHHQHHHHH7?OOCC?CHHHHHHHHNNH?;;;-;;-;->-:!!??OSHHHHNHSCC??>>??777???OCCOC7>>>?OC!>?SCOQNHHHHHHHHO"
	write-host "S77?????7?7777>7?7?????CC?777?>>>>7>>77??7>S?7QQHQHQHHQHHHHNCCOSC77CHHHHQHHNHNO:;-::--;;---:!!>7CSHHNHHQO777?77?C?CCCCC??7?C?????C7>?CC?SHNHHHHHHNHS"
	write-host "C7777CSC?C7>!>?7????77???7>777>>7>?77>77?>>QQCSQQHHHHQHHHHHNQ7CCC7OQHHHNSQQHHNC:;--:-----::!!!!-!?HNHHHHC>>???C?OOCOSOC7>77??????C77OQOCSQNHHHHHHHH?"
	write-host "C>!>>?OCC?7>!7C7!?????7?C??>7>>777777!!!!>!SNQQQHQHHHHHHHHHHH?7?7>HHNHNHSHQHHHO:;.-;;--:!!77:-:!!CQHHHHHQ7>??CCOSO??CSSO??CCOSQSCC?7COSSQHNHHHHHHNH7"
	write-host "C>>7>?C?OO7>>>C?!!?7??COOCO????777?>7>>>>>7ONNNHQQHHHHHHHHHHHS??>!HNHQHQQHHNHQ7!......;:!:!:!CQHHQHHQHHNN7>?:7???7!>CSQSOOOOCSOSOC??7?OSQHHHHHHHHNS7"
	write-host "S?7??OC?CC?77?7?7:7?COOOSSCC77>77777>>>7>7?CHNHHHHHHHHHHHHHHNQ?7!:NNSSQQQHHHH7!.;:7?OOO?!:>7QHHQSSHHHHHHH7>7>>7>???OSQQOCCCCCQOCSC?CC>7OSHHHNHHHHHHS"
	write-host "QC7>777?CC>!77>777?CCCC?CC7?7>!>>>7!>7>>7?7CHNHHHHHHHHHHHHHHHHO7!>NNHHOQHQQHHSO>?OSOQQNO>>?ONNQQCSQHHHHHNO?>>??7?SCCSHHQOO?CCSCC?77??>7CQHHHHHHHHNN!"
	write-host "HS7>!>?7?7>!7?????OOCCC7?77?7??C?77>77>77?7CQNHHHHHHHHHHHHHHHNO?>7HNHNHHHHHHQQ?::>OOQQSO>:>QHNHHQHQHNHHHHSC7?C???C??SQHHSOOCOO?7>>!77>OCQHNHHHHHHNH>"
	write-host "Q?!!!?C7777?7?CCOCSC7>7???7>7?OOSC7>>!!777>?QNHHHHHHHHHHHHHHHNSC>?SHHHHHHHHHHS!:?OHNNHHO!;-QHQQNHHHHHHQHNQC7?SOC?CCSSSSSSOCOQS7!>>:!7?QOSQNHHHHHHNHC"
	write-host "!!!!77C??OC????OC??777>?C?777?COOO?>777???COQNHHHHHHHHHHHHHHHNHQ7CHNHHHHHQQHMHCSMMMH?SH?:;-HH-?SQQHNHHCSNS?7CSSCCHHHQO??7CCOQS7:>!::?SHSCSNHHHHHHHHO"
	write-host "?7>>>>>>7C??77?7>>?COC?CC?7>7>7????77>CQQCC?SNHHHHHHHHHHHHHHHHNH7?HNHHHHHQSOQHOO?:!O>7>:;;;CS-7CSQCCQNSQNO?7CSSC?OC7>!7>?C7?C?>!!>!>OQQOCSNNHHNHHHQO"
	write-host "C??C77>>CSC??777>>??C?7?7>>!777>???>>>?HQ77!ONNHHHHHHHHHHHHHHHHNC7HHHHHHHHC;SM>-:-:?!:::;;.?H>:!CO77QNHHQNQOOSO?7?>!:>C??????77>>!>7OQQC>ONHHHHHHHHN"
	write-host "C??77>:?SO7777777??!>>7C7>>:7??7>?C77??OC7>!ONHHHHHHHHHHHHHHHHHNQONNHHHHHH? ?M!-;;-!--;;;;;7HC:-!>!:QQNHNSO7?C7777>>>??777!>>!>>7>7?OC?>7SMHHHHHHNHC"
	write-host "O??7!!!?SS777>77???>>?CS?77!>?777CC77??77>>!CNHHHHHHHHHHHHHHHHHHHSHHQHHQHH?;OM>;;;-:;;---;;-SC>>::>7SHNHNOC7?>:!>7>>!7>>7>!!!!!!>!77?>!:>OMHHHHHHHQ?"
	write-host "O?777!!7????77??7??OCCC77??77777?O?7>77??CCCSNHHNHHHHHHHHHHNHHHHNHHHHHQQHHC!>MC;;;;--;;--..;O?::!>7?SQHHH??77!>!!77???>>7>>7>>>>>>77777!>OMNHHHHHHH>"
	write-host "C>7?C7>77CCC7?C???CSC??7?C????O?CCC77??OQSSOSNHHHHHHHHHHHHHHHHHHHHHHHHSQN?7?:NH-;;-;---;;-::C?::777CQQHNQ7>7777!777?7>!>>777>>7777>?>77!!OMHHHHHHNH?"
	write-host "7!7CO?777?OC>??????OC???CCC7OOS???C7??CSHQSOSHHHHHHHHHHHHHHHHHHHHHQHHHOQH!>C>QS----;---...;>S?::>>7?QHHNS7>?7?7!?777>!:!>777>>777?77>77>!CMHHHNHHHHO"
	write-host "?!?CO?>!:?CC?COO?!?O??CSHSCCQNQO7>7?SOSQOOOSSHNHHHHHHHHHHHHHHHHHHHHQNQ?QM!!O>OH-;---!!>:>SSHMH!:>??OQQHNS??OC?>!7?77>>>!>?77777>77OC7?C7>OMHHHHHHNS>"
	write-host "?>>OS?7:!7CCCCCO7!?C77CQHS?CSHSOC??COCOSCOSSOHNHHHHHHHHQHHHHHHHHHHQQNO:?H?>HCOH!:!;-!!->HQHMMQ>!?CSQHQHNHSO??CC7>?C77?!>7C7C7?CCC?OC>??77SNHHHHHHNS?"
	write-host "S>-!?????CC??7?77?CC77?CC??SQHSCOHHSO7CSSSOOCQHHHHHHHHHHHHHHHHHHHHSQNO!--SS77SNS::!!::;;-;->77>77OQHHOQHOHHOCSQC>7C7>7>?OOOOC?OQO77!77>!:ONQNHHHHHHS"
	write-host "O:.-C?7?CC??CC?77COCCC?>7>?OHO?>?SSOC?CSSCCOQQHHHHHHHHHHHHHHHHHHHHQHNN7  SN?>OMQ7::!:-;;...;!!>7?OSQN7CH?OQSSHQ?777>>>?OCCCC??SQC7!!>7>!>ONHNHHHHHHS"
	write-host ">:-!???7?OCOOC?7>7CCOOC:>7>7O>!!>?>OHQSS?COQQHHHHHHHHHHHHHHHHHHHHNQHHNH?:OHQ7;QN!:::--.. >7SQQCC?SSHQ>7SO?CQSOC77??7?OSSOSSSCOCC?!!?!!77?SNHHHHHHNH?"
	write-host ">>CCCO?>7COOC??>!7??COC77>>??!>7?77OHQSSCCSNHHHHHHHHHHHHHHHHHHHHHHHHHHNHHNNQ!;SH7-:-;;.7QNNMNNHHOSSHQ?CQOOSHC7>!>CSSOQSSQHHHQQO?>>??77??OQNHHHHHHHH?"
	write-host "7?OC?C>:->CC???7>7?CSQSOC??CC7CCC77CHSOQSOQNHHHHHHHHHHHHHHHHHHHHHHHHHHHHHNNNC;?MH>;;7?MMNC7SSOSQOSHHSCSHSSSS?!>?>>7???7CSQHC7?77!7OC7>7>OQNQNHHHHHQ7"
	write-host "7?S7>7>!!7COOC???CCCQQOCCC????C??77?OSOC?OSNHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHNHO--?O?:!OO>!-;>?COQQSSHQ?7OQ??OSC7?CCC>7777?OOS?!!>>?OS?7>7>?SNHHHHHHHN?"
	write-host "7?C!!>777COSO?C?OOOOO?7>7C7>>>777?77?SOC??CHHHHHHHHHHHHHHHHHHHHHHHHHHHNHHNNSO?:!77>OO?7OONMMQHHHQSHQ7>7?>COCC?7?OOC7>7??7>77>??COS?>!>>!7SNHNHHHHHH7"
	write-host "7>>!!>>77COQSCCCOSSSC?>7?C?>>7>??C!7?QSSCCSHNHHHHHHHHHHHHHHHHHHHHHHHHHHHHNNCCO>>>>7C?C>SHNMNNHHQOQNS7>7!7OOCC7>7?SO?>7?777>7?CC?CC>!!!7!?SNQNHNHHNQ!"
	write-host ">!>!7>!>7CSSSOCOOSHS7>>?SO7>777CC>!>CSHQO!:SNHHHHHHHHHHHHHHHHHHHHHNHHHHHHNNO!CO7!7:>>>:!:7??>CQQSHHC!>!>?SSOC7>!7CS?!>77>7?7?777?7!!>7O>?SNNHHHHHNO7"
	write-host "7!!?C>!!>?C??7?COSQC!!7CCO?7??77-;7>?OO-7. >NHHHHHHHHHHHHHHNHHHHNHHHHQHHHHN?-!QH7>>>::;;.:!:;CSSHQO7>>>>??CCCC77>7777?OC7>??777C7>77??O7CQNQNHNQHHQ?"
	write-host ">:777>!!7??7>7COSSO777??C7???7>>?SQ77>--?;;SMHHHHHHHHHHHHHHHHHHHHHHHHHHHHNN?::ONHOC7:-;---::7SQHNQCCC77?77?OSSC7!7>>>7?7>7??>77?7?C??7>!OQNHHHHNHHQO"
	write-host ">!C7>7>COC??7CCCCC?7?C??7?CO?777>SO7C. OO7ONHHHHHHHHHHHHHHHHHHNHHHHHHHHHHNN7--!CHNHH7!--->>?OQNHS?77C77C??OHQS?>>>>77>>7?CC!!77C?OSS?>.:CQNHHHHNHHNQ"
	write-host "-CO?777CCOOC?C?>>>>7>77777CO????:CC>7.;Q?CQQQHHHHHHHHHHHHHHHHHHHHHHHHQHHNHH!-!-CONNNHO?C?COQHHQO!!!>CCCOOQQQO7?777???77COOO>>7>7?OCC?7>!SQNQNHHHHHH?"
	write-host ":CCOOOCOSHQSOS7:!!!7>777>7?77CC>7QQ?7?7OSSQQHHHHHHHHHHHHHHHHHHHHHHHHQQQHHNH7!!>7OQHNNNNHNHHHHNO?>!:!???7?OSS77?>>>7??>7CSSQCOO?77?7?77?>OQNHHHHHHHH?"
	Start-Sleep -m 350
	Clear  
	write-host "OSOCCOCOO?OSOC?COOHQQSOSOC???>7OOQOOSOSSSOOSQ??!->>?:>C7777>77CCOSCCCC?C?C?77COO??COOC?CC????>?7??CCCC?7777?77777>???CCCC?C??COCOO?O??!ONHHHHHHHHC7?"
	write-host "OC??CC?OC7COCCCCOOQSQQSQSC??C>?OOSOOCCCOSOCSO;;->CC;;-?C7??>?7?CCOCCCOOC?CC77COO???C?????C77777????CCC?>7???77777>???CCCC?????OOCOOC?C7SNHHHHHHNNO>?"
	write-host "C?>>7CCC?COOOSCSSSHQSSOOCOC??7??COOOCCCCOOOQ7.-C?7?>->SO?7?>?C?COOCOCCOCCC?>7CSO7?>7C?7COC?777?7??7?OC??>7?>7777>7??CO?CC??C??COC?CO??>ONHHHNHHHHC!7"
	write-host "O?7777777??COOOOSSSSOOC77CCC????CCCCCCCOCCCC!;?HO>S?>7SC?CC???????OCOCCCCCC77OSO7777??7?C?7777??7?7?OC77?77?777>>7?CCCOC????????O?????7SNHHHHHHHHC>?"
	write-host "O?77>>7>7OCCOCOSOSSOC?77?COOCOOC???OCCCCC??S!-OHOCSO7?SSC????O?7C??CC???O??77CSSC?77??CCC777>???7???CC>>!>77777>>>???OOC?7?7>7777?7?777SNNHHHHHNH?77"
	write-host "?777?7777CCCCC?????CC??7?COC?????7?C77??C??C;>OSS?S??CSC???C?O?7?77???7????7?OQOOC???????7?777777?CSS?!7????7777>7???CO?77?77?7?777777>SNHHHNHHHNC7O"
	write-host "??>7??7777?COOC?7C?C?CC>>7???C?C??77????C?CC:>OHC7O??CQC?????C?7777????????7COQSOC?????7?>7??77?77OSOC7?OCC???7>77?77??7>77>>?777>>>7>>SNHHNHHHHH?>C"
	write-host "7777C??C?COOC?C??77?7>-;:>7CCCC?CC????????C7->OHOOO?7CQO?CCCC77??7?O?77?7CCCCOCO?????7>>>77??>777>7CSC7????>77>>>!77?7?77??7????777>77>CNHHHHHHHHO?O"
	write-host ">7??CCC??OSOC?777?77!!;;;>>?CCOC??7??7????C!:>CHOCO??CSC?CCC??77??COC?77?????C7?7777?7>77??OS????7>7OC??>777777>>?????7?777?CCC?777777>SNHHHHHHHNQ?O"
	write-host "7??COOCCSSSOOC7777??!>>7C>!7OCC777CC?C???CO?-?>HC>QO?CHC?OCC?7??77CCO???C?7?C7????7????7?C?OOO??777??7?7>>>7??7>77??777777>>7?CCC??77>>SNHHHHHHHNO!?"
	write-host "??CCCCCCOSOCOC7777??>>>??>!7CC???7CC?C?CCCO?-7?H7!SO?CQC?C??77????CCC?7??????????77C?CC??C??C???>777777777>7??777777777>77>>7???C???7>!ONHHHHHHHHC!7"
	write-host "CCC?7??7?OCCCO77>77?77?C?7>>?77?77CC???CCSS?:?SH7:S??CCC>???7???CC??>7>?????77??77??CO?????>77?7777>77????7>??77>777777>7C777??C??7??>:ONHHHHHHHQ7?C"
	write-host "???77777?COCCC??77????C?77?>77>7>?C????CSQQ7->CQ>?S7!>CC>???7???C?7?777?C?????????CCCCC?77>>7?CO??77??OCC777?777777777>>7??7CCCO?7??7>>SNHHHHHHNQ?7O"
	write-host "CC77777?7OSSC?77>7CCCC?77C?77>7>777?77?OS>!:-:?S?CO7>77C7????7777?>7>>77????C?77CC??CCO?77>77??CC?C???C?O????777???7>777????OOSO?>???7>SNNHHHHHHHC>C"
	write-host "?CCCC?C??CC???77??SSOOCCC????7??C?>>7>?C7;.;-?QHOCH7>!?O>7??7?77>77>>7???777?C??OC?CSSSC????CCCCOOC??7>???????7>???CCCC7?CCOSSCC77!>>>>SNHHHHHHNSOOS"
	write-host "CCSSQOO?7?7>???COOSSSSSCC???C?OOC?777>>?:.;.!OHH7>C?>7?C?7??C?77?77?7??77777?OOOSOCCSSO??CC?CC?COO?7??CCC??7?777??OSSC????7OSOCC7>!!>>:ONHHHHHHHQOSC"
	write-host "?COOOSO?7>>7?CSSOOOQSSSC???O??COSOC?7>>>-;;;COO.-:;;>7CC?7777?7?>777?7>>777?77CSSC77CC7CCCCC7???????7???C77>7??C?OOOC??CC???COC7777777>SNHHHHHHHHC>C"
	write-host "7?O?CCO?7>77?7CCC??OOCO?7CO?77COOC?77>>!!---SO;;7:;-::?O?77>777??7?777>!!>>>77?CC7777??CC77?777777??777?>>>77COO??CCCCOOC?77?S?77C??C?!SNNHHHHHHH??S"
	write-host ">7C7CCCCC777????7??7OOOC?CSO?77>>>?77>>:!!::OS!>C::7!>!OC777777>??????77>7777?7????O77CC?7>7?>7>777777>7>777?COC?7???CSOC?7>???7>7OO?77QHHHQHHHHHO??"
	write-host "77??OO?CC?77?C?77777CCC?CCSO?77>!>??>>7::!:;CS>C7!!C::!QO7777777??CCC??77777777?7?CO??CCC777?>>7>7?77777>777C?C777?CCCSOO?>7????>?SOC?7QHHHHHHHHHC??"
	write-host "77C?SSCC???COOC777?7???CO??77?77>7C?!>?:-:-.->CH?7CO!:!S777>7>>7>?SO??????7>??????CSOCCCS??7?7CC77C?CC??777??C?7>7?C??SO??7?C?C?CSQSOC>SNHHHHHHHHS7?"
	write-host "7777??7?7777?C7!77?7???????7777:7777!>?:-::-!7:7?OC7;;-OC!!>77>>77??>77??C?7???7???OC?CC??CCC?CCCC????CCCCCSO?7>7?????OSC?OCCC???C??CC7SNNHHHHHHQC!C"
	write-host "7??7>>777:!>77!>77??777CCC?77777777>7??:::!>>!;--C>.;-?S?:!7??777??77777>7777???C??CCC??77???77??C?CCCOQSQQSO7C7?CCC?COSO??CC?777?>7CC?QNQHHHHHHHO>C"
	write-host "7??77777!>!7>!!>>!>777????77777?7>>77??-!7COC;-->>;;CCCQC!?C77>77?7?7>!!!!!777??CC?777>77>>7?7>>77?O??OOSSSSOC?COC?C??C?C?>7??77>77?OO?QHHHHHHHHHO?C"
	write-host "77?7777>!>>77777>!7>77777??77777>777??C-:7OQO!;7CC>>COSHC?CO?>>>7?7?777>77>>77>777>>>!!>7>>?7>>7?7??7???CCCOSO?CC7?77?7???777C7?77?OSOCHHHHHHHHHHSSN"
	write-host "!7C>7>>!>7?OCC7>7:>>!!>>??7?77CC7?777??--:?SQQQQ?CC7:>SHC7COC?>777>?7777!77>>7!COSSSOOC??7?77???77???77?CCCCOC?C??CC????CCOOC?7777OSCC?QHHNHHHHHQ???"
	write-host ">7?777>77?COCC7!7:!77>77??7777CC???777?-->?COCQHOC7?;-CS7???OO???7777>>>!>>>>7?QHSHHHHHQQOO7?7???7?OC?77???C???C????77C77CC77>77CCOOC?7QHHHHHHHHQ?>7"
	write-host "!77777>>7???777:!!!7!!?C?77>?C?7?7>>?7C>::>7!!O7QS77->SC>7>?OOC?7????>!>>>>>>?O?OSCCHHHHHHNNQCCCOO?CO??7>7?777???????>?77?C7?C??OOSOO7!SNHHHHHHHQ?!>"
	write-host "!>?>>777777777??7>77>777777777777?CC?7C!-77!>77-!O??7?HC>C?OSO?>>???77>!!!7?OCCOSHCCHHSHHHNHHHQSOC?C?>777OOC?77777?????7>7OCCOCO??CCC7>ONHHHHHHHH?7?"
	write-host "!!7>7777777?????7??7!777777?7777??CSC7C7-??!!?!-:OCCCOHO7CCOSO7>>???777!!>7SOCOOQHOOHQSQHHHHHNHHOC?C?>???OOO?7>777?CC??7>7OOOCCC77??C7>SNHHHHHHHHC7C"
	write-host "!!!777?7CO???C?COCCC77>777?C7>>7?C?OC7?C>>7:!>-;:-CQQSHSCCCOOO7>77?CC7>7COOHHQQSQHHNQQSHHHHQQHHNQ???C??OQSSO??7?7CSOOO>777OOO777>!>7SCONHHHHHHHNH>7S"
	write-host ">!>7777?COOCOOSOCCC???777CO???7??7>7777?>>7:7>-;::?SQHNSOCCOOO?777CO?77?QHHHQSQQHNQHHHHHHHHHHHHHHS77C??CSSOC?77?7CO?C?77??C7>?CO7!77OC7QNHNHNHHHQ7CH"
	write-host "?77777?COOOO?C?CC>?OOOO?CSSHSOC??7>!>7???>>>!:::77SSHQNSCCCOCCSC7>CCCOSHNQQSCSQQHNQQHHHNNHHNHSQQHH?!>7CCOO?!>>?C77C???OOOS?>>?CC?>??7!!QNHHHHHHHQSSS"
	write-host "??>77COSSC?7??7>>77?OSQOSSSHSQOC??777?CO?77>:>>7OSQSHHQC?7777??CC?C?7OHHHQS?SOSHHNO7>7?CQNNNHHQQHNS>>>????7>777??7OCOSSSSQO77777?????>!SNSHHHHHHNS?7"
	write-host "777??CCSSSCC?777>77?OSQSOCOSSCOCOOC?CSO?7?CO?CSSHHHHHHH777?77C???SO77OHHHOOQSSNMNN!;--;-!?QHHHHHHHHC!>77>7777777?CSQQOOOOSO?C?77CS?7?7!SNHHHHHHHHQ?C"
	write-host "??OCOOCCOOOC?7?????CQQQOO77CCCOOSOOOSO?77?CHSQHQHHHQHHQO?7???CC?COC!?QHQHQQQOHQS!;;.;;;;-->CHNHHHHNQC777?777??7CCOSSSC?77C?CC7>>7C?77>>QNHNHHHHHNQ?C"
	write-host "7?OOOOOOOC??777CC?OCQQO??>>??CCCCOOOQS>7>7?HNHHHNHHHHHQMQ7>?C?C??O?CHNHHQQSCONM;;;;;;--;;-;:CMNHHHHNQO7??????OOOSSSQQOC7?COOC>>>?????7!SNHHNHHHHHQC7"
	write-host "??OOOCOOO?777?C??C?COOO7>7?7??7?COSCO?>>>77?QHHSQQHHHHQNNS?7????7?7SNHHHHHQSQMC;;;;;;-;-::-->NNNHHHHQO?77??77??CSQQQSCCOC??SO>>?C?7??7:SNHHHHHHHHQ7C"
	write-host "CCOCOCOSO?777?C??CCOSOO7>?C7??7COSSCC7>>>?C?OHQSQQHHHHSNNHC>??C???7SHHHHHHQSHM>-;;;;;;;:::---NNNHQHHQS?7777>777CSQQOCCOC?7?SC>7OO7>>?7:SNHQHHHHHHQ?C"
	write-host "COO?7OSQO>7?CSCSSSOOOSSC??S?777CCC7??!>77SS??SSSHHSHNHQHHNH?7?C?OCCQHHHHQHQSNH-.;;;;;;;--::::OHNHHHHQS77?77!>>?7OQO?!7O>>>7?C77SO?::?7!QNHHHHHHHNQSO"
	write-host "7CO77CSS?>??CCCCSSQSQQO?7?CC?7>??>>>:!!>7OSC?QQQQQQHHHQHHHNS7?OOSOCQHQHHHQQHNM!.;;-;--;--::!?OHHHHHHQS?7777>77?7??CC7?C777777CCOO7!77??SHHHHHHHHHOOS"
	write-host ">7?777CC>?CC7??COQSSSOO7??CSC7>??>!!7?7?7?OO7OQHHQHHHHQHHHHHC?CCCCQHHHHHHHHHNH-;;;;-;;-;-:!7?SOSHHHNNQSC??7>77?7>7?CCCCCCO?7>??CO7>>CCSHHHHHHHHHHC?Q"
	write-host "777?7???77??777??CC?OOC?7>?C77>77>>7????7>?MSOSQHHHHHHQHHHHNOO??7?QQHHHQHHHHNC:;-:----;-::!7>CCSHHHHHHS?77?>7C?77?C??CC????77?CCC7>?OCCQHHHHHHHHHSSS"
	write-host "777?OC???>!7?7?7?C?7??C?777>>>>7?>>>!??7>>?NNHQHQHQHHQHHHHHNC7CC7CHHQHQQHHQNQ>-;;-------:-!!!?C?QHHNHHS7>???7?COCOS???777?C??7CC77?CC?CHHHHHHHHHNQ??"
	write-host "7!>?SCC?7!:>??77777?77??7>7>>>77?77>>>>>7>7HNHHHHHHHHHHHHHHNS>77CHHHQHSSQHHHQ!--;.;;--::!!!::->7QHQHHNO77CC7?OSO??OOCC?7?CCOCC?C?7?SOOSHNHQHHHHHHO?7"
	write-host "7:>7CCCO?!>7?>>>77??CC?C??77>>???77>!>>>?>7QHHHHHHHHHHHHHHHHQ>>:CNHHHQSQQHHHQ>--;;.;::!:!?!;-77CQHHHHNQ??CC?CSOC>7OSQSC?CCOSSOCC?7??OSHNHHHHHHHHQ7?O"
	write-host "C?7OC?CC?7????7:7?COOOOOC???>7777>!>7>>7C>7QHHHHHHHHHHHHHHHHNO-:ONHQHQHHHNH??;..;;;-!!::->7CQQSQHHHHHHH>>>>!77?C!?OSHOOOOCCSCOOC?CC7COQHHHHHHHHHHCOO"
	write-host "?7?C????7>7>777>??CCOCCCC?7>!>!!7>7!>!>7?7?QHHHHHHHHHHHHHHHHNS--QMHSQQHHQHH??-;-CSHHHC:7>7ONNSCCQHQQHHN?!>7>>!?O?OQHHQOC?CCQOOO??CC77CQHHHHHHHHHMS7?"
	write-host "7!!>7??7>!>>7?7?COCC?CC???7>>?>>7!7>777777?QNHHHHHHHHHHHHHHHNQ::QNQQQQQHHHHOO>77HSQNMH7!>OQNHSCOQHQHHHNS>777?>7SCCQHHQSC??CSO??77??>7CSHHHHHHHHHH?:C"
	write-host "7!>?7?77>7?7CCCCSO??77??7>7?COOC?7!>>7>777?QHHHHHHHHHHHHHHHHHN?7CNHHHHHHHHHQ?!:>OQQQQS7::SNHHHHHHHHHHHNN>7?OC?7OC?SQQQSOCCSO?!>!!>77SOSNHHHHHHHHH?7O"
	write-host ">::>?C7C??C?COOC?7>>77CC777?OSSO?7>>:7???7?HNNHHHHHHHHHHHHHHHNSC?SNHHHHHQNNQC!CNMMNNSS?.:SMSQNHHHHHHOSNQ77?QSO?OQNOSQOCOOOSS?!7>::>?QSOHNHHHHHHHHOSC"
	write-host "7>7>>77?C?777?7>??C?OOO??7777???77777OQSOCCQHHHHHHHHHHHHHHHHHNSCSHHHHHHQSQHHOSNQHN?S>7>;.CH-:QSSHHHHSSHH>7?SSO?SQS?>>>>???CO7!77!>?SQO?QHHHHHHHHHCCN"
	write-host "7?77>>?OC?7777!!??CC?CC77>7>>>7?>>>>7QHSC7>SNNHHHHHHHHHHHHHHHHQSQHHHHHHQQ?CNS7O::C7?:--;;?S?>CSHS?SNQQQH7?OSSO7CC!!7?77???C7>>>7!7OSHOCQNHHHHHHHHQQQ"
	write-host "???7!7COC7??7?77?7!7777>!!7?7>7C?7???QO77!!QNHHHHHHHHHHHHHHHHHHHQHQHHHHN:->M?;-;:!!:--;;;>SC:!>??>OHHHHN7CCC?7777!!77?7?77>>>7>>>?SSS?7QHQHHHHHHNQC>"
	write-host "?7>>!7OSC77777?C?>>?CCC7>!>?7>7COC7CCC7>>>!HNHHHHHHHHHHHHHHHHHHHHHQHHHHH:;>M?--;---:;;--;:QO>7:>7>OQNHHH77?7>>!77>>?7>77>!>>>>>777OC?>>QHHHHHHHHQC>?"
	write-host "77>!!7???777C???7??CC?7??7777?CO?>7?>777?CCSHHHHHHHHHHHHHHHHHHHHHHQHHQHM7-7MO;;;;;;--;;;;;SC:!7>>>?HHHNS777!!!>>!7?7>!7>>>!>>>!!>777!!>QHHHHHHHHHC!7"
	write-host "7??7>7>?C?77C????OO?777C?77?C?CC?7777?OOOSSQHHHHHHHHHHHHHHHHHHHHHHQHSQNQC!>HH-.;-;-;---;;;CO:>7>77SHHHHC777!>>>!77?>!>7!77>>77>>7?777!:SNHHHHHHHH?>>"
	write-host ">?C7777?S?7>?????OO????C???COC???7?>>OQQSSOSHHHHHHHHHHHHHHHHHHHHHHHHQQNOO>!SM-.;---;---...?7:7>7C7QHHHH?77777!>!777>!>7>77>!777777?>>>:QNHHHHHHHHC>>"
	write-host "7CC?7!!7C?77OO?>?OC?COQQOOSHQC?77?COSQQOOSOSHHNHHHHHHHHHHHHHHHHHHHNQOSM-?7!CM>;;;;-:-;.-:7SS>;77?CQHHHH??CC?7!7?77>!>!>777>7777?C?7777!SNHHHHHHHHO>S"
	write-host "7OOC?!:7CCCCOO?!?O7?OSHHOCQHQOC?7?OCOSOCSSSOQQNHHHHHHHHQHHHHHHHHHHNS>?M?!?7HM>;---:!-:7HNMMH7-??C?HHHHHCCCC?7!7C??>>>!7777777777SC??C?!QNHHHHHHNQ>7O"
	write-host "-??C?7>??C?7??7?CC7?CCOC?CSHQSSQQSC?7OSOQOOOQNHHHHHHHHHHHHHHHHHHHSHS:!7O7?CCH?-:::?>.:C7ONMO7>??SQHHHHNHS??SS?>??77?77COCCC?COCC?>777>7QNNHHHHHHHO7>"
	write-host ";-?C>?OCC????>>COC?C77?7?OQQC?CHQS???OQOSOOQHHHHHHHHHHHHHHHHHHHHHQHH7; 7S77ONQ>:::>-;;;;:>C!>77CSSHQOHOQHOOHHC77??>>>?OCCC??OSO?>!>77>>QNNHHHQHHHS?7"
	write-host "-:??77?CCCCCC?>?OC?O>!!>7CO>>!7??OSSSOC7CHHHHHHHHHHHHHHHHHHHHHHHHHNNN: :M?77QH7-!!!-;;..;;->!COSQQN?:OS?QQSQO?7?7>>?COCCCOC?CSC7!!>!>!>SHHHHHHHHHSSH"
	write-host "7?OO7>?CSOCCO?!7??CC77>>>?C!!7>77OQQSSOCOHNHHHHHHHHHHHHHHHHHHHHHHHHHNQOOMO>-SN?!::!;.;-7CCSQCOOSSQHC>OSCQQSC?>>?CCOSOQSQQHQQOC7>777!???QHHHHHHHNHCCC"
	write-host "COCS>>-!7?777>>>7?OOC??77CC7???7?CHSSSSOONHHHHHHHHHHHHHHHHHHHHHHHHHHHNNNNHC;7MS:;.--7SMMMNNMHQSQSQQOOQCSNQC>>!>OOSSSOOSQHHSQO>>7C7??CCOHNHHHHHHHH?7?"
	write-host "OC777!-:?CCC???7?CSSOCOC?CCCCC777?SQOOOC?QQNHHHHHHHHHHHHHHHHHHHHHHHHHHHHNQO-!SQ?:-!SQSC>7COOHSSSQHS?SHSONC?777>>>7777?OQQO7>7!>?SO7777?QHNHHHHHHH?>O"
	write-host "C>>>>>??OSOCCCOOOOQO>>7C?7>>77??>>CSO??7?OSNHHHHHHHHHHHHHHHHHHHHHHHHHHNHHSO!-?O?:!CC;;;-:??OHSOSQNO>CS?>HO???CC7?7?777?CCC!!77CSO?7>7>>QNNHHHHHNNO7>"
	write-host "7!>!!7?CSSSOCOOSOOOC>>>C7!>>7???7>7SQO?7CSQNHHHHHHHHHHHHHHHHHHHHHHHHHHHHNCC7::?>!7OC>7CSOHQQHSSQSQO!??77SC??7COCO?>7?7?7777?C?OS7!>>>>>QHHHHHHHHNC77"
	write-host "!>7>>>7?OQSOCCCOQQC7>7CC?>>>7?C>>77SHQC?>QHNHHHHHHHHHHHHHHHHHHHHHHNHHHHHM77O?>>>>>?7COQHNHHHQQQQHQ?>>!7CSSO7>77OQ?!>7>>777????CC>!!!7!?HHHHNHHHHH77S"
	write-host "!7C>::!CO?C?CCOQHO>!7COOC777?C: >>?OO>7- CHHHHHQHHHHHHHHHHHNHHHHNHHHHHHHN>-7HC::?7>!--;!77>?SQQHHC>!>>>OSCC777!7C?>>??>>?77?7777!!7?O7?HHNHHNHHNS7SS"
	write-host ">??7:!>?C!>>COOQS?>7CCCC??7777!7Q?77!->- ONHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH>--CN77>7:-;;;;!:-?SQNNSC?7!>>?COOO?7>7>77?CC7>C?77??777?C??7CHHHHHHHHNHC?7"
	write-host ">777>7CC?77??COSC????7777OC7>>OMS7C- !H?SNNHHHHHHHHHHHHHHHHHHHNHHHHHHHHHN!:->HMCOO:-----!>>SQNQQ???7???>OSSS?>!>>7!77777?7>>7??COO?7:!?HHHNHHHHNHS>:"
	write-host "O?77>CCOO??C?77?7>7777>>CO?77?>HC7O..OSOHQQNHHHHHHHHHHHHHHHHHHHHHHHHHHNNH--!:CQNHQC!:::>7OOQNS7>>?C??CCCQQQO?>>>7?77>?CCC>!>>7CCSO?>::?HHHHHHHHHNN>7"
	write-host "OC?C?OSHSCCO?>!!!77!?7>7C77C??7HS?!>!QSCSCSNHHHHHHHHHHHHHHHHHHHHHHHHQHNNQ:::>?OHHNNHOSQQSHQHH?::!!?CCCOSHSC7?77>??777CQSO7>??>??CC?777OHHHNHHHHHNC:?"
	Start-Sleep -s 3
    clear
	Write-Host "May the Odds Be Ever In Your Favor"
    (New-Object Media.SoundPlayer "$pwd/2.wav").Play()
	Start-Sleep -s 4
    Clear  
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
        write-host -fore Gray -back $fileoutputdir 
        if ($fileoutputdir)
        {
            write-host -fore Gray -back black "[INFO] Finished with Directory Input, beginning to create file structure"
            try
            {
                mkdir $fileoutputdir/$CollectionDate
                function_InherentScriptingLogName
            }
            catch
            {
                write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $fileoutputdir
                function_failwhale
                clear
            }
        }

        else
        {
            $fileoutputdir = "./"
            write-host -fore Gray -back Black "[INFO] Finished with Directory Input, beginning to create file structure"
            try
            {
                mkdir $fileoutputdir/$CollectionDate/
                mkdir $fileoutputdir/$CollectionDate/$ScriptStartTime/
                function_InherentScriptingLogName
            }
            catch
            {
                write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $fileoutputdir
                function_failwhale
                clear
            }
        }
    }

    if ($Prompt_Script_Location -eq "NO")
    {
        $fileoutputdir = "./"
        write-host -fore Gray -back Black "[INFO] Finished with Directory Input, beginning to create file structure"
        try
        {
            mkdir $fileoutputdir/$CollectionDate/
            mkdir $fileoutputdir/$CollectionDate/$ScriptStartTime/
            clear
            function_InherentScriptingLogName
        }
        catch
        {
            write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $fileoutputdir
            function_failwhale
            clear
        }
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
        mkdir $SavedForensicArtifacts
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $SavedForensicArtifacts
    }

    $SavedForensicArtifactsCSV = $SavedForensicArtifacts + "\CSV\"
    try
    {
        mkdir $SavedForensicArtifactsCSV
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $SavedForensicArtifactsCSV
    }
    
    $SavedForensicArtifactsJSON = $SavedForensicArtifacts + "\JSON\"
    try
    {
        mkdir $SavedForensicArtifactsJSON
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $SavedForensicArtifactsJSON                
    }

    $SavedForensicArtifactsXML = $SavedForensicArtifacts + "\XML\"
    try
    {
        mkdir $SavedForensicArtifactsXML
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $SavedForensicArtifactsXML
    }

    $SavedForensicArtifactsWMI = $SavedForensicArtifacts + "\WMI\"
    try
    {
        mkdir $SavedForensicArtifactsWMI
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $SavedForensicArtifactsWMI
    }

    $SavedForensicArtifactsTasks = $SavedForensicArtifacts + "\Tasks\"
    try
    {
        mkdir $SavedForensicArtifactsTasks
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $SavedForensicArtifactsTasks
    }

    $StoredForensicLocationNET = $StoredForensicLocation + "\Net\"
    try
    {
        mkdir $StoredForensicLocationNET
    }
    catch
    {
        write-host -back black -fore yellow "[WARN] Could Not Create Directory: " $StoredForensicLocationNET
    }

    $StoredForensicLocationWBEM = $StoredForensicLocation + "\WBEM\"
    try
    {
        mkdir $StoredForensicLocationWBEM
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
                if ($var_pagefileexistsbool -eq "TRUE")
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
        if ($var_test_path_shell -eq "True")
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
        if ($var_test_path_time -eq "True")
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
        if ($var_test_path_consent -eq "True")
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
        if ($var_test_path_pipe -eq "True")
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
            if ($var_RIP_SHIMCACHE_MAIN_Test -eq "True")
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
        function_Triage_Meta-Blue_DLLSEARCHORDER
        Function_Triage_Meta-Blue_ProcessHash
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
        function_Triage_Meta-Blue_DLLSEARCHORDER
        Function_Triage_Meta-Blue_ProcessHash
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
        if ($var_CollectionPlanPrompt_Triage_Main -ne "No")
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
