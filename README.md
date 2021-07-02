# This Project Is Still In Early Beta #

## BattleField-Triage (BFT) ###
Forensic Triage Toolset

### Background: 

    ######################################################################
    ### The name and the methodology stems from a need to be able to   ###
    ### conduct digital media forensics in austere enviornments.       ###
    ### have tried to take various lessons I have learned the hard way ###
    ### and standardize the apporach for organizations needing an open ###
    ### source solution in areas that lack enterprise solutions.       ###
    ### These techniquesare not meant to replace such solutions like   ###
    ### F-Response, KAPE, etc.                                         ###
    ######################################################################

### DESCRIPTION:

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

The core functionality of the tool requires the associated binaries to be in the ./src/ directory. Plan accordingly prior to running. 
- Test software and script prior to using in a live enviorment

### REQUIREMENTS: <br />
Note: Store Binaries (And Their Associated DLLs/Files In The Following Folder Structure:<br/>
<blockquote>
#   ./BATTLEFIELD_TRIAGE.ps1<br/>
#      ./src/<br/>
#         ./src/DumpIt/DumpIt.exe<br/>
#         ./src/ftk/ftkimager.exe<br/>
#         ./src/man/helper.bat<br/>
#         ./src/RamCapture/x64/RamCapture64.exe<br/>
#         ./src/RamCapture/x86/RamCapture86.exe<br/>
#         ./src/Surge/surgecollect.exe<br/>
#         ./src/winpmem.exe<br/>
#         ./src/memoryze/Memoryze.exe<br/>
</blockquote>

ProTip: _./src/man_ refers to Mandiant Redline Collector.
    
### Current Development Status 
  1. Windows PowerShell Script
     - [X] Core Functionality <br />
       &#9746; Additional Triage Sources   
       &#9746; Switches and Parametization
       &#9746; Testing
     - [ ] GUI   
  2. Linux/Unix Python Script
     - [ ] Core Functionality
       - [ ] Additional Triage Sources   
       - [ ] Switches and Parametization
       - [ ] Testing
     - [ ] GUI   
  3. OSX Script
     - [ ] Core Functionality
       - [ ] Additional Triage Sources   
       - [ ] Switches and Parametization
       - [ ] Testing
     - [ ] GUI   
  4. Companion Analysis Tool
     - [ ] Core Functionality
       - [ ] MITRE ATT&CK Integration
       - [ ] Testing
     - [ ] GUI
  5. ELK/Splunk Linkage Tool
     - [ ] Core Functionality
     - [ ] ELK Linkage
     - [ ] SPLUNK Linkage
     - [ ] Testing
     - [ ] GUI

##### Legend:
- - [X] - Completed <br />
&#9746; - Partially Completed
- - [ ] - Not Started

##### Known Issues:
  1. Windows PowerShell Script
     - [ ] Red Line's Folder Creation For Artifact Is A Few Seconds Off Which Causes It To Create A Seperate Folder.
     - [ ] GPResult Does Not Dump Into Appropriate XML Format.
     - [ ] Disk Info Does Not Always Appropriately Mark The Drive As External.
  2. Linux/Unix Python Script
  3. OSX Script
  4. Companion Analysis Tool
  5. ELK/Splunk Linkage Tool

### Updating The Core Binaries

When updating various binaries (winpmem for example), ensure the name matches what is currently in the directory and copy over any associated .dll file. 

  <Special Note Regarding Mandiant (FireEye) Redline Collector>: The _Helper.bat_ file located in _./src/man/_ has been modified to store forensic artifacts in a relational folder   along with the others. Feel free to update (or use different Redline Collection Configurations) but try to match the associated changes as seen below:
  
   ![image](https://user-images.githubusercontent.com/27127072/124299452-6df85500-db2b-11eb-9795-d6edbabf880b.png)
