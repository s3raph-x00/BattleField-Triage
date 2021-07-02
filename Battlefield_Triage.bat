mode con: cols=160 lines=100
echo off
SET ThisScriptsDirectory=%~dp0
SET PowerShellScriptPath=%ThisScriptsDirectory%BattleField_Triage.ps1

echo "##########################################################"
echo "##   BattleField-Triage.PS1 CONFIGURATION REQUIREMENTS  ##"
echo "##                        s3raph                        ##"
echo "##                       20210701                       ##" 
echo "##########################################################"

echo "Setting the Execution Policy to "unrestricted" to run the Powershell Scripts"
powershell set-executionpolicy unrestricted
echo "Press Enter to Continue"
pause

echo "Running the script now"
start PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& '%PowerShellScriptPath%'";

echo "Press Enter to Continue"
pause

echo "Setting the Execution Policy back to "restricted" to prevent malicious scripts"
powershell set-executionpolicy restricted
echo "Press Enter to Continue"
pause



echo ":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
echo ":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
echo "::      #######                                               /      ::"
echo "::    /       ###                                           #/       ::"
echo "::   /         ##                                           ##       ::"
echo "::   ##        #                                            ##       ::"
echo "::    ###                                                   ##       ::"
echo "::   ## ###           /##  ###  /###     /###       /###    ##  /##  ::"
echo "::    ### ###        / ###  ###/ #### / / ###  /   / ###  / ## / ### ::"
echo "::      ### ###     /   ###  ##   ###/ /   ###/   /   ###/  ##/   ###::"
echo "::        ### /##  ##    ### ##       ##    ##   ##    ##   ##     ##::"
echo "::          #/ /## ########  ##       ##    ##   ##    ##   ##     ##::"
echo "::           #/ ## #######   ##       ##    ##   ##    ##   ##     ##::"
echo "::            # /  ##        ##       ##    ##   ##    ##   ##     ##::"
echo "::  /##        /   ####    / ##       ##    /#   ##    ##   ##     ##::"
echo ":: /  ########/     ######/  ###       ####/ ##  #######    ##     ##::"
echo "::/     #####        #####    ###       ###   ## ######      ##    ##::"
echo "::|                                              ##                / ::"
echo ":: \)                                            ##               /  ::"
echo "::                                               ##              /   ::"
echo "::                                                ##            /    ::"
echo ":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
echo ":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
echo "Press Enter to Exit"
pause
