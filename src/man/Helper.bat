@ECHO off

SETLOCAL enableextensions enabledelayedexpansion

ECHO Ensuring the proper working directory
%~d0
cd %~dp0

REM Verify the files exist
SET agent64=.\x64\
SET agent32=.\x86\
SET script=MemoryzeAuditScript.xml
SET outputdir=.
SET bitness=%PROCESSOR_ARCHITECTURE%
SET sessionsFolder=RedLine
SET analysisFolderCommonName=AnalysisSession
SET auditsFolder=Audits

IF NOT EXIST "%agent64%" GOTO :failed
REM IF NOT EXIST "%agent32%" GOTO :failed
IF NOT EXIST "%script%" GOTO :failed

IF "%1"=="" (
	SET "outputdir=..\..\%DATE:~10,4%-%DATE:~4,2%-%DATE:~7,2%"
	GOTO :usedefault
)

SET "outputdir=%1"
REM Check that the directory exists, and if not create it.
IF NOT EXIST "%outputdir%" CALL mkdir "%outputdir%"

:usedefault
SET "sessionsFolder=%outputdir%\%sessionsFolder%"
SET "analysisFolderCustomName=%analysisFolderCommonName%1"

IF EXIST "%sessionsFolder%" (
	FOR /f "delims=" %%a IN ('cscript //nologo "%~dp0\getNextSessionFolder.js" "%sessionsFolder%" "%analysisFolderCommonName%"') DO (SET analysisFolderCustomName=%%a)
) ELSE (
	MKDIR "%sessionsFolder%"
)
MKDIR "%sessionsFolder%\%analysisFolderCustomName%"
SET "fullAuditsPath=%sessionsFolder%\%analysisFolderCustomName%\%auditsFolder%"
MKDIR "%fullAuditsPath%"
SET args=-o "%fullAuditsPath%" -f "%script%"

SET agent=%agent32%
IF "%bitness%"=="x86" GOTO :agentset
IF "%bitness%"=="IA64" GOTO :unsupported
SET agent=%agent64%
:agentset

FOR /f "delims=" %%a IN ('cscript //nologo "%~dp0\getPath.js" "%agent%"') DO (SET "agent=%%a")

SET "fullAgentPath=%agent%xagt.exe"

ECHO "%fullAgentPath%" %args%
rem PAUSE
call "%fullAgentPath%" %args%

SET iocExists=false
IF EXIST IOCs (
	SET iocExists=true
)
cscript //nologo "%~dp0\finishAnalysis.js" "%sessionsFolder%\%analysisFolderCustomName%" "%analysisFolderCustomName%" "%fullAuditsPath%" "%auditsFolder%" "%iocExists%"

GOTO :end

:failed
ECHO.
ECHO.
ECHO Failure Encountered:
ECHO Agent and/or Redline Audit Script not found.
GOTO :end

:unsupported
ECHO.
ECHO.
ECHO Failure Encountered:
ECHO This Operating System is not supported by the FireEye Agent
GOTO :end

:auditfail
ECHO.
ECHO.
ECHO Failure Encountered
ECHO %errorlevel% return from "%lastcmd%"
IF EXIST "%buildlog%" START notepad "%buildlog%"
GOTO :end

:end
REM PAUSE
ENDLOCAL
@ECHO on