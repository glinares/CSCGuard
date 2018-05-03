# CSCGuard
Protects and logs suspicious and malicious usage of .NET CSC.exe and Runtime C# Compilation 

# Usage
CSCGuard is meant to be used in sandbox, analysis, or non-production environments.  I simply have not tested enough conditions to guarantee it's performance or security within real user environments, please use at your own risk.  The code is ugly but its functional, being a hack done in a single day in order to analyze some malware.

# Installation
- Compile the source and take the resulting CSCGuard.exe and CSCGuard.exe.config files or use the provided binaries.
- You will need to elevate your privileges to TrustedInstaller in order to change the .NET Framework folders - I suggest using the tools RunAsSystem and RunFromToken tools in order to easily accomplish this.
- IMPORTANT! Backup the original CSC.EXE and CSC.EXE.Config files stored in your \Windows\Microsoft.NET\Framework & Framework64 sub .NET version folders and rename them to CSCGuard.EXE and CSCGuard.Exe.config in their current folders (See Config section)
- Rename and move CSCGuard.exe and CSCGuard.exe.config to CSC.EXE and CSC.EXE.Config in the .NET Folders in order to replace and intercept CSC execution.

# Example Installation 
End result in C:\Windows\Microsoft.NET\Framework64\v2.0.50727 (or default .NET folder) should be similar to this:
CSCGuard.Exe ->             05/03/2018  01:26 AM            20,480 csc.exe
CSCGuard.Exe.Config file->  05/03/2018  07:30 AM               267 csc.exe.config
Original CSC.EXE ->         09/28/2017  03:49 PM            88,720 cscguard.exe
Original CSC.EXE.Config - > 03/20/2018  05:38 PM               221 cscguard.exe.config

# Features
- Able to detect and prevent runtime C# compilation used by malware even when "GenerateInMemory" is used
- Limited Heuristic detection of suspicious usage of CSC.EXE
- Variable threshold to allow pass-thru to original CSC.EXE or to deny execution
- Optional Windows Event Log creation whenever CSCGuard is triggered
- Captures Evidence in %USERPROFILE%\CSCGuard\Log\ to allow future analysis
- Provides detailed logs for users to review all parameters passed to CSC.EXE
- Minorly customizable using App.Config 

# Log and Evidence
CSCGuard will attempt to capture the following files and evidence upon execution:
- The Parent Process .EXE which called CSC.EXE
- All C# source files passed as parameters to CSC.EXE
- The compiled binary results (if passed to CSC.EXE)
- Any temporary files in the source folder that appear to be related to the CSC.EXE execution (Runtime Compilation).

Log parent folder is by default set to %USERPROFILE%\CSCGuard\Log\.
Each execution generates an individual log file folder in the following format MM-DD\HH-mm-ss.fffffff\
Example: %USERPROFILE%\CSCGuard\Log\2018\May-03\00-04-15.7864500

# Log Files
CMDLine.txt - Contains the original (or runtime generated) Commandline passed to CSC.EXE
CSCGuard.txt - Contains debug and detailed information of the intercept event and all the information gathered.


# Evidence Files
Additional files collected in this folder are all the evidence files gathered by CSCGuard in order to help analysis:
- Parent Process Binary
- Compiled File Results (If passthru allowed)
- C# source files
- Resource files


# Config File
CSCGuard has a simple App config file that has the following content by default:
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <appSettings>
    <add key="MaxThreatLevel" value="2"></add>
    <add key="OriginalCSC" value="CSCGuard.exe"></add>
    <add key="CreateEventLog" value="true"></add>
  </appSettings>
</configuration>

MaxThreatLevel (Integer) = the max amount of suspicious heuristic details a intercepted event should have before original CSC.exe pass thru is denied.  2 is default.

OriginalCSC (String Filename) = is the name of the Original CSC.EXE that is executed when pass thru is allowed (must be in the same folder as CSCGuard)

CreateEventLog (true or false) = create a Windows Event log when triggered 

# Event Log
A Windows Event Log entry will contain the following output:

CSCGuard Intercept Event: 

<PARENT PROCESS BINARY> Attempted to Execute CSC.EXE with the following parameters: 
<CSC COMMANDLINE>

CSCGuard Log Folder For This Event: <SPECIFIC EVENT CSCGUARD LOG FOLDER>
  
CSCGuard Passed Execution To Original CSC.exe: <TRUE|FALSE>

CSCGuard Heuristic Threat Level: <INTEGER>
  
CSCGuard Detected Runtime Compilation: <TRUE|FALSE>

CSCGuard Parent Process Signed: <TRUE|FALSE>

CSCGuard Parent Process Has Valid Signature: <TRUE|FALSE>

CSCGuard Code Executed From %TEMP% Folder: <TRUE|FALSE>

CSCGuard v0.3 by Greg Linares (@Laughing_Mantis)


# License
Free to use and modify as long as full credit is given in the form of something similar to:
CSCGuard by Greg Linares (@Laughing_Mantis).
