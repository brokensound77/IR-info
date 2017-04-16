@echo off
REM IR Information Gatherer Tool
REM Justin Ibarra
REM MIT License
REM For: UTSA, IS6973, Advanced Digital Forensics
REM Synopsis:
REM     Processed Memory Information Gathering
REM 
REM Dependencies:
REM     psloggedon (sysinternals) (included)
REM     pwdump7                   (included)
REM     listdlls   (sysinternals) (included)
REM     handle	   (sysinternals) (included)
REM     pslist	   (sysinternals) (included)
REM **********************************************
REM
REM 
REM *****************************************************************************************
REM *****************************************************************************************


CLS
ECHO.
ECHO. 
ECHO ************************************************************
ECHO.                                                               
ECHO    _/_/_/  _/_/_/        _/_/_/                _/_/           
ECHO     _/    _/    _/        _/    _/_/_/      _/        _/_/    
ECHO    _/    _/_/_/          _/    _/    _/  _/_/_/_/  _/    _/   
ECHO   _/    _/    _/        _/    _/    _/    _/      _/    _/    
ECHO _/_/_/  _/    _/      _/_/_/  _/    _/    _/        _/_/       
ECHO.                                                               
ECHO.                                                               
ECHO IR Info Gatherer
ECHO ***********************************************************
ECHO.


REM Check to ensure running as admin! Exit if not!
REM **********************************************
NET SESSION >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    ECHO Administrator PRIVILEGES Detected!
    ECHO Script executing...
    ECHO. 
) ELSE (
    ECHO You must run this script from an elevated prompt!"
    PAUSE
    EXIT /B 1
)


REM Create IR Log File
REM *******************
echo IR Log Results > IR_Results.txt

REM **************************************************************
REM The log(s) should provide the following data: 
REM	Location where your VM folders and .vmem files are stored
REM **************************************************************
SET /p locationOfFiles="For record keeping, enter the directory name where any raw memory files are located (i.e. vmem) (leave blank if none): "
REM echo %locationOfFiles%
echo.
echo vmem files located: >> IR_Results.txt
if not "%locationOfFiles%"=="" (
	echo %locationOfFiles% >> IR_Results.txt
) else (
	echo "None specified" >> IR_Results.txt
)echo. >>  IR_Results.txt


REM	Date/time you started and ended your incident response
REM **********************************************************
echo Start time of script: >> IR_Results.txt
date /t >> IR_Results.txt
time /t >> IR_Results.txt
echo Completion time of script will be at the bottom of the report >> IR_Results.txt
echo ************************************************************* >> IR_Results.txt
echo. >> IR_Results.txt


echo Report created, gathering system information...
echo.


REM ************************************************************************************************************
REM	IP address, MAC address, basic network settings, hostname, OS version, DNS server, default gateway, etc.
REM ************************************************************************************************************
REM	Network adapter mode
REM ************************

echo *****ipconfig /all >> IR_Results.txt
ipconfig /all >> IR_Results.txt
echo. >> IR_Results.txt

echo *****hostname >> IR_Results.txt
hostname >> IR_Results.txt
echo. >> IR_Results.txt


REM ************************************************************************************************************
REM	Routing table
REM *****************
echo *****route print >> IR_Results.txt
route print >> IR_Results.txt
echo. >> IR_Results.txt


REM ************************************************************************************************************
REM	DNS queries
REM ***************
echo *****ipconfig /diplaydns >> IR_Results.txt
ipconfig /displaydns >> IR_Results.txt
echo. >> IR_Results.txt


REM ************************************************************************************************************
REM	ARP cache
REM *************
echo *****arp - a >> IR_Results.txt
arp -a >> IR_Results.txt
echo. >> IR_Results.txt


REM ************************************************************************************************************
REM	Netbios info (cached and current sessions)
REM **********************************************
echo *****nbtstat -c >> IR_Results.txt
nbtstat -c >> IR_Results.txt
echo. >> IR_Results.txt
echo *****nbtstat -S >> IR_Results.txt
nbtstat -S >> IR_Results.txt
echo. >> IR_Results.txt


REM ************************************************************************************************************
REM	Currently logged in users
REM *****************************
REM ** REQUIRES psloggedon!! **
REM ***************************
echo *****psloggedon -l >> IR_Results.txt 
tools\psloggedon /accepteula -l >> IR_Results.txt 2>NUL
echo. >> IR_Results.txt


REM ************************************************************************************************************
REM	User account info
REM *********************
echo *****net user >> IR_Results.txt
net user >> IR_Results.txt
echo. >> IR_Results.txt


REM ************************************************************************************************************
REM	Windows update status
REM *************************
echo *****wmic qfe list >> IR_Results.txt
wmic qfe list >> IR_Results.txt
echo. >> IR_Results.txt
 

REM ************************************************************************************************************
REM	System uptime
REM *****************
echo *****systeminfo >> IR_Results.txt
systeminfo >> IR_Results.txt
echo. >> IR_Results.txt


REM ************************************************************************************************************
REM	Port info – listening & connected
REM *************************************
echo *****netstat -nat >> IR_Results.txt
netstat -a >> IR_Results.txt
echo. >> IR_Results.txt


REM ************************************************************************************************************
REM	Active network connections with IP address (for connections) and PID info
REM *****************************************************************************
echo *****netstat -ano >> IR_Results.txt
netstat -ano >> IR_Results.txt
echo. >> IR_Results.txt


REM ************************************************************************************************************
REM	Running processes/services info (process/service name, PID, 
REM ***************************************************************
echo *****tasklist >> IR_Results.txt
tasklist >> IR_Results.txt
echo. >> IR_Results.txt


REM ************************************************************************************************************
REM 					Loop Through suspiscuious processes
REM ************************************************************************************************************

echo Refer to the end of IR_Results.txt to identify suspicious processes. Make note of the PIDs for for further processing.
echo.
set /p xyz="Hit enter to view partial report results...(CLOSE REPORT TO PROCEED WITH SCRIPT AFTER!)"
notepad IR_Results.txt
echo.
set /p list="Enter PIDs of suspicious processes which require further interrogation (seperated by a single space): "  
(for %%a in (%list%) do ( 
   echo Details for %%a below: >> IR_Results.txt
   echo ********************** >> IR_Results.txt
   echo. >> IR_Results.txt


	REM ************************************************************************************************************
	REM	For any suspicious processes/services provide path/filename of executables that launched services, 
	REM       process dependencies, process-to-user correlation where applicable, process command line info 
	REM       where applicable
	REM ******************************************************************************************************
	echo 	*****pslist %%a >> IR_Results.txt
	tools\pslist %%a /accepteula >> IR_Results.txt 2>NUL
	echo. >> IR_Results.txt

	echo *****listdlls %%a >> IR_Results.txt
	tools\listdlls %%a /accepteula >> IR_Results.txt 2>NUL
	echo. >> IR_Results.txt

	REM ************************************************************************************************************
	REM	Open file handles, files opened locally, files opened remotely.
	REM *******************************************************************
	echo 	*****handle %%a >> IR_Results.txt
	tools\handle %%a /accepteula >> IR_Results.txt 2>NUL
	echo. >> IR_Results.txt


))
REM ************************************************************************************************************
REM 							 End looping
REM ************************************************************************************************************


REM ************************************************************************************************************
REM	Command history
REM *******************
echo *****doskey /history >> IR_Results.txt
doskey /history >> IR_Results.txt
echo. >> IR_Results.txt


REM ************************************************************************************************************
REM	Network shares configured
REM *****************************
echo *****net share >> IR_Results.txt
net share >> IR_Results.txt
echo. >> IR_Results.txt


REM ************************************************************************************************************
REM	Scheduled tasks
REM *******************
echo *****schtasks >> IR_Results.txt
schtasks >> IR_Results.txt
echo. >> IR_Results.txt


REM ************************************************************************************************************
REM	Password hashes of configured accounts
REM ******************************************
REM REQUIRES pwdump7 (located with this script)!! **
REM ************************************************
echo *****pwdump7\pwdump7 >> IR_Results.txt
tools\pwdump7\pwdump7 >> IR_Results.txt 2>NUL
echo. >> IR_Results.txt


REM ************************************************************************************************************
REM	Date/time ended incident response
REM *************************************
echo End time of script: >> IR_Results.txt
date /t >> IR_Results.txt
time /t >> IR_Results.txt
echo END OF REPORT >> IR_Results.txt


REM ************************************************************************************************************
echo.
echo REPORT GENERATED AND SAVED AS "IR_Results.txt"
echo.
echo SHA1 HASH OF REPORT:
echo.
tools\fciv -sha1 IR_Results.txt > report_hash.txt
tools\fciv -sha1 IR_results.txt
echo.
echo HASH STORED IN "report_hash.txt"
