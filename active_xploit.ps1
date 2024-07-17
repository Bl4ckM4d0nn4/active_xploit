#Get the active processes on the local host
#Format output into a table organized by process name
#Output to text file named "native_procs.txt"
Get-Process | Format-Table Name | Out-File -File native_procs.txt

#Sleep for 10 seconds
Start-Sleep -s 10

#Load content of "native_procs.txt" into memory
$native_procs = Get-Content -Path .\native_procs.txt

#List of exploitable processes, DLLs, Et al. according to https://lolbas-project.github.io/lolbas/Binaries/Msedge/
$lolbas = "AddinUtil","AppInstaller","Aspnet_Compiler","At","Atbroker","Bash","Bitsadmin","CertOC","CertReq","Certutil","Cmd","Cmdkey",
          "cmdl32","Cmstp","Colorcpl","ConfigSecurityPolicy","Control","Csc","Cscript","DataSvcUtil","Desktopimgdownldr","DeviceCredentialDeployment",
          "Dfsvc","Diantz","Diskshadow","Dnscmd","Esentutl","Eventvwr","Expand","Explorer","Extexport","Extrac32","Findstr","Finger","fltMC",
          "Forfiles","Fsutil","Ftp","Gpscript","Hh","IMEWDBLD","Ie4uinit","iediagcmd","Ieexec","Ilasm","Infdefaultinstall","Installutil","Jsc",
          "Ldifde","Makecab","Mavinject","Microsoft.Workflow.Compiler","Mmc","MpCmdRun","Msbuild","Msconfig","msedge","Mshta","Msiexec","Netsh",
          "Ngen","Odbcconf","OfflineScannerShell","OneDriveStandaloneUpdater","Pcalua","Pcwrun","Pktmon","Pnputil","Presentationhost","Print",
          "PrintBrm","Provlaunch","Psr","Rasautou","rdrleakdiag","Reg","Regasm","Regedit","Regini","Register-cimprovider","Regsvcs","Regsvr32",
          "Replace","Rpcping","Rundll32","Runexehelper","Runonce","Runscripthelper","Sc","Schtasks","Scriptrunner","Setres","SettingSyncHost",
          "ssh","Stordiag","SyncAppvPublishingServer","Tar","Ttdinject","Tttracer","vbc","Verclsid","Wab","wbadmin","winget","Wlrmdr","Wmic",
          "WorkFolders","Wscript","Wsreset","wuauclt","Xwizard","msedge_proxy","msedgewebview2","wt","Advpack","Desk","Dfshim","Ieadvpack",
          "Ieframe","Mshtml","Pcwutl","Scrobj","Setupapi","Shdocvw","Shell32","Shell32","Shimgvw","Syssetup","Url","Zipfldr","Comsvcs","AccCheckConsole",
          "adplus","AgentExecutor","AppCert","Appvlp","Bginfo","Cdb","coregen","Createdump","csi","DefaultPack","Devtoolslauncher","dnx","Dotnet",
          "dsdbutil","Dump64","DumpMinitool","Dxcap","Excel","Fsi","FsiAnyCpu","Microsoft.NodejsTools.PressAnyKey","MSAccess","Msdeploy","MsoHtmEd",
          "msxsl","ntdsutil","OpenConsole","Powerpnt","Procdump","ProtocolHandler","rcsi","Remote","Sqldumper","Sqlps","SQLToolsPS","Squirrel",
          "te","Teams","TestWindowRemoteAgent","Tracker","Update","VSDiagnostics","VSIISExeLauncher","Visio","VisualUiaVerifyNative","Vshadow",
          "vsjitdebugger","Wfc","WinProj","Winword","Wsl","devtunnel","vsls-agent","vstest.console","winfile","CL_LoadAssembly","CL_Mutexverifiers",
          "CL_Invocation","Launch-VsDevShell","Manage-bde","Pubprn","Syncappvpublishingserver","UtilityFunctions","winrm","Pester"

#For each row in the list of processes 
foreach ($row in $native_procs)
{
    #For each exploitable process in the $lolbas list.
    foreach ($bin in $lolbas)
    {
        #Trim row to strings of names of active process
        #If process name is equal to exploitable process list
        if ($row.Trim() -eq $bin)
        {
            #Write exploitable process to outfile.
            "Exploitable process detected!!!" | Out-File -File active.txt
            $row.Trim() + " is an active process on this host and is exploitable using LOLBAS techniques." >> active.txt
        }
    }
}
