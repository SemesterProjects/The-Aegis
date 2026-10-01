
# Aegis Core Real-Run Monitoring Report (Historical Evidence)

> [!NOTE]
> **HISTORICAL EVIDENCE:** This document contains machine-generated observation evidence and forensic output captured during a 14.7-second physical host validation run (Run ID: `91a5928bb12d44788e5d8473f082fda0`) on Windows 10 on 2026-09-27. It provides empirical validation that process, network, file, and health collectors operated concurrently with valid cryptographic hash chain verification.

+========================================================================+
|                  AEGIS CORE - MONITORING SESSION REPORT                |
+========================================================================+

  Run ID         : 91a5928bb12d44788e5d8473f082fda0
  Hostname       : Visha-PC
  Host ID        : 5aa198b75215785ec0ebd097
  OS             : Windows 10 (10.0.26200)
  Session start  : 2026-09-27 07:14:12 UTC
  Session end    : 2026-09-27 07:14:27 UTC
  Duration       : 14.7 seconds
  Evidence scope : events observed at or after 2026-09-27T07:14:12.832790+00:00
  Hash chain     : [OK] VALID
  Collectors     : process_lifecycle, file_events, network_bridge, auth_events

  Monitored paths:
    [+]  C:\Users\Visha\AppData\Local\Temp\aegis-final-watch-_wqur29_

  +----------------------+---------------+
  |   EVENT SUMMARY      |              |
  +----------------------+---------------+
  |   Kind               |  Count       |
  +----------------------+---------------+
  |  Process            |  319         |
  |  Network            |  268         |
  |  File               |  6           |
  |  Authentication     |  0           |
  |  Health             |  3           |
  +----------------------+---------------+
  |  TOTAL              |  596         |
  +----------------------+---------------+
  |  Findings           |  0           |
  +----------------------+---------------+


============================== CAPABILITY REPORT ===============================
  OS: Windows 10
  Elevated: False
  Dependencies/features: etw_capability_probe, file_polling, powershell, process_snapshot, psutil, sqlite_store
  Host limitations: ETW consumption requires a dedicated, signed Windows implementation
  Collector status is reported in HEALTH evidence; unavailable sensors are not treated as zero telemetry.

============================== TELEMETRY SUMMARY ===============================
  Counts are scoped to this run. No rows are hidden unless --max-rows is supplied.
  KIND                TOTAL       DISPLAYED   FIRST OBSERVED             LAST OBSERVED              SOURCES / MECHANISMS                                        
  ------------------  ----------  ----------  -------------------------  -------------------------  ------------------------------------------------------------
  process             319         319         2026-09-27T07:14:24.3487>  2026-09-27T07:14:25.6720>  process_lifecycle / psutil                                  
  network             268         268         2026-09-27T07:14:25.7122>  2026-09-27T07:14:26.7865>  network_bridge / network_monitor_adapter                    
  file                6           6           2026-09-27T07:14:25.6766>  2026-09-27T07:14:25.6960>  file_events / watchdog                                      
  authentication      0           0           -                          -                          -                                                           
  health              3           3           2026-09-27T07:14:12.8327>  2026-09-27T07:14:27.4862>  engine / direct                                             


========================= PROCESS EVENTS  (319 events) =========================
  TIME      ACTION     PID     NAME                  USER            STARTED              STATUS    EXE / CMDLINE                           
  --------  ---------  ------  --------------------  --------------  -------------------  --------  ----------------------------------------
  07:14:24  snapshot   0       System Idle Process   NT AUTHORITY\>  -                    running   -                                       
  07:14:24  snapshot   4       System                NT AUTHORITY\>  -                    running   -                                       
  07:14:24  snapshot   92      -                     -               2026-09-22 13:02:30  stopped   -                                       
  07:14:24  snapshot   136     Registry              -               2026-09-22 13:02:30  running   Registry                                
  07:14:24  snapshot   564     svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   584     smss.exe              -               2026-09-22 13:02:34  running   C:\Windows\System32\smss.exe            
  07:14:24  snapshot   776     wininit.exe           -               2026-09-22 13:02:42  running   C:\Windows\System32\wininit.exe         
  07:14:24  snapshot   792     svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   992     csrss.exe             -               2026-09-22 13:02:42  running   C:\Windows\System32\csrss.exe           
  07:14:24  snapshot   1100    services.exe          -               2026-09-22 13:02:44  running   C:\Windows\System32\services.exe        
  07:14:24  snapshot   1144    LsaIso.exe            -               2026-09-22 13:02:44  running   C:\Windows\System32\LsaIso.exe          
  07:14:24  snapshot   1152    lsass.exe             -               2026-09-22 13:02:44  running   C:\Windows\System32\lsass.exe           
  07:14:24  snapshot   1284    svchost.exe           -               2026-09-22 13:02:44  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   1316    WUDFHost.exe          -               2026-09-22 13:02:44  running   C:\Windows\System32\WUDFHost.exe        
  07:14:24  snapshot   1336    fontdrvhost.exe       -               2026-09-22 13:02:44  running   C:\Windows\System32\fontdrvhost.exe     
  07:14:24  snapshot   1460    svchost.exe           -               2026-09-22 13:02:44  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   1516    svchost.exe           -               2026-09-22 13:02:44  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   1660    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   1752    PresentMonService.e>  -               2026-09-22 13:02:55  running   C:\Program Files\WindowsApps\AppUp.Inte>
  07:14:24  snapshot   1764    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   1776    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   1852    svchost.exe           -               2026-09-23 04:44:35  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   1860    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   1880    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   1900    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   1908    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   1968    conhost.exe           VISHA-PC\Visha  2026-09-27 05:45:46  running   \??\C:\WINDOWS\system32\conhost.exe 0x4 
  07:14:24  snapshot   1988    conhost.exe           VISHA-PC\Visha  2026-09-25 06:15:51  running   \??\C:\WINDOWS\system32\conhost.exe 0x4 
  07:14:24  snapshot   2036    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   2056    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   2104    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   2176    IntelCpHDCPSvc.exe    -               2026-09-22 13:02:45  running   C:\Windows\System32\DriverStore\FileRep>
  07:14:24  snapshot   2220    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   2284    RuntimeBroker.exe     VISHA-PC\Visha  2026-09-27 05:44:30  running   C:\Windows\System32\RuntimeBroker.exe ->
  07:14:24  snapshot   2296    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   2360    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   2380    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   2408    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   2424    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   2444    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   2456    chrome.exe            VISHA-PC\Visha  2026-09-27 06:59:12  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:24  snapshot   2476    cmd.exe               VISHA-PC\Visha  2026-09-27 05:44:38  running   C:\WINDOWS\System32\cmd.exe             
  07:14:24  snapshot   2488    mscopilot_proxy.exe   VISHA-PC\Visha  2026-09-25 14:21:21  running   C:\Program Files (x86)\Microsoft\Copilo>
  07:14:24  snapshot   2560    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   2600    msedge.exe            VISHA-PC\Visha  2026-09-24 04:48:31  running   C:\Program Files (x86)\Microsoft\Edge\A>
  07:14:24  snapshot   2768    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   2808    svchost.exe           -               2026-09-22 13:02:56  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   2840    OpenConsole.exe       VISHA-PC\Visha  2026-09-27 06:17:44  running   c:\Users\Visha\AppData\Local\Programs\M>
  07:14:24  snapshot   2852    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   2892    RuntimeBroker.exe     VISHA-PC\Visha  2026-09-24 04:47:21  running   C:\Windows\System32\RuntimeBroker.exe ->
  07:14:24  snapshot   3032    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   3040    igfxCUIServiceN.exe   -               2026-09-22 13:02:45  running   C:\Windows\System32\DriverStore\FileRep>
  07:14:24  snapshot   3148    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   3160    svchost.exe           -               2026-09-22 13:02:45  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   3316    svchost.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   3360    svchost.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   3372    conhost.exe           -               2026-09-22 13:06:23  running   C:\Windows\System32\conhost.exe         
  07:14:24  snapshot   3416    vmms.exe              -               2026-09-22 13:02:46  running   C:\Windows\System32\vmms.exe            
  07:14:24  snapshot   3444    unsecapp.exe          VISHA-PC\Visha  2026-09-24 04:48:38  running   C:\WINDOWS\system32\wbem\unsecapp.exe ->
  07:14:24  snapshot   3480    svchost.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   3520    gamingservices.exe    -               2026-09-22 13:28:04  running   C:\Program Files\WindowsApps\Microsoft.>
  07:14:24  snapshot   3528    svchost.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   3568    svchost.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   3576    svchost.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   3600    svchost.exe           -               2026-09-23 04:44:51  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   3640    svchost.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   3648    svchost.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   3680    MemCompression        -               2026-09-22 13:02:46  running   MemCompression                          
  07:14:24  snapshot   3720    svchost.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   3764    Antigravity.exe       VISHA-PC\Visha  2026-09-25 06:16:03  running   C:\Users\Visha\AppData\Local\Programs\A>
  07:14:24  snapshot   3808    Dell.Connected.Serv>  -               2026-09-22 13:08:16  running   C:\Program Files\Dell\Dell Connected Se>
  07:14:24  snapshot   3816    svchost.exe           VISHA-PC\Visha  2026-09-24 04:47:16  running   C:\WINDOWS\system32\svchost.exe -k UdkS>
  07:14:24  snapshot   3820    svchost.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   3832    svchost.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   3844    svchost.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   3884    Dell.Update.SubAgen>  -               2026-09-22 13:06:23  running   C:\Program Files (x86)\Dell\UpdateServi>
  07:14:24  snapshot   3892    conhost.exe           -               2026-09-22 13:06:23  running   C:\Windows\System32\conhost.exe         
  07:14:24  snapshot   3904    svchost.exe           VISHA-PC\Visha  2026-09-24 04:47:14  running   C:\WINDOWS\system32\svchost.exe -k Clip>
  07:14:24  snapshot   3932    svchost.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   4020    svchost.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   4172    Dell.D3.WinSvc.exe    -               2026-09-22 13:06:15  running   C:\Program Files (x86)\Dell Digital Del>
  07:14:24  snapshot   4188    svchost.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   4268    svchost.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   4344    Dell.UCA.Manager.exe  -               2026-09-22 13:06:23  running   C:\Program Files\Dell\MyDell\Manager\De>
  07:14:24  snapshot   4356    spoolsv.exe           -               2026-09-22 13:02:46  running   C:\Windows\System32\spoolsv.exe         
  07:14:24  snapshot   4448    svchost.exe           -               2026-09-22 13:02:47  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   4480    vmcompute.exe         -               2026-09-22 13:02:47  running   C:\Windows\System32\vmcompute.exe       
  07:14:24  snapshot   4516    svchost.exe           -               2026-09-22 13:02:47  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   4532    svchost.exe           -               2026-09-22 13:02:47  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   4548    svchost.exe           -               2026-09-22 13:02:47  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   4556    Dell.TechHub.exe      -               2026-09-22 13:02:47  running   C:\Program Files\Dell\TechHub\Dell.Tech>
  07:14:24  snapshot   4576    svchost.exe           -               2026-09-22 13:29:07  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   4592    esif_uf.exe           -               2026-09-22 13:02:47  running   C:\Windows\System32\DriverStore\FileRep>
  07:14:24  snapshot   4612    chrome.exe            VISHA-PC\Visha  2026-09-24 04:53:09  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:24  snapshot   4620    WidgetBoard.exe       VISHA-PC\Visha  2026-09-24 04:47:16  running   C:\Program Files\WindowsApps\MicrosoftW>
  07:14:24  snapshot   4716    IntelAudioService.e>  -               2026-09-22 13:02:47  running   C:\Windows\System32\DriverStore\FileRep>
  07:14:24  snapshot   4740    svchost.exe           -               2026-09-22 13:02:47  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   4760    jhi_service.exe       -               2026-09-22 13:02:47  running   C:\Windows\System32\DriverStore\FileRep>
  07:14:24  snapshot   4900    MpDefenderCoreServi>  -               2026-09-22 13:02:47  running   C:\ProgramData\Microsoft\Windows Defend>
  07:14:24  snapshot   4916    svchost.exe           -               2026-09-22 13:02:47  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   4940    RtkAudUService64.exe  -               2026-09-22 13:02:47  running   C:\Windows\System32\DriverStore\FileRep>
  07:14:24  snapshot   4956    RtkBtManServ.exe      -               2026-09-22 13:02:47  running   C:\Windows\System32\DriverStore\FileRep>
  07:14:24  snapshot   5004    SmartByteAnalyticsS>  -               2026-09-22 13:02:47  running   C:\Program Files\Rivet Networks\SmartBy>
  07:14:24  snapshot   5024    svchost.exe           -               2026-09-22 13:02:47  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   5032    svchost.exe           -               2026-09-22 13:02:47  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   5040    Code.exe              VISHA-PC\Visha  2026-09-25 14:21:22  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:24  snapshot   5100    SmartByteNetworkSer>  -               2026-09-22 13:02:47  running   C:\Program Files\Rivet Networks\SmartBy>
  07:14:24  snapshot   5144    WavesAudioService.e>  -               2026-09-22 13:02:47  running   C:\Windows\System32\DriverStore\FileRep>
  07:14:24  snapshot   5188    svchost.exe           -               2026-09-22 13:02:47  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   5240    MsMpEng.exe           -               2026-09-22 13:02:47  running   C:\ProgramData\Microsoft\Windows Defend>
  07:14:24  snapshot   5264    conhost.exe           -               2026-09-22 13:02:55  running   C:\Windows\System32\conhost.exe         
  07:14:24  snapshot   5280    WMIRegistrationServ>  -               2026-09-22 13:02:47  running   C:\Windows\System32\DriverStore\FileRep>
  07:14:24  snapshot   5308    svchost.exe           -               2026-09-22 13:02:47  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   5332    WavesSysSvc64.exe     -               2026-09-22 13:02:47  running   C:\Windows\System32\DriverStore\FileRep>
  07:14:24  snapshot   5404    RuntimeBroker.exe     VISHA-PC\Visha  2026-09-24 04:47:16  running   C:\Windows\System32\RuntimeBroker.exe ->
  07:14:24  snapshot   5456    gamingservicesnet.e>  -               2026-09-22 13:28:04  running   C:\Program Files\WindowsApps\Microsoft.>
  07:14:24  snapshot   5520    wslservice.exe        -               2026-09-22 13:02:47  running   C:\Program Files\WSL\wslservice.exe     
  07:14:24  snapshot   5568    conhost.exe           -               2026-09-22 13:06:23  running   C:\Windows\System32\conhost.exe         
  07:14:24  snapshot   5628    Dell.Connected.Serv>  -               2026-09-22 13:06:23  running   C:\Program Files\Dell\Dell Connected Se>
  07:14:24  snapshot   5696    conhost.exe           VISHA-PC\Visha  2026-09-25 14:23:44  running   \??\C:\WINDOWS\system32\conhost.exe 0x4 
  07:14:24  snapshot   5844    SecurityHealthServi>  -               2026-09-22 13:03:31  running   C:\Windows\System32\SecurityHealthServi>
  07:14:24  snapshot   5980    svchost.exe           -               2026-09-22 13:02:47  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   6112    igfxEMN.exe           VISHA-PC\Visha  2026-09-24 04:47:11  running   C:\WINDOWS\System32\DriverStore\FileRep>
  07:14:24  snapshot   6260    RAPSService.exe       -               2026-09-22 13:02:48  running   C:\Program Files\Rivet Networks\SmartBy>
  07:14:24  snapshot   6404    AggregatorHost.exe    -               2026-09-22 13:02:48  running   C:\Windows\System32\AggregatorHost.exe  
  07:14:24  snapshot   6468    Code.exe              VISHA-PC\Visha  2026-09-25 14:21:29  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:24  snapshot   6504    svchost.exe           -               2026-09-22 13:28:08  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   6604    RAPS.exe              -               2026-09-22 13:02:48  running   C:\Program Files\Rivet Networks\SmartBy>
  07:14:24  snapshot   6632    conhost.exe           -               2026-09-22 13:02:48  running   C:\Windows\System32\conhost.exe         
  07:14:24  snapshot   6636    taskhostw.exe         VISHA-PC\Visha  2026-09-24 04:47:11  running   taskhostw.exe {222A245B-E637-4AE9-A93F->
  07:14:24  snapshot   6724    conhost.exe           VISHA-PC\Visha  2026-09-26 05:37:56  running   \??\C:\WINDOWS\system32\conhost.exe 0x4 
  07:14:24  snapshot   6728    msedgewebview2.exe    VISHA-PC\Visha  2026-09-24 04:47:20  running   C:\Program Files (x86)\Microsoft\EdgeWe>
  07:14:24  snapshot   6764    WidgetService.exe     VISHA-PC\Visha  2026-09-24 04:47:17  running   C:\Program Files\WindowsApps\Microsoft.>
  07:14:24  snapshot   6884    chrome.exe            VISHA-PC\Visha  2026-09-24 04:48:45  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:24  snapshot   7012    conhost.exe           -               2026-09-22 13:06:23  running   C:\Windows\System32\conhost.exe         
  07:14:24  snapshot   7112    svchost.exe           -               2026-09-22 13:02:52  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   7324    Code.exe              VISHA-PC\Visha  2026-09-25 14:21:22  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:24  snapshot   7336    ServiceShell.exe      -               2026-09-22 13:06:15  running   C:\Program Files (x86)\Dell\UpdateServi>
  07:14:24  snapshot   7356    svchost.exe           -               2026-09-22 13:02:51  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   7500    Code.exe              VISHA-PC\Visha  2026-09-27 05:45:49  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:24  snapshot   7512    IntelGraphicsSoftwa>  -               2026-09-22 13:02:51  running   C:\Program Files\WindowsApps\AppUp.Inte>
  07:14:24  snapshot   7684    svchost.exe           -               2026-09-22 13:02:51  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   7844    Dell.TechHub.Analyt>  -               2026-09-22 13:06:23  running   C:\Program Files\Dell\DTP\AnalyticsSubA>
  07:14:24  snapshot   7964    svchost.exe           -               2026-09-22 13:05:31  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   8016    conhost.exe           -               2026-09-22 13:06:23  running   C:\Windows\System32\conhost.exe         
  07:14:24  snapshot   8048    svchost.exe           -               2026-09-22 13:02:51  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   8340    WavesSvc64.exe        VISHA-PC\Visha  2026-09-24 04:48:36  running   C:\Windows\System32\DriverStore\FileRep>
  07:14:24  snapshot   8352    svchost.exe           -               2026-09-22 13:02:54  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   8472    svchost.exe           -               2026-09-22 13:02:55  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   8488    conhost.exe           VISHA-PC\Visha  2026-09-25 15:59:58  running   \??\C:\WINDOWS\system32\conhost.exe 0x4 
  07:14:24  snapshot   8708    msedge.exe            VISHA-PC\Visha  2026-09-24 04:48:29  running   C:\Program Files (x86)\Microsoft\Edge\A>
  07:14:24  snapshot   8928    sihost.exe            VISHA-PC\Visha  2026-09-24 04:47:11  running   sihost.exe                              
  07:14:24  snapshot   8964    codex-windows-sandb>  -               2026-09-26 06:43:15  running   C:\Program Files\WindowsApps\OpenAI.Cod>
  07:14:24  snapshot   9060    svchost.exe           -               2026-09-22 13:02:52  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   9128    svchost.exe           -               2026-09-22 13:02:52  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   9156    csrss.exe             -               2026-09-23 19:02:53  running   C:\Windows\System32\csrss.exe           
  07:14:24  snapshot   9180    OneDrive.Sync.Servi>  VISHA-PC\Visha  2026-09-24 14:51:52  running   /silentConfig                           
  07:14:24  snapshot   9236    CodeSetup-stable-04>  VISHA-PC\Visha  2026-09-25 14:23:01  running   C:\Users\Visha\AppData\Local\Temp\is-7N>
  07:14:24  snapshot   9396    svchost.exe           -               2026-09-22 13:02:53  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   9436    NgcIso.exe            -               2026-09-22 13:02:53  running   C:\Windows\System32\NgcIso.exe          
  07:14:24  snapshot   9540    chrome.exe            VISHA-PC\Visha  2026-09-24 04:48:45  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:24  snapshot   9692    svchost.exe           -               2026-09-22 13:02:55  running   C:\Windows\System32\svchost.exe         
  07:14:24  snapshot   9760    msedge.exe            VISHA-PC\Visha  2026-09-25 06:55:53  running   C:\Program Files (x86)\Microsoft\Edge\A>
  07:14:24  snapshot   9768    ctfmon.exe            VISHA-PC\Visha  2026-09-24 04:47:19  running   /QuitInfo:000000000000038C;000000000000>
  07:14:24  snapshot   9852    msedge.exe            VISHA-PC\Visha  2026-09-24 04:48:32  running   C:\Program Files (x86)\Microsoft\Edge\A>
  07:14:24  snapshot   9904    msedge.exe            VISHA-PC\Visha  2026-09-24 04:48:29  running   C:\Program Files (x86)\Microsoft\Edge\A>
  07:14:24  snapshot   10044   winlogon.exe          -               2026-09-23 19:02:53  running   C:\Windows\System32\winlogon.exe        
  07:14:24  snapshot   10148   Dell.TechHub.DataMa>  -               2026-09-22 13:06:23  running   C:\Program Files\Dell\DTP\DataManagerSu>
  07:14:24  snapshot   10332   Antigravity.exe       VISHA-PC\Visha  2026-09-25 06:15:49  running   C:\Users\Visha\AppData\Local\Programs\A>
  07:14:24  snapshot   10596   SearchHost.exe        VISHA-PC\Visha  2026-09-24 04:47:15  running   C:\WINDOWS\SystemApps\MicrosoftWindows.>
  07:14:24  snapshot   10668   chrome.exe            VISHA-PC\Visha  2026-09-24 04:48:45  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:24  snapshot   10708   msedgewebview2.exe    VISHA-PC\Visha  2026-09-24 04:47:19  running   C:\Program Files (x86)\Microsoft\EdgeWe>
  07:14:24  snapshot   10736   conhost.exe           -               2026-09-22 13:06:23  running   C:\Windows\System32\conhost.exe         
  07:14:24  snapshot   10808   Dell.TechHub.Instru>  -               2026-09-22 13:06:23  running   C:\Program Files\Dell\DTP\Instrumentati>
  07:14:24  snapshot   10888   svchost.exe           VISHA-PC\Visha  2026-09-24 05:06:16  running   C:\WINDOWS\system32\svchost.exe -k Devi>
  07:14:24  snapshot   10936   msedge.exe            VISHA-PC\Visha  2026-09-24 04:48:30  running   C:\Program Files (x86)\Microsoft\Edge\A>
  07:14:24  snapshot   10952   WmiPrvSE.exe          -               2026-09-22 13:03:34  running   C:\Windows\System32\wbem\WmiPrvSE.exe   
  07:14:25  snapshot   10968   taskhostw.exe         VISHA-PC\Visha  2026-09-27 05:27:54  running   taskhostw.exe                           
  07:14:25  snapshot   10996   Dell.CoreServices.C>  -               2026-09-22 13:06:23  running   C:\Program Files\Dell\TechHub\Dell.Core>
  07:14:25  snapshot   11012   OpenConsole.exe       VISHA-PC\Visha  2026-09-27 05:45:51  running   c:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   11060   SearchIndexer.exe     -               2026-09-22 13:02:58  running   C:\Windows\System32\SearchIndexer.exe   
  07:14:25  snapshot   11180   FileSyncHelper.exe    -               2026-09-22 14:41:40  running   C:\Program Files\Microsoft OneDrive\26.>
  07:14:25  snapshot   11312   GameInputSvc.exe      -               2026-09-22 13:28:32  running   C:\Windows\System32\GameInputSvc.exe    
  07:14:25  snapshot   11364   cpptools.exe          VISHA-PC\Visha  2026-09-25 16:00:10  stopped   c:\Users\Visha\.vscode\extensions\ms-vs>
  07:14:25  snapshot   11420   msedge.exe            VISHA-PC\Visha  2026-09-24 04:48:29  running   C:\Program Files (x86)\Microsoft\Edge\A>
  07:14:25  snapshot   11476   msedge.exe            VISHA-PC\Visha  2026-09-24 04:48:28  running   C:\Program Files (x86)\Microsoft\Edge\A>
  07:14:25  snapshot   11496   Code.exe              VISHA-PC\Visha  2026-09-27 05:44:35  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   11508   Antigravity.exe       VISHA-PC\Visha  2026-09-25 06:15:52  running   C:\Users\Visha\AppData\Local\Programs\A>
  07:14:25  snapshot   11608   svchost.exe           -               2026-09-22 13:05:32  running   C:\Windows\System32\svchost.exe         
  07:14:25  snapshot   11832   StartMenuExperience>  VISHA-PC\Visha  2026-09-24 04:47:15  running   C:\Windows\SystemApps\Microsoft.Windows>
  07:14:25  snapshot   11840   chrome.exe            VISHA-PC\Visha  2026-09-27 04:54:00  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:25  snapshot   12064   backgroundTaskHost.>  VISHA-PC\Visha  2026-09-27 05:44:29  running   C:\WINDOWS\system32\backgroundTaskHost.>
  07:14:25  snapshot   12148   fontdrvhost.exe       -               2026-09-23 19:02:54  running   C:\Windows\System32\fontdrvhost.exe     
  07:14:25  snapshot   12272   chrome.exe            VISHA-PC\Visha  2026-09-24 04:48:45  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:25  snapshot   12304   chrome.exe            VISHA-PC\Visha  2026-09-27 03:26:35  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:25  snapshot   12316   svchost.exe           -               2026-09-22 13:03:03  running   C:\Windows\System32\svchost.exe         
  07:14:25  snapshot   12320   TextInputHost.exe     VISHA-PC\Visha  2026-09-24 04:47:25  running   C:\WINDOWS\SystemApps\MicrosoftWindows.>
  07:14:25  snapshot   12348   conhost.exe           -               2026-09-22 13:06:23  running   C:\Windows\System32\conhost.exe         
  07:14:25  snapshot   12480   Dell.TechHub.Diagno>  -               2026-09-22 13:06:23  running   C:\Program Files\Dell\DTP\DiagnosticsSu>
  07:14:25  snapshot   12576   svchost.exe           -               2026-09-22 13:03:01  running   C:\Windows\System32\svchost.exe         
  07:14:25  snapshot   12868   svchost.exe           VISHA-PC\Visha  2026-09-24 04:50:27  running   C:\WINDOWS\System32\svchost.exe -k Unis>
  07:14:25  snapshot   12896   msedge.exe            VISHA-PC\Visha  2026-09-25 06:59:40  running   C:\Program Files (x86)\Microsoft\Edge\A>
  07:14:25  snapshot   12968   svchost.exe           VISHA-PC\Visha  2026-09-24 04:47:22  running   C:\WINDOWS\system32\svchost.exe -k Loca>
  07:14:25  snapshot   13048   conhost.exe           VISHA-PC\Visha  2026-09-26 05:37:57  running   \??\C:\WINDOWS\system32\conhost.exe 0x4 
  07:14:25  snapshot   13116   msedge.exe            VISHA-PC\Visha  2026-09-24 04:48:29  running   C:\Program Files (x86)\Microsoft\Edge\A>
  07:14:25  snapshot   13164   ShellExperienceHost>  VISHA-PC\Visha  2026-09-24 04:48:35  stopped   C:\WINDOWS\SystemApps\ShellExperienceHo>
  07:14:25  snapshot   13388   dllhost.exe           VISHA-PC\Visha  2026-09-25 14:24:47  running   C:\WINDOWS\system32\DllHost.exe /Proces>
  07:14:25  snapshot   13416   RuntimeBroker.exe     VISHA-PC\Visha  2026-09-24 04:47:28  running   C:\Windows\System32\RuntimeBroker.exe ->
  07:14:25  snapshot   13436   msedge.exe            VISHA-PC\Visha  2026-09-24 04:49:29  running   C:\Program Files (x86)\Microsoft\Edge\A>
  07:14:25  snapshot   13660   GameInputRedistServ>  -               2026-09-22 13:28:35  running   C:\Program Files\Microsoft GameInput\x6>
  07:14:25  snapshot   13780   RuntimeBroker.exe     VISHA-PC\Visha  2026-09-24 04:49:29  running   C:\Windows\System32\RuntimeBroker.exe ->
  07:14:25  snapshot   13904   Code.exe              VISHA-PC\Visha  2026-09-27 05:45:35  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   14096   Dell.TechHub.Instru>  -               2026-09-24 04:47:44  running   C:\Program Files\Dell\DTP\Instrumentati>
  07:14:25  snapshot   14208   chrome.exe            VISHA-PC\Visha  2026-09-27 07:10:23  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:25  snapshot   14248   svchost.exe           -               2026-09-22 13:08:35  running   C:\Windows\System32\svchost.exe         
  07:14:25  snapshot   14400   dllhost.exe           VISHA-PC\Visha  2026-09-27 05:44:32  running   C:\WINDOWS\SysWOW64\DllHost.exe /Proces>
  07:14:25  snapshot   14508   Code.exe              VISHA-PC\Visha  2026-09-27 05:45:06  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   14536   msedge.exe            VISHA-PC\Visha  2026-09-24 04:48:28  running   C:\Program Files (x86)\Microsoft\Edge\A>
  07:14:25  snapshot   14560   SecurityHealthSystr>  VISHA-PC\Visha  2026-09-24 04:47:38  running   C:\Windows\System32\SecurityHealthSystr>
  07:14:25  snapshot   14648   NisSrv.exe            -               2026-09-22 13:03:19  running   C:\ProgramData\Microsoft\Windows Defend>
  07:14:25  snapshot   14712   Code.exe              VISHA-PC\Visha  2026-09-25 14:21:22  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   14932   OpenConsole.exe       VISHA-PC\Visha  2026-09-27 05:44:38  running   c:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   15028   Code.exe              VISHA-PC\Visha  2026-09-27 05:44:35  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   15032   Code.exe              VISHA-PC\Visha  2026-09-25 14:21:28  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   15044   conhost.exe           VISHA-PC\Visha  2026-09-26 05:37:57  running   \??\C:\WINDOWS\system32\conhost.exe 0x4 
  07:14:25  snapshot   15064   node.exe              VISHA-PC\Visha  2026-09-25 14:23:44  running   C:\Users\Visha\AppData\Local\aws\toolki>
  07:14:25  snapshot   15220   python.exe            VISHA-PC\Visha  2026-09-27 07:14:11  running   C:\Program Files\Python311\python.exe C>
  07:14:25  snapshot   15428   chrome.exe            VISHA-PC\Visha  2026-09-24 04:48:47  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:25  snapshot   15528   svchost.exe           -               2026-09-22 13:09:08  running   C:\Windows\System32\svchost.exe         
  07:14:25  snapshot   15672   svchost.exe           VISHA-PC\Visha  2026-09-24 04:47:11  running   C:\WINDOWS\system32\svchost.exe -k Unis>
  07:14:25  snapshot   15712   cpptools-srv.exe      VISHA-PC\Visha  2026-09-26 05:37:57  running   c:\Users\Visha\.vscode\extensions\ms-vs>
  07:14:25  snapshot   15720   msedge.exe            VISHA-PC\Visha  2026-09-24 04:48:28  running   C:\Program Files (x86)\Microsoft\Edge\A>
  07:14:25  snapshot   15904   PhoneExperienceHost>  VISHA-PC\Visha  2026-09-24 04:47:34  running   C:\Program Files\WindowsApps\Microsoft.>
  07:14:25  snapshot   15992   dllhost.exe           VISHA-PC\Visha  2026-09-24 13:46:36  running   C:\WINDOWS\system32\DllHost.exe /Proces>
  07:14:25  snapshot   16080   Code.exe              VISHA-PC\Visha  2026-09-27 05:44:32  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   16128   devsense.php.ls.exe   VISHA-PC\Visha  2026-09-27 05:55:55  running   c:\Users\Visha\.vscode\extensions\devse>
  07:14:25  snapshot   16496   svchost.exe           -               2026-09-22 17:08:33  running   C:\Windows\System32\svchost.exe         
  07:14:25  snapshot   16500   svchost.exe           -               2026-09-22 13:08:22  running   C:\Windows\System32\svchost.exe         
  07:14:25  snapshot   16516   pet.exe               VISHA-PC\Visha  2026-09-27 05:45:46  running   c:\Users\Visha\.vscode\extensions\ms-py>
  07:14:25  snapshot   16660   msedgewebview2.exe    VISHA-PC\Visha  2026-09-24 04:47:19  running   C:\Program Files (x86)\Microsoft\EdgeWe>
  07:14:25  snapshot   16728   codex.exe             VISHA-PC\Visha  2026-09-25 14:23:12  running   c:\Users\Visha\.vscode\extensions\opena>
  07:14:25  snapshot   16968   Antigravity.exe       VISHA-PC\Visha  2026-09-25 06:15:48  running   C:\Users\Visha\AppData\Local\Programs\A>
  07:14:25  snapshot   16996   svchost.exe           -               2026-09-22 13:08:33  running   C:\Windows\System32\svchost.exe         
  07:14:25  snapshot   17000   Antigravity.exe       VISHA-PC\Visha  2026-09-25 06:15:49  running   C:\Users\Visha\AppData\Local\Programs\A>
  07:14:25  snapshot   17060   svchost.exe           VISHA-PC\Visha  2026-09-24 04:47:11  running   C:\WINDOWS\system32\svchost.exe -k Unis>
  07:14:25  snapshot   17300   svchost.exe           -               2026-09-27 07:11:07  running   C:\Windows\System32\svchost.exe         
  07:14:25  snapshot   17420   GameInputRedistServ>  VISHA-PC\Visha  2026-09-24 04:47:14  running   C:\Program Files\Microsoft GameInput\x6>
  07:14:25  snapshot   17428   CodeSetup-stable-04>  VISHA-PC\Visha  2026-09-25 14:23:00  running   C:\Users\Visha\AppData\Local\Temp\vscod>
  07:14:25  snapshot   17612   svchost.exe           VISHA-PC\Visha  2026-09-24 04:47:11  running   C:\WINDOWS\system32\svchost.exe -k BthA>
  07:14:25  snapshot   17852   msedgewebview2.exe    VISHA-PC\Visha  2026-09-24 04:47:18  running   C:\Program Files (x86)\Microsoft\EdgeWe>
  07:14:25  snapshot   17872   cpptools-srv2.exe     VISHA-PC\Visha  2026-09-26 05:37:56  running   c:\Users\Visha\.vscode\extensions\ms-vs>
  07:14:25  snapshot   17980   dllhost.exe           VISHA-PC\Visha  2026-09-24 13:46:36  running   C:\WINDOWS\system32\DllHost.exe /Proces>
  07:14:25  snapshot   18696   SystemSettings.exe    VISHA-PC\Visha  2026-09-25 14:42:08  stopped   C:\Windows\ImmersiveControlPanel\System>
  07:14:25  snapshot   18820   FusionService.exe     -               2026-09-22 13:08:53  running   C:\Program Files\Dell\Fusion\FusionServ>
  07:14:25  snapshot   18868   SupportAssistAgent.>  -               2026-09-22 13:09:08  running   C:\Program Files\Dell\SupportAssistAgen>
  07:14:25  snapshot   18968   svchost.exe           -               2026-09-22 13:09:09  running   C:\Windows\System32\svchost.exe         
  07:14:25  snapshot   19128   svchost.exe           -               2026-09-22 13:08:56  running   C:\Windows\System32\svchost.exe         
  07:14:25  snapshot   19152   MicrosoftStartFeedP>  VISHA-PC\Visha  2026-09-24 04:47:25  running   C:\Program Files\WindowsApps\Microsoft.>
  07:14:25  snapshot   19256   SnippingTool.exe      VISHA-PC\Visha  2026-09-24 13:49:11  running   C:\Program Files\WindowsApps\Microsoft.>
  07:14:25  snapshot   19268   UserOOBEBroker.exe    VISHA-PC\Visha  2026-09-24 05:06:17  running   C:\Windows\System32\oobe\UserOOBEBroker>
  07:14:25  snapshot   19284   Code.exe              VISHA-PC\Visha  2026-09-25 14:21:21  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   19288   msedgewebview2.exe    VISHA-PC\Visha  2026-09-24 04:47:18  running   C:\Program Files (x86)\Microsoft\EdgeWe>
  07:14:25  snapshot   19380   LockApp.exe           VISHA-PC\Visha  2026-09-24 04:47:20  stopped   C:\WINDOWS\SystemApps\Microsoft.LockApp>
  07:14:25  snapshot   19592   chrome.exe            VISHA-PC\Visha  2026-09-27 06:03:43  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:25  snapshot   19680   msedgewebview2.exe    VISHA-PC\Visha  2026-09-24 04:47:19  running   C:\Program Files (x86)\Microsoft\EdgeWe>
  07:14:25  snapshot   19696   cpptools.exe          VISHA-PC\Visha  2026-09-25 15:59:58  running   c:\Users\Visha\.vscode\extensions\ms-vs>
  07:14:25  snapshot   19720   cmd.exe               VISHA-PC\Visha  2026-09-27 05:45:51  running   C:\WINDOWS\System32\cmd.exe             
  07:14:25  snapshot   19724   GameInputSvc.exe      -               2026-09-23 19:02:58  running   C:\Windows\System32\GameInputSvc.exe    
  07:14:25  snapshot   19812   Code.exe              VISHA-PC\Visha  2026-09-25 14:21:26  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   19844   CrossDeviceResume.e>  VISHA-PC\Visha  2026-09-24 04:47:13  running   C:\WINDOWS\SystemApps\MicrosoftWindows.>
  07:14:25  snapshot   19932   dptf_helper.exe       VISHA-PC\Visha  2026-09-24 04:47:11  running   C:\WINDOWS\System32\DriverStore\FileRep>
  07:14:25  snapshot   19976   ApplicationFrameHos>  VISHA-PC\Visha  2026-09-24 05:06:15  running   C:\WINDOWS\system32\ApplicationFrameHos>
  07:14:25  snapshot   20000   chrome.exe            VISHA-PC\Visha  2026-09-24 04:53:09  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:25  snapshot   20524   chrome.exe            VISHA-PC\Visha  2026-09-24 04:48:45  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:25  snapshot   20560   CrossDeviceService.>  VISHA-PC\Visha  2026-09-24 04:47:15  running   C:\Program Files\WindowsApps\MicrosoftW>
  07:14:25  snapshot   20580   RtkAudUService64.exe  -               2026-09-24 04:47:14  running   C:\Windows\System32\DriverStore\FileRep>
  07:14:25  snapshot   20612   OpenConsole.exe       VISHA-PC\Visha  2026-09-25 14:21:31  running   c:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   20664   language_server.exe   VISHA-PC\Visha  2026-09-25 06:15:51  running   C:\Users\Visha\AppData\Local\Programs\A>
  07:14:25  snapshot   20724   msedge.exe            VISHA-PC\Visha  2026-09-24 04:48:28  running   C:\Program Files (x86)\Microsoft\Edge\A>
  07:14:25  snapshot   20928   MSPCManagerService.>  -               2026-09-24 04:47:59  running   C:\Program Files\WindowsApps\Microsoft.>
  07:14:25  snapshot   20948   svchost.exe           VISHA-PC\Visha  2026-09-24 04:47:11  running   C:\WINDOWS\system32\svchost.exe -k Loca>
  07:14:25  snapshot   20972   RuntimeBroker.exe     VISHA-PC\Visha  2026-09-24 04:50:25  running   C:\Windows\System32\RuntimeBroker.exe ->
  07:14:25  snapshot   21048   chrome.exe            VISHA-PC\Visha  2026-09-27 07:13:03  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:25  snapshot   21336   Antigravity.exe       VISHA-PC\Visha  2026-09-25 06:16:03  running   C:\Users\Visha\AppData\Local\Programs\A>
  07:14:25  snapshot   21384   RtkAudUService64.exe  VISHA-PC\Visha  2026-09-24 04:48:08  running   C:\Windows\System32\DriverStore\FileRep>
  07:14:25  snapshot   21648   Notepad.exe           VISHA-PC\Visha  2026-09-26 06:49:21  running   C:\Program Files\WindowsApps\Microsoft.>
  07:14:25  snapshot   21780   RuntimeBroker.exe     VISHA-PC\Visha  2026-09-24 04:48:35  running   C:\Windows\System32\RuntimeBroker.exe ->
  07:14:25  snapshot   21784   dwm.exe               -               2026-09-23 19:02:54  running   C:\Windows\System32\dwm.exe             
  07:14:25  snapshot   22104   explorer.exe          VISHA-PC\Visha  2026-09-24 04:47:12  running   C:\WINDOWS\Explorer.EXE                 
  07:14:25  snapshot   22200   chrome.exe            VISHA-PC\Visha  2026-09-27 05:06:42  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:25  snapshot   22480   msedge.exe            VISHA-PC\Visha  2026-09-25 06:55:53  running   C:\Program Files (x86)\Microsoft\Edge\A>
  07:14:25  snapshot   22604   conhost.exe           VISHA-PC\Visha  2026-09-25 16:00:15  running   \??\C:\WINDOWS\system32\conhost.exe 0x4 
  07:14:25  snapshot   22768   Code.exe              VISHA-PC\Visha  2026-09-25 14:21:26  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   23720   Code.exe              VISHA-PC\Visha  2026-09-27 05:46:08  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   23772   conhost.exe           VISHA-PC\Visha  2026-09-25 14:23:17  running   \??\C:\WINDOWS\system32\conhost.exe 0x4 
  07:14:25  snapshot   23872   codex.exe             VISHA-PC\Visha  2026-09-27 05:45:14  running   c:\Users\Visha\.vscode\extensions\opena>
  07:14:25  snapshot   23896   cpptools-srv.exe      VISHA-PC\Visha  2026-09-25 16:00:15  running   c:\Users\Visha\.vscode\extensions\ms-vs>
  07:14:25  snapshot   24192   Code.exe              VISHA-PC\Visha  2026-09-25 14:21:22  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   24620   chrome.exe            VISHA-PC\Visha  2026-09-27 07:10:23  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:25  snapshot   24940   conhost.exe           VISHA-PC\Visha  2026-09-27 05:46:10  running   \??\C:\WINDOWS\system32\conhost.exe 0x4 
  07:14:25  snapshot   25108   powershell.exe        VISHA-PC\Visha  2026-09-27 06:17:44  running   C:\WINDOWS\System32\WindowsPowerShell\v>
  07:14:25  snapshot   25160   Code.exe              VISHA-PC\Visha  2026-09-25 14:23:28  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   25180   cmd.exe               VISHA-PC\Visha  2026-09-25 14:21:31  running   C:\WINDOWS\System32\cmd.exe             
  07:14:25  snapshot   25304   audiodg.exe           -               2026-09-27 05:34:56  running   C:\WINDOWS\system32\AUDIODG.EXE 0x00000>
  07:14:25  snapshot   25416   Code.exe              VISHA-PC\Visha  2026-09-27 05:45:41  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   25768   cpptools-srv2.exe     VISHA-PC\Visha  2026-09-26 05:37:57  running   c:\Users\Visha\.vscode\extensions\ms-vs>
  07:14:25  snapshot   26040   Code.exe              VISHA-PC\Visha  2026-09-25 14:21:27  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   26048   conhost.exe           VISHA-PC\Visha  2026-09-27 05:45:14  running   \??\C:\WINDOWS\system32\conhost.exe 0x4 
  07:14:25  snapshot   26172   chrome.exe            VISHA-PC\Visha  2026-09-27 07:13:12  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:25  snapshot   26348   Code.exe              VISHA-PC\Visha  2026-09-25 14:21:25  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   26412   msedge.exe            VISHA-PC\Visha  2026-09-27 07:13:07  running   C:\Program Files (x86)\Microsoft\Edge\A>
  07:14:25  snapshot   26804   svchost.exe           -               2026-09-27 07:11:04  running   C:\Windows\System32\svchost.exe         
  07:14:25  snapshot   26860   svchost.exe           -               2026-09-27 04:48:45  running   C:\Windows\System32\svchost.exe         
  07:14:25  snapshot   27180   chrome.exe            VISHA-PC\Visha  2026-09-27 06:57:52  running   C:\Program Files\Google\Chrome\Applicat>
  07:14:25  snapshot   27248   Code.exe              VISHA-PC\Visha  2026-09-27 05:44:36  running   C:\Users\Visha\AppData\Local\Programs\M>
  07:14:25  snapshot   27808   python.exe            VISHA-PC\Visha  2026-09-27 07:14:11  running   C:\Program Files\Python311\python.exe C>
  07:14:25  snapshot   28244   conhost.exe           VISHA-PC\Visha  2026-09-27 05:56:00  running   \??\C:\WINDOWS\system32\conhost.exe 0x4 
  07:14:25  snapshot   28512   node.exe              VISHA-PC\Visha  2026-09-27 05:46:10  running   C:\Users\Visha\AppData\Local\aws\toolki>
  07:14:25  snapshot   29312   ShellHost.exe         VISHA-PC\Visha  2026-09-27 04:52:20  running   C:\Windows\System32\ShellHost.exe       


========================= NETWORK EVENTS  (268 events) =========================
  TIME      ACTION                PROTOCOL   LOCAL ADDR             REMOTE ADDR      REMOTE GEO / ISP                PROCESS             DIRECTION  
  --------  --------------------  ---------  ---------------------  ---------------  ------------------------------  ------------------  -----------
  07:14:25  connection_snapshot   udp        fe80::adef:29b5:abe3>  *:*              -                               svchost.exe         unknown    
  07:14:25  process_network_act>  udp        fe80::adef:29b5:abe3>  *:*              -                               svchost.exe         -          
  07:14:25  connection_snapshot   tcp        192.168.0.103:63697    34.149.212.60:>  Kansas City, United States (G>  Code.exe            outbound   
  07:14:25  process_network_act>  tcp        192.168.0.103:63697    34.149.212.60:>  Kansas City, United States (G>  Code.exe            -          
  07:14:25  connection_snapshot   udp        0.0.0.0:52644          *:*              -                               svchost.exe         unknown    
  07:14:25  process_network_act>  udp        0.0.0.0:52644          *:*              -                               svchost.exe         -          
  07:14:25  connection_snapshot   tcp        127.0.0.1:62591        127.0.0.1:63698  -                               Code.exe            local      
  07:14:25  connection_snapshot   udp        0.0.0.0:59343          *:*              -                               Code.exe            unknown    
  07:14:25  process_network_act>  tcp        127.0.0.1:62591        127.0.0.1:63698  -                               Code.exe            -          
  07:14:25  process_network_act>  udp        0.0.0.0:59343          *:*              -                               Code.exe            -          
  07:14:25  connection_snapshot   udp        0.0.0.0:55663          *:*              -                               chrome.exe          unknown    
  07:14:25  process_network_act>  udp        0.0.0.0:55663          *:*              -                               chrome.exe          -          
  07:14:25  connection_snapshot   tcp        127.0.0.1:52733        *:*              -                               language_server.e>  inbound    
  07:14:25  process_network_act>  tcp        127.0.0.1:52733        *:*              -                               language_server.e>  -          
  07:14:25  connection_snapshot   tcp        0.0.0.0:49664          *:*              -                               lsass.exe           inbound    
  07:14:25  process_network_act>  tcp        0.0.0.0:49664          *:*              -                               lsass.exe           -          
  07:14:25  connection_snapshot   tcp        :::47821               *:*              -                               Code.exe            inbound    
  07:14:25  process_network_act>  tcp        :::47821               *:*              -                               Code.exe            -          
  07:14:25  connection_snapshot   tcp        192.168.0.103:56917    104.18.32.47:4>  Toronto, Canada (Cloudflare, >  codex.exe           outbound   
  07:14:25  connection_snapshot   tcp        192.168.0.103:62754    134.224.0.125:>  San Jose, United States (Amaz>  chrome.exe          outbound   
  07:14:25  connection_snapshot   udp        :::55663               *:*              -                               chrome.exe          unknown    
  07:14:25  connection_snapshot   udp        :::5353                *:*              -                               svchost.exe         unknown    
  07:14:25  connection_snapshot   tcp        127.0.0.1:52732        127.0.0.1:58768  -                               language_server.e>  local      
  07:14:25  connection_snapshot   tcp        192.168.0.103:50550    170.114.52.2:4>  San Jose, United States (Clou>  chrome.exe          outbound   
  07:14:25  process_network_act>  tcp        192.168.0.103:56917    104.18.32.47:4>  Toronto, Canada (Cloudflare, >  codex.exe           -          
  07:14:25  process_network_act>  tcp        192.168.0.103:62754    134.224.0.125:>  San Jose, United States (Amaz>  chrome.exe          -          
  07:14:25  process_network_act>  udp        :::55663               *:*              -                               chrome.exe          -          
  07:14:25  process_network_act>  udp        :::5353                *:*              -                               svchost.exe         -          
  07:14:25  process_network_act>  tcp        127.0.0.1:52732        127.0.0.1:58768  -                               language_server.e>  -          
  07:14:25  process_network_act>  tcp        192.168.0.103:50550    170.114.52.2:4>  San Jose, United States (Clou>  chrome.exe          -          
  07:14:25  connection_snapshot   udp        0.0.0.0:5353           *:*              -                               chrome.exe          unknown    
  07:14:25  process_network_act>  udp        0.0.0.0:5353           *:*              -                               chrome.exe          -          
  07:14:25  connection_snapshot   tcp        :::49670               *:*              -                               services.exe        inbound    
  07:14:25  process_network_act>  tcp        :::49670               *:*              -                               services.exe        -          
  07:14:25  connection_snapshot   tcp        192.168.0.103:54757    20.192.44.82:4>  Pune, India (Microsoft Corpor>  CrossDeviceServic>  outbound   
  07:14:25  connection_snapshot   tcp        127.0.0.1:64568        *:*              -                               Code.exe            inbound    
  07:14:25  connection_snapshot   udp        ::1:1900               *:*              -                               svchost.exe         unknown    
  07:14:25  process_network_act>  tcp        192.168.0.103:54757    20.192.44.82:4>  Pune, India (Microsoft Corpor>  CrossDeviceServic>  -          
  07:14:25  process_network_act>  tcp        127.0.0.1:64568        *:*              -                               Code.exe            -          
  07:14:25  process_network_act>  udp        ::1:1900               *:*              -                               svchost.exe         -          
  07:14:25  connection_snapshot   tcp        0.0.0.0:47823          *:*              -                               Code.exe            inbound    
  07:14:25  connection_snapshot   tcp        :::47822               *:*              -                               Code.exe            inbound    
  07:14:25  process_network_act>  tcp        0.0.0.0:47823          *:*              -                               Code.exe            -          
  07:14:25  process_network_act>  tcp        :::47822               *:*              -                               Code.exe            -          
  07:14:25  connection_snapshot   udp        0.0.0.0:56210          *:*              -                               svchost.exe         unknown    
  07:14:25  connection_snapshot   udp        127.0.0.1:1900         *:*              -                               svchost.exe         unknown    
  07:14:25  connection_snapshot   tcp        192.168.0.103:64471    134.224.130.33>  London, United Kingdom (Amazo>  chrome.exe          outbound   
  07:14:25  connection_snapshot   tcp        192.168.0.103:55133    104.18.32.47:4>  Toronto, Canada (Cloudflare, >  chrome.exe          outbound   
  07:14:25  process_network_act>  udp        0.0.0.0:56210          *:*              -                               svchost.exe         -          
  07:14:25  process_network_act>  udp        127.0.0.1:1900         *:*              -                               svchost.exe         -          
  07:14:25  process_network_act>  tcp        192.168.0.103:64471    134.224.130.33>  London, United Kingdom (Amazo>  chrome.exe          -          
  07:14:25  process_network_act>  tcp        192.168.0.103:55133    104.18.32.47:4>  Toronto, Canada (Cloudflare, >  chrome.exe          -          
  07:14:25  connection_snapshot   tcp        127.0.0.1:50240        127.0.0.1:52732  -                               Antigravity.exe     local      
  07:14:25  connection_snapshot   tcp        127.0.0.1:8884         *:*              -                               System              inbound    
  07:14:25  process_network_act>  tcp        127.0.0.1:50240        127.0.0.1:52732  -                               Antigravity.exe     -          
  07:14:25  process_network_act>  tcp        127.0.0.1:8884         *:*              -                               System              -          
  07:14:25  connection_snapshot   tcp        192.168.0.103:57380    13.107.213.48:>  Teterboro, United States (Mic>  msedge.exe          outbound   
  07:14:25  connection_snapshot   udp        :::52644               *:*              -                               svchost.exe         unknown    
  07:14:25  connection_snapshot   udp        ::1:60241              *:*              -                               svchost.exe         unknown    
  07:14:25  connection_snapshot   tcp        :::47823               *:*              -                               Code.exe            inbound    
  07:14:25  process_network_act>  tcp        192.168.0.103:57380    13.107.213.48:>  Teterboro, United States (Mic>  msedge.exe          -          
  07:14:25  process_network_act>  udp        :::52644               *:*              -                               svchost.exe         -          
  07:14:25  process_network_act>  udp        ::1:60241              *:*              -                               svchost.exe         -          
  07:14:25  process_network_act>  tcp        :::47823               *:*              -                               Code.exe            -          
  07:14:25  connection_snapshot   tcp        0.0.0.0:49666          *:*              -                               svchost.exe         inbound    
  07:14:25  connection_snapshot   udp        192.168.0.103:64095    *:*              -                               chrome.exe          unknown    
  07:14:25  connection_snapshot   udp        0.0.0.0:55660          *:*              -                               chrome.exe          unknown    
  07:14:25  connection_snapshot   tcp        192.168.0.103:50875    57.144.43.32:4>  Mumbai, India (Facebook, Inc.)  chrome.exe          outbound   
  07:14:25  process_network_act>  tcp        0.0.0.0:49666          *:*              -                               svchost.exe         -          
  07:14:25  process_network_act>  udp        192.168.0.103:64095    *:*              -                               chrome.exe          -          
  07:14:25  process_network_act>  udp        0.0.0.0:55660          *:*              -                               chrome.exe          -          
  07:14:25  process_network_act>  tcp        192.168.0.103:50875    57.144.43.32:4>  Mumbai, India (Facebook, Inc.)  chrome.exe          -          
  07:14:25  connection_snapshot   udp        fe80::adef:29b5:abe3>  *:*              -                               svchost.exe         unknown    
  07:14:25  connection_snapshot   tcp        0.0.0.0:47824          *:*              -                               Code.exe            inbound    
  07:14:25  connection_snapshot   udp        0.0.0.0:61957          *:*              -                               chrome.exe          unknown    
  07:14:25  connection_snapshot   tcp        172.29.0.1:139         *:*              -                               System              inbound    
  07:14:25  process_network_act>  udp        fe80::adef:29b5:abe3>  *:*              -                               svchost.exe         -          
  07:14:25  process_network_act>  tcp        0.0.0.0:47824          *:*              -                               Code.exe            -          
  07:14:25  process_network_act>  udp        0.0.0.0:61957          *:*              -                               chrome.exe          -          
  07:14:25  process_network_act>  tcp        172.29.0.1:139         *:*              -                               System              -          
  07:14:25  connection_snapshot   udp        192.168.0.103:60243    *:*              -                               svchost.exe         unknown    
  07:14:25  connection_snapshot   tcp        127.0.0.1:56968        *:*              -                               Code.exe            inbound    
  07:14:25  process_network_act>  udp        192.168.0.103:60243    *:*              -                               svchost.exe         -          
  07:14:25  process_network_act>  tcp        127.0.0.1:56968        *:*              -                               Code.exe            -          
  07:14:25  connection_snapshot   tcp        127.0.0.1:52731        *:*              -                               Antigravity.exe     inbound    
  07:14:25  connection_snapshot   udp        0.0.0.0:56211          *:*              -                               svchost.exe         unknown    
  07:14:25  connection_snapshot   tcp        192.168.0.103:139      *:*              -                               System              inbound    
  07:14:25  process_network_act>  tcp        127.0.0.1:52731        *:*              -                               Antigravity.exe     -          
  07:14:25  process_network_act>  udp        0.0.0.0:56211          *:*              -                               svchost.exe         -          
  07:14:25  process_network_act>  tcp        192.168.0.103:139      *:*              -                               System              -          
  07:14:25  connection_snapshot   tcp        ::1:49669              *:*              -                               jhi_service.exe     inbound    
  07:14:25  process_network_act>  tcp        ::1:49669              *:*              -                               jhi_service.exe     -          
  07:14:25  connection_snapshot   tcp        192.168.0.103:54753    20.49.91.128:8>  San Antonio, United States (M>  SupportAssistAgen>  unknown    
  07:14:25  process_network_act>  tcp        192.168.0.103:54753    20.49.91.128:8>  San Antonio, United States (M>  SupportAssistAgen>  -          
  07:14:25  connection_snapshot   tcp        ::1:42050              *:*              -                               OneDrive.Sync.Ser>  inbound    
  07:14:25  process_network_act>  tcp        ::1:42050              *:*              -                               OneDrive.Sync.Ser>  -          
  07:14:25  connection_snapshot   tcp        0.0.0.0:135            *:*              -                               svchost.exe         inbound    
  07:14:25  connection_snapshot   tcp        :::49664               *:*              -                               lsass.exe           inbound    
  07:14:25  process_network_act>  tcp        0.0.0.0:135            *:*              -                               svchost.exe         -          
  07:14:25  process_network_act>  tcp        :::49664               *:*              -                               lsass.exe           -          
  07:14:25  connection_snapshot   tcp        192.168.0.103:50893    172.64.155.209>  -                               codex.exe           outbound   
  07:14:25  connection_snapshot   tcp        192.168.0.103:52799    20.42.65.84:443  Boydton, United States (Micro>  Code.exe            outbound   
  07:14:25  connection_snapshot   udp        172.29.0.1:68          *:*              -                               svchost.exe         unknown    
  07:14:25  connection_snapshot   tcp        192.168.0.103:57942    134.224.130.33>  London, United Kingdom (Amazo>  chrome.exe          outbound   
  07:14:25  connection_snapshot   udp        172.29.0.1:1900        *:*              -                               svchost.exe         unknown    
  07:14:25  connection_snapshot   tcp        :::47824               *:*              -                               Code.exe            inbound    
  07:14:25  process_network_act>  tcp        192.168.0.103:50893    172.64.155.209>  -                               codex.exe           -          
  07:14:25  process_network_act>  tcp        192.168.0.103:52799    20.42.65.84:443  Boydton, United States (Micro>  Code.exe            -          
  07:14:25  process_network_act>  udp        172.29.0.1:68          *:*              -                               svchost.exe         -          
  07:14:25  process_network_act>  tcp        192.168.0.103:57942    134.224.130.33>  London, United Kingdom (Amazo>  chrome.exe          -          
  07:14:25  process_network_act>  udp        172.29.0.1:1900        *:*              -                               svchost.exe         -          
  07:14:25  process_network_act>  tcp        :::47824               *:*              -                               Code.exe            -          
  07:14:25  connection_snapshot   tcp        :::49667               *:*              -                               svchost.exe         inbound    
  07:14:25  connection_snapshot   udp        192.168.0.103:137      *:*              -                               System              unknown    
  07:14:25  process_network_act>  tcp        :::49667               *:*              -                               svchost.exe         -          
  07:14:25  process_network_act>  udp        192.168.0.103:137      *:*              -                               System              -          
  07:14:26  connection_snapshot   tcp        192.168.0.103:49470    4.213.25.241:4>  Pune, India (Microsoft Corpor>  svchost.exe         outbound   
  07:14:26  connection_snapshot   tcp        0.0.0.0:49667          *:*              -                               svchost.exe         inbound    
  07:14:26  connection_snapshot   tcp        127.0.0.1:58768        127.0.0.1:52732  -                               Antigravity.exe     local      
  07:14:26  connection_snapshot   udp        172.29.0.1:137         *:*              -                               System              unknown    
  07:14:26  connection_snapshot   tcp        192.168.0.103:65093    185.199.111.13>  San Francisco, United States >  chrome.exe          outbound   
  07:14:26  connection_snapshot   tcp        192.168.0.103:63486    48.218.107.40:>  Tokyo, Japan (Microsoft Corpo>  msedge.exe          outbound   
  07:14:26  process_network_act>  tcp        192.168.0.103:49470    4.213.25.241:4>  Pune, India (Microsoft Corpor>  svchost.exe         -          
  07:14:26  process_network_act>  tcp        0.0.0.0:49667          *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  tcp        127.0.0.1:58768        127.0.0.1:52732  -                               Antigravity.exe     -          
  07:14:26  process_network_act>  udp        172.29.0.1:137         *:*              -                               System              -          
  07:14:26  process_network_act>  tcp        192.168.0.103:65093    185.199.111.13>  San Francisco, United States >  chrome.exe          -          
  07:14:26  process_network_act>  tcp        192.168.0.103:63486    48.218.107.40:>  Tokyo, Japan (Microsoft Corpo>  msedge.exe          -          
  07:14:26  connection_snapshot   tcp        :::2179                *:*              -                               vmms.exe            inbound    
  07:14:26  connection_snapshot   tcp        0.0.0.0:2179           *:*              -                               vmms.exe            inbound    
  07:14:26  connection_snapshot   udp        172.29.0.1:2177        *:*              -                               svchost.exe         unknown    
  07:14:26  connection_snapshot   udp        10.153.124.79:62887    *:*              -                               chrome.exe          unknown    
  07:14:26  connection_snapshot   tcp        0.0.0.0:47821          *:*              -                               Code.exe            inbound    
  07:14:26  connection_snapshot   udp        fe80::88a0:d396:d44d>  *:*              -                               svchost.exe         unknown    
  07:14:26  connection_snapshot   tcp        192.168.0.103:54041    172.64.148.235>  -                               chrome.exe          outbound   
  07:14:26  connection_snapshot   udp        172.29.0.1:62886       *:*              -                               chrome.exe          unknown    
  07:14:26  connection_snapshot   tcp        127.0.0.1:63698        127.0.0.1:62591  -                               Code.exe            local      
  07:14:26  process_network_act>  tcp        :::2179                *:*              -                               vmms.exe            -          
  07:14:26  process_network_act>  tcp        0.0.0.0:2179           *:*              -                               vmms.exe            -          
  07:14:26  process_network_act>  udp        172.29.0.1:2177        *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  udp        10.153.124.79:62887    *:*              -                               chrome.exe          -          
  07:14:26  process_network_act>  tcp        0.0.0.0:47821          *:*              -                               Code.exe            -          
  07:14:26  process_network_act>  udp        fe80::88a0:d396:d44d>  *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  tcp        192.168.0.103:54041    172.64.148.235>  -                               chrome.exe          -          
  07:14:26  process_network_act>  udp        172.29.0.1:62886       *:*              -                               chrome.exe          -          
  07:14:26  process_network_act>  tcp        127.0.0.1:63698        127.0.0.1:62591  -                               Code.exe            -          
  07:14:26  connection_snapshot   tcp        0.0.0.0:49665          *:*              -                               wininit.exe         inbound    
  07:14:26  connection_snapshot   tcp        192.168.0.103:54426    172.188.155.25>  -                               msedge.exe          outbound   
  07:14:26  connection_snapshot   tcp        0.0.0.0:47822          *:*              -                               Code.exe            inbound    
  07:14:26  connection_snapshot   udp        :::56212               *:*              -                               svchost.exe         unknown    
  07:14:26  connection_snapshot   tcp        :::445                 *:*              -                               System              inbound    
  07:14:26  connection_snapshot   tcp        127.0.0.1:52732        127.0.0.1:50240  -                               language_server.e>  local      
  07:14:26  connection_snapshot   udp        172.29.0.1:138         *:*              -                               System              unknown    
  07:14:26  process_network_act>  tcp        0.0.0.0:49665          *:*              -                               wininit.exe         -          
  07:14:26  process_network_act>  tcp        192.168.0.103:54426    172.188.155.25>  -                               msedge.exe          -          
  07:14:26  process_network_act>  tcp        0.0.0.0:47822          *:*              -                               Code.exe            -          
  07:14:26  process_network_act>  udp        :::56212               *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  tcp        :::445                 *:*              -                               System              -          
  07:14:26  process_network_act>  tcp        127.0.0.1:52732        127.0.0.1:50240  -                               language_server.e>  -          
  07:14:26  process_network_act>  udp        172.29.0.1:138         *:*              -                               System              -          
  07:14:26  connection_snapshot   tcp        192.168.0.103:51317    134.224.0.125:>  San Jose, United States (Amaz>  chrome.exe          outbound   
  07:14:26  connection_snapshot   tcp        192.168.0.103:60946    34.54.84.110:4>  Kansas City, United States (G>  language_server.e>  outbound   
  07:14:26  connection_snapshot   tcp        :::49665               *:*              -                               wininit.exe         inbound    
  07:14:26  process_network_act>  tcp        192.168.0.103:51317    134.224.0.125:>  San Jose, United States (Amaz>  chrome.exe          -          
  07:14:26  process_network_act>  tcp        192.168.0.103:60946    34.54.84.110:4>  Kansas City, United States (G>  language_server.e>  -          
  07:14:26  process_network_act>  tcp        :::49665               *:*              -                               wininit.exe         -          
  07:14:26  connection_snapshot   tcp        :::49668               *:*              -                               spoolsv.exe         inbound    
  07:14:26  connection_snapshot   tcp        192.168.0.103:60339    134.224.130.33>  London, United Kingdom (Amazo>  chrome.exe          outbound   
  07:14:26  connection_snapshot   udp        fe80::adef:29b5:abe3>  *:*              -                               svchost.exe         unknown    
  07:14:26  connection_snapshot   tcp        127.0.0.1:52732        *:*              -                               language_server.e>  inbound    
  07:14:26  connection_snapshot   tcp        192.168.0.103:61936    140.82.112.26:>  San Francisco, United States >  chrome.exe          outbound   
  07:14:26  connection_snapshot   tcp        :::135                 *:*              -                               svchost.exe         inbound    
  07:14:26  connection_snapshot   tcp        127.0.0.1:58270        *:*              -                               System              inbound    
  07:14:26  connection_snapshot   tcp        192.168.0.103:59744    147.135.78.177>  Oakton, United States (OVH SA>  chrome.exe          outbound   
  07:14:26  connection_snapshot   tcp        0.0.0.0:49668          *:*              -                               spoolsv.exe         inbound    
  07:14:26  connection_snapshot   udp        0.0.0.0:53             *:*              -                               svchost.exe         unknown    
  07:14:26  connection_snapshot   udp        fe80::88a0:d396:d44d>  *:*              -                               svchost.exe         unknown    
  07:14:26  connection_snapshot   tcp        127.0.0.1:62756        127.0.0.1:58270  -                               -                   local      
  07:14:26  connection_snapshot   udp        0.0.0.0:55662          *:*              -                               chrome.exe          unknown    
  07:14:26  connection_snapshot   tcp        127.0.0.1:52729        *:*              -                               Antigravity.exe     inbound    
  07:14:26  connection_snapshot   tcp        0.0.0.0:445            *:*              -                               System              inbound    
  07:14:26  connection_snapshot   udp        :::5355                *:*              -                               svchost.exe         unknown    
  07:14:26  connection_snapshot   tcp        192.168.0.103:64458    172.217.113.4:>  -                               language_server.e>  outbound   
  07:14:26  process_network_act>  tcp        :::49668               *:*              -                               spoolsv.exe         -          
  07:14:26  process_network_act>  tcp        192.168.0.103:60339    134.224.130.33>  London, United Kingdom (Amazo>  chrome.exe          -          
  07:14:26  process_network_act>  udp        fe80::adef:29b5:abe3>  *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  tcp        127.0.0.1:52732        *:*              -                               language_server.e>  -          
  07:14:26  process_network_act>  tcp        192.168.0.103:61936    140.82.112.26:>  San Francisco, United States >  chrome.exe          -          
  07:14:26  process_network_act>  tcp        :::135                 *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  tcp        127.0.0.1:58270        *:*              -                               System              -          
  07:14:26  process_network_act>  tcp        192.168.0.103:59744    147.135.78.177>  Oakton, United States (OVH SA>  chrome.exe          -          
  07:14:26  process_network_act>  tcp        0.0.0.0:49668          *:*              -                               spoolsv.exe         -          
  07:14:26  process_network_act>  udp        0.0.0.0:53             *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  udp        fe80::88a0:d396:d44d>  *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  udp        0.0.0.0:55662          *:*              -                               chrome.exe          -          
  07:14:26  process_network_act>  tcp        127.0.0.1:52729        *:*              -                               Antigravity.exe     -          
  07:14:26  process_network_act>  tcp        0.0.0.0:445            *:*              -                               System              -          
  07:14:26  process_network_act>  udp        :::5355                *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  tcp        192.168.0.103:64458    172.217.113.4:>  -                               language_server.e>  -          
  07:14:26  connection_snapshot   tcp        127.0.0.1:62171        *:*              -                               Code.exe            inbound    
  07:14:26  connection_snapshot   udp        0.0.0.0:5355           *:*              -                               svchost.exe         unknown    
  07:14:26  process_network_act>  tcp        127.0.0.1:62171        *:*              -                               Code.exe            -          
  07:14:26  process_network_act>  udp        0.0.0.0:5355           *:*              -                               svchost.exe         -          
  07:14:26  connection_snapshot   udp        0.0.0.0:5050           *:*              -                               svchost.exe         unknown    
  07:14:26  connection_snapshot   tcp        127.0.0.1:62591        *:*              -                               Code.exe            inbound    
  07:14:26  connection_snapshot   udp        :::55661               *:*              -                               chrome.exe          unknown    
  07:14:26  connection_snapshot   udp        0.0.0.0:55661          *:*              -                               chrome.exe          unknown    
  07:14:26  connection_snapshot   tcp        192.168.0.103:61173    140.82.113.21:>  San Francisco, United States >  Code.exe            outbound   
  07:14:26  process_network_act>  udp        0.0.0.0:5050           *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  tcp        127.0.0.1:62591        *:*              -                               Code.exe            -          
  07:14:26  process_network_act>  udp        :::55661               *:*              -                               chrome.exe          -          
  07:14:26  process_network_act>  udp        0.0.0.0:55661          *:*              -                               chrome.exe          -          
  07:14:26  process_network_act>  tcp        192.168.0.103:61173    140.82.113.21:>  San Francisco, United States >  Code.exe            -          
  07:14:26  connection_snapshot   tcp        :::7680                *:*              -                               svchost.exe         inbound    
  07:14:26  connection_snapshot   tcp        192.168.0.103:64789    192.178.211.18>  Mountain View, United States >  chrome.exe          unknown    
  07:14:26  connection_snapshot   tcp        192.168.0.103:52829    172.217.118.4:>  -                               language_server.e>  outbound   
  07:14:26  connection_snapshot   udp        192.168.0.103:1900     *:*              -                               svchost.exe         unknown    
  07:14:26  connection_snapshot   tcp        127.0.0.1:50685        127.0.0.1:58270  -                               -                   local      
  07:14:26  connection_snapshot   udp        172.29.0.1:60245       *:*              -                               svchost.exe         unknown    
  07:14:26  connection_snapshot   udp        127.0.0.1:60244        *:*              -                               svchost.exe         unknown    
  07:14:26  connection_snapshot   tcp        :::49666               *:*              -                               svchost.exe         inbound    
  07:14:26  process_network_act>  tcp        :::7680                *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  tcp        192.168.0.103:64789    192.178.211.18>  Mountain View, United States >  chrome.exe          -          
  07:14:26  process_network_act>  tcp        192.168.0.103:52829    172.217.118.4:>  -                               language_server.e>  -          
  07:14:26  process_network_act>  udp        192.168.0.103:1900     *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  udp        172.29.0.1:60245       *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  udp        127.0.0.1:60244        *:*              -                               svchost.exe         -          
  07:14:26  connection_snapshot   tcp        192.168.0.103:64443    35.190.80.1:443  Kansas City, United States (G>  chrome.exe          outbound   
  07:14:26  connection_snapshot   tcp        192.168.0.103:54500    172.64.148.235>  -                               chrome.exe          outbound   
  07:14:26  connection_snapshot   udp        192.168.0.103:138      *:*              -                               System              unknown    
  07:14:26  connection_snapshot   tcp        127.0.0.1:50890        127.0.0.1:58270  -                               -                   local      
  07:14:26  process_network_act>  tcp        :::49666               *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  tcp        192.168.0.103:64443    35.190.80.1:443  Kansas City, United States (G>  chrome.exe          -          
  07:14:26  process_network_act>  tcp        192.168.0.103:54500    172.64.148.235>  -                               chrome.exe          -          
  07:14:26  process_network_act>  udp        192.168.0.103:138      *:*              -                               System              -          
  07:14:26  connection_snapshot   tcp        192.168.0.103:62863    52.110.14.153:>  Pune, India (Microsoft Corpor>  explorer.exe        outbound   
  07:14:26  connection_snapshot   udp        192.168.0.103:2177     *:*              -                               svchost.exe         unknown    
  07:14:26  process_network_act>  tcp        192.168.0.103:62863    52.110.14.153:>  Pune, India (Microsoft Corpor>  explorer.exe        -          
  07:14:26  connection_snapshot   tcp        192.168.0.103:61012    172.64.148.235>  -                               chrome.exe          outbound   
  07:14:26  connection_snapshot   tcp        127.0.0.1:50895        127.0.0.1:58270  -                               -                   local      
  07:14:26  connection_snapshot   tcp        192.168.0.103:60284    134.224.130.33>  London, United Kingdom (Amazo>  chrome.exe          outbound   
  07:14:26  connection_snapshot   tcp        0.0.0.0:5040           *:*              -                               svchost.exe         inbound    
  07:14:26  connection_snapshot   tcp        0.0.0.0:49670          *:*              -                               services.exe        inbound    
  07:14:26  connection_snapshot   tcp        127.0.0.1:50892        127.0.0.1:58912  -                               -                   local      
  07:14:26  connection_snapshot   udp        fe80::88a0:d396:d44d>  *:*              -                               svchost.exe         unknown    
  07:14:26  connection_snapshot   tcp        192.168.0.103:50683    170.114.52.38:>  San Jose, United States (Clou>  chrome.exe          outbound   
  07:14:26  connection_snapshot   tcp        127.0.0.1:59732        127.0.0.1:62591  -                               -                   local      
  07:14:26  connection_snapshot   tcp        192.168.0.103:62230    134.224.130.33>  London, United Kingdom (Amazo>  chrome.exe          outbound   
  07:14:26  connection_snapshot   tcp        0.0.0.0:7680           *:*              -                               svchost.exe         inbound    
  07:14:26  connection_snapshot   udp        172.29.0.1:67          *:*              -                               svchost.exe         unknown    
  07:14:26  connection_snapshot   tcp        192.168.0.103:61172    140.82.113.21:>  San Francisco, United States >  Code.exe            outbound   
  07:14:26  connection_snapshot   udp        0.0.0.0:61161          *:*              -                               chrome.exe          unknown    
  07:14:26  process_network_act>  udp        192.168.0.103:2177     *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  tcp        192.168.0.103:61012    172.64.148.235>  -                               chrome.exe          -          
  07:14:26  process_network_act>  tcp        192.168.0.103:60284    134.224.130.33>  London, United Kingdom (Amazo>  chrome.exe          -          
  07:14:26  process_network_act>  tcp        0.0.0.0:5040           *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  tcp        0.0.0.0:49670          *:*              -                               services.exe        -          
  07:14:26  process_network_act>  udp        fe80::88a0:d396:d44d>  *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  tcp        192.168.0.103:50683    170.114.52.38:>  San Jose, United States (Clou>  chrome.exe          -          
  07:14:26  process_network_act>  tcp        192.168.0.103:62230    134.224.130.33>  London, United Kingdom (Amazo>  chrome.exe          -          
  07:14:26  process_network_act>  tcp        0.0.0.0:7680           *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  udp        172.29.0.1:67          *:*              -                               svchost.exe         -          
  07:14:26  process_network_act>  tcp        192.168.0.103:61172    140.82.113.21:>  San Francisco, United States >  Code.exe            -          
  07:14:26  process_network_act>  udp        0.0.0.0:61161          *:*              -                               chrome.exe          -          
  07:14:26  connection_snapshot   udp        127.0.0.1:49664        *:*              -                               svchost.exe         unknown    
  07:14:26  process_network_act>  udp        127.0.0.1:49664        *:*              -                               svchost.exe         -          
  07:14:26  traffic_stats         -          *:*                    *:*              -                               -                   -          
  07:14:26  traffic_stats         -          *:*                    *:*              -                               -                   -          


=========================== FILE EVENTS  (6 events) ============================
  Note: Process attribution for files requires ETW (Windows) / eBPF (Linux) which will be added in v2.
  TIME      ACTION    EXT     SIZE (B)    PROCESS           PATH                                                        
  --------  --------  ------  ----------  ----------------  ------------------------------------------------------------
  07:14:25  create    .txt    -           unavailable       C:\Users\Visha\AppData\Local\Temp\aegis-final-watch-_wqur29>
  07:14:25  modify    .txt    -           unavailable       C:\Users\Visha\AppData\Local\Temp\aegis-final-watch-_wqur29>
  07:14:25  modify    .txt    -           unavailable       C:\Users\Visha\AppData\Local\Temp\aegis-final-watch-_wqur29>
  07:14:25  modify    .txt    -           unavailable       C:\Users\Visha\AppData\Local\Temp\aegis-final-watch-_wqur29>
  07:14:25  rename    .txt    -           unavailable       C:\Users\Visha\AppData\Local\Temp\aegis-final-watch-_wqur29>
  07:14:25  delete    .txt    -           unavailable       C:\Users\Visha\AppData\Local\Temp\aegis-final-watch-_wqur29>


====================== AUTHENTICATION EVENTS  (0 events) =======================
  (no authentication events in this session)
  Note: On Windows, capturing auth events requires the script to be run as Administrator (to read the Security Event Log), and requires an actual login/logout event to occur during the monitoring window.


============================ FINDINGS  (0 findings) ============================
  (no findings generated in this session)


========================== HEALTH EVENTS  (3 events) ===========================
  TIME      SOURCE              STATUS / ACTION           DETAIL                                                      
  --------  ------------------  ------------------------  ------------------------------------------------------------
  07:14:12  engine              started                   collectors=['process_lifecycle', 'file_events', 'network_br>
  07:14:27  engine              healthy                   collectors=[{'backing_off': False, 'collector': 'process_li>
  07:14:27  engine              stopped                   -                                                           


================================= LIMITATIONS ==================================
  - File process attribution is unavailable with watchdog/polling and is explicitly recorded as unavailable.
  - Process lifecycle is snapshot-difference based; short-lived processes and PID reuse can be missed or ambiguous.
  - Network polling can miss connections that start and end between polls; ETW is capability-detected, not consumed by this Python path.
  - Authentication results depend on the host Security Event Log/journal source and permissions; zero matching events is distinct from unavailable capability.
  - IP geolocation is report-time enrichment only; raw evidence remains IP addresses and timestamps, so geographic movement is not asserted.
  - No authentication events were observed in this run; inspect HEALTH capability/status evidence for the reason.
  - ETW consumption requires a dedicated, signed Windows implementation
