# Microsoft NPS accounting logs to Sophos NG-SIEM

Network Policy Server (NPS) writes its RADIUS accounting log, every Access-Request, Access-Accept, Access-Reject and Accounting-Request, to text files (`IN*.log`) in `%SystemRoot%\System32\LogFiles` by default. NXLog Community Edition can read them and send each record, unchanged, as a syslog message to a Sophos NG-SIEM data collector, the pattern Sophos's own NXLog template uses for DHCP, DNS and IIS logs. The NPS events in the Windows Security log (6272, 6273 and the rest) come through the Sophos Windows Event Log integration instead; these files add the accounting side: session start and stop, the address the client was given, and byte counts.

1. In the NPS console, go to Accounting > Change Log File Properties. Under Settings, log at least Accounting requests and Authentication requests. On the Log File tab, keep the directory or note yours, and pick a format: DTS Compliant (Microsoft's default), ODBC (Legacy) or IAS (Legacy). The parsers read all three.
2. Install NXLog Community Edition on each NPS server and add the block below to `nxlog.conf`. Set `XDR` to your data collector's address and `NPSLOGS` to the log folder.
3. Restart the NXLog service.

```
define XDR      A.B.C.D
define PORT     601
define NPSLOGS  C:\Windows\System32\LogFiles

<Extension _syslog>
    Module      xm_syslog
</Extension>

<Input NPSIN>
    Module      im_file
    File        '%NPSLOGS%\IN*.log'
    SavePos     TRUE
    InputType   LineBased
    Exec        if $raw_event == '' drop();
    Exec        $Hostname = hostname_fqdn(); $SourceName = "NPSLog"; $Message = $raw_event;
</Input>

<Output NPSOUT>
    Module      om_tcp
    Host        %XDR%
    Port        %PORT%
    # RFC 5424 syslog on local5.info. NXLog writes the header's time in local time with its offset,
    # which the parser adds to the NPS record's own local time.
    Exec        $SyslogFacilityValue = 21; $Hostname = hostname_fqdn(); $Severity = 'INFO'; to_syslog_ietf();
</Output>

<Route nps_accounting>
    Path        NPSIN => NPSOUT
</Route>
```

If your nxlog.conf already defines `_syslog`, leave out the second definition. Each record arrives as `<174>1 2026-10-14T09:04:33.640218+11:00 nps01.corp.example.com NPSLog - - [NXLOG@14506 EventReceivedTime="2026-10-14 09:04:33" SourceModuleName="NPSIN" SourceModuleType="im_file"] "NPS01","IAS",10/14/2026,09:04:33,2,...`.

NPS writes its times in the server's local time with no zone, and its dates in the server's regional order: 10/14/2026 on a server set to month first, 14/10/2026 on one set to day first, as Australian servers usually are. With the RFC 5424 header above, the parser adds the header's offset to the record's own date and time, so the event time is right wherever the server is, and takes the date order from a day over 12 or, failing that, from the header's date. With `to_syslog_bsd()`, as in Sophos's template for other Windows logs, the header has no zone either, so the event time is when the record arrived and the record's time is kept as `record_time` in event_metadata. Don't keep `UTCTimestamp TRUE` in the xm_syslog block: the header would then carry UTC, not the server's offset.

Use TCP: a DTS Compliant record can be over 2 KB, which UDP syslog can cut off.

Not checked against a live NPS server or NXLog agent. The config follows Sophos's NXLog template, NXLog's xm_syslog reference and Microsoft's NPS accounting docs. Send a few records and compare them with `samples.log` before you rely on it.
