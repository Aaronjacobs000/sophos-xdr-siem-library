# Exchange Server message tracking to Sophos NG-SIEM

Exchange writes message tracking logs as CSV files (`MSGTRK*.LOG`) on each Mailbox and Edge Transport server. NXLog Community Edition can read them and send each row, unchanged, as a syslog message to a Sophos NG-SIEM data collector. That's the pattern Sophos's own NXLog template uses for IIS, DNS and DHCP logs.

1. Install NXLog Community Edition on each Exchange server.
2. Add the block below to `nxlog.conf`. Set `XDR` to your data collector's address, and change `EXCHANGE` if Exchange isn't installed in the default folder. Use TCP: some rows are over 2 KB, which UDP syslog can cut off.
3. Restart the NXLog service.

```
define XDR      A.B.C.D
define PORT     601
define EXCHANGE C:\Program Files\Microsoft\Exchange Server\V15

<Extension _syslog>
    Module      xm_syslog
</Extension>

<Input MSEXCHTRKIN>
    Module      im_file
    File        '%EXCHANGE%\TransportRoles\Logs\MessageTracking\MSGTRK*.LOG'
    SavePos     TRUE
    InputType   LineBased
    # Skip the # header lines, and the CSV header row some files start with.
    Exec        if $raw_event =~ /^(\xEF\xBB\xBF)?(#|date-time,)/ drop();
    Exec        $Hostname = hostname_fqdn(); $SourceName = "MSExchangeTracking"; $Message = $raw_event;
</Input>

<Output MSEXCHTRKOUT>
    Module      om_tcp
    Host        %XDR%
    Port        %PORT%
    # RFC 3164 syslog on local5.info, as in Sophos's NXLog template.
    Exec        $SyslogFacilityValue = 21; $Hostname = hostname_fqdn(); $Severity = 'INFO'; to_syslog_bsd();
</Output>

<Route exchange_message_tracking>
    Path        MSEXCHTRKIN => MSEXCHTRKOUT
</Route>
```

If your nxlog.conf already defines `_syslog`, leave out the second definition. Each row arrives as `<174>Oct 12 22:40:15 exch01.corp.example.com MSExchangeTracking: 2026-10-12T11:40:15.123Z,...`. The parser reads the row with or without that syslog header, and takes the event time from the row's `date-time` column, which Exchange writes in UTC.

Not checked against a live Exchange server or NXLog agent. The config follows Sophos's NXLog template and the log folder, file names and header lines in Microsoft's and NXLog's docs. Send a few rows and compare them with `samples.log` before you rely on it.
