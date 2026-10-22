# Sangoma FreePBX and Asterisk to Sophos NG-SIEM

Asterisk sends nothing to syslog until you add a syslog channel, and FreePBX writes its security log to a file until you route it to syslog. This entry reads what both send once they do: Asterisk security events, failed PJSIP and chan_sip requests, failed AMI logins, and FreePBX web logins.

## Asterisk

1. Add a syslog channel with the `security` level. On FreePBX, put it in `/etc/asterisk/logger_logfiles_custom.conf`, which FreePBX doesn't overwrite. On Asterisk on its own, put it under `[logfiles]` in `/etc/asterisk/logger.conf`:

   ```
   syslog.local0 => notice,warning,error,security
   ```

2. Run `asterisk -rx "logger reload"`, then `asterisk -rx "logger show channels"` and check the syslog channel lists `SECURITY`.

## FreePBX

1. Go to Settings > Advanced Settings and set FreePBX Log Routing (`AMPSYSLOGLEVEL`) to `LOG_NOTICE`. Leave Log Verbose Messages (`LOG_OUT_MESSAGES`) on: FreePBX only writes security lines while it is on.
2. Run `fwconsole reload`.

## Forward to the data collector

FreePBX sends to the `user` facility and Asterisk to `local0`. Forward both to the data collector on port 514, for example in `/etc/rsyslog.d/90-ngsiem.conf` (`@` is UDP, `@@` TCP):

```
user.*;local0.* @collector.example.com:514
```

Then restart rsyslog. RFC 3164 (rsyslog's default when it forwards) and RFC 5424 both work.

## What lands where

| Line | Schema |
| --- | --- |
| `SecurityEvent="SuccessfulAuth"`, `"InvalidAccountID"`, `"ChallengeResponseFailed"`, `"InvalidPassword"`, `"FailedACL"`, `"AuthMethodNotAllowed"`, `"UnexpectedAddress"`, `"InvalidTransport"` | Auth |
| PJSIP `Request '...' from '...' failed for '...'` and chan_sip `Registration from '...' failed for '...'` | Auth |
| AMI `... failed to authenticate as '...'` | Auth |
| FreePBX `Authentication failure for`, `Authentication successful for`, `Remote auth failure for`, `Remote auth success for` | Auth |
| `ChallengeSent`, the request, session, memory and load security events, and every other Asterisk or FreePBX line | Generic |

With security logging on, a failed SIP request gives a security event and a PJSIP or chan_sip notice, so a count of failures should use one of the two.

Asterisk writes a security event's time with its zone. The FreePBX time and an RFC 3164 header have none, so the parser reads them as UTC: keep the PBX on UTC, or expect those times to be off by its offset.

Not checked against a live PBX: the lines here are built from the Asterisk and FreePBX source code, since neither publishes example lines. Send a failed registration and a failed web login, and compare them with `samples.log` before you rely on it.
