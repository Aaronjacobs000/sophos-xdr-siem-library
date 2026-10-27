# Kiteworks to Sophos NG-SIEM

Kiteworks logs user and admin activity across secure email, file sharing, SFTP, managed file transfer and web forms. It can send that activity over syslog to the Sophos NG-SIEM data collector, in JSON Format or plain text, or post it as PubSub webhook events straight to Sophos NG-SIEM HTTP Ingest. These parsers read all three.

## Send the activity over syslog

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. In the Kiteworks admin console, open the Locations page (System > Locations in the legacy console, System Setup > Locations in the new one), select the location and expand Syslog Settings under External Services.
3. Add a syslog server with the data collector's address, UDP or TCP, and its port. Tick Use TLS if the data collector takes TLS over TCP. Set Format to JSON Format, which carries the most detail; plain text parses too.
4. Set the time zone to UTC. The syslog time has no zone, so the parsers read it as UTC.

Kiteworks sends the appliance's own system logs (auditd, sendmail) over the same syslog. These parsers leave those lines alone.

## Or send PubSub events to HTTP Ingest

Kiteworks 9.4.0 and later post each event to a webhook with an Authorization header you set, so it can send to HTTP Ingest with no bridge.

1. In Sophos Fusion, go to Security Operations > Integrations > Marketplace, choose Custom, then Set Up under HTTP Ingest. Copy the Integration Key and URL.
2. In the Kiteworks admin console, go to Application Setup > Event Subscriptions and choose + Add Webhook URL:
   - Webhook URL: the HTTP Ingest URL.
   - In the Token field, enter the word Bearer, a space and the Integration Key. Kiteworks sends this value as the Authorization header on every delivery.
   - Secret: any value. Kiteworks signs deliveries with it, and HTTP Ingest doesn't check the signature.
   - Event categories: Subscribe to all events, or the categories you want.
3. Save, sign in to Kiteworks, and check that the sign-in arrives in Sophos NG-SIEM as one record.

Kiteworks retries a failed delivery after 5 seconds, 5 minutes, 1 hour and 1 day, then drops it. This route hasn't been tested end to end: the parsers passed Run Test on PubSub events, but none was sent through HTTP Ingest.

## Add the parsers

In Sophos Fusion, go to Security Operations > Integrations > Custom Parsers. Add `KITEWORKS_PARENT` first, then each child with the parent as its parent parser. Use Run Test with your own lines before you turn them on.

| Parser | Events |
| --- | --- |
| `KITEWORKS_PARENT` | Claims Kiteworks activity in all three shapes and routes it |
| `KITEWORKS_CHILD_AUTH` | Sign-ins, failed sign-ins, lockouts, unlocks, and password resets and changes to Auth |
| `KITEWORKS_CHILD_THIRDPARTYALERT` | Files a scan flagged as malicious, prohibited or quarantined to Thirdparty |
| `KITEWORKS_CHILD_CLOUDAUDIT` | Every other activity to CloudAudit |

## What you get

- Auth: the user, source address, user agent, client app (such as Kiteworks Web), session, and LOGON, LOGOFF, FAILURE or ACCOUNT with the auth category. A failed sign-in carries Kiteworks' error message.
- Thirdparty: a title with the scan type and verdict, such as "Kiteworks ATP scan: malicious file", high severity for a malicious file and medium otherwise, blocked when Kiteworks quarantined the file or the action failed, and the file name, path, size, type and hash.
- CloudAudit: the event name (such as add_file, send_mail, delete_folder_permanent, add_user or download), the kind of object as the event type (file, folder, mail or user, or the Activity Group in plain text), the user, address and user agent, the file or folder path, the objects as resources, and a secure mail's subject, sender, recipients and attachments as request parameters. Downloads and views are read-only, and admin and account changes are management events.
- The event time is the syslog time, read as UTC, or the PubSub event's `created` time.

## Limits

Kiteworks documents its PubSub envelope, one sign-in example and the payload keys. It doesn't publish its syslog formats or a full list of event names. The syslog JSON keys here come from the Cortex XSIAM Kiteworks modeling rule, the event names from Exabeam's Kiteworks parsers, and the plain text line from Hunters' sample and those parsers.

- Kiteworks' PubSub docs show only the login event. The upload and download event names in the samples come from its activity API examples. The Auth child takes any event name containing login or logout, so other sign-in names still land there.
- In plain text, the value in brackets after the user ID isn't documented, so the parsers keep it as `user_label`. The samples' Activity Group values other than file_changes are made up.
- Kiteworks doesn't name its scan events. The Thirdparty child reads the data.malicious, data.prohibited and data.quarantined flags, whatever the event is called, and the scan sample is made up from those keys.
