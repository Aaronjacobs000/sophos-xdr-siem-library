# BeyondTrust Password Safe to Sophos NG-SIEM

BeyondInsight forwards Password Safe events (password requests, approvals and retrievals, sessions, account and system changes, and password changes) through its event forwarder connectors. This parser reads them in LEEF once they reach the Sophos NG-SIEM data collector over syslog.

## Send the events

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. In BeyondInsight, go to Configuration > General > Connectors and choose Create New Connector.
3. Name it, set Connector Type to IBM QRadar, and choose Create Connector. That connector sends LEEF.
4. Leave Active (yes) on. Under Available Output Pipelines pick TCP, TCP-SSL or UDP, and enter the data collector's host name and port.
5. Set the formatter to LEEF Format V1.
6. Under Event Filters, select Password Safe.
7. Choose Test Connector, then Create Connector.

Password Safe Cloud has the same connectors. Pick a Resource Zone on the connector to send through that zone's Resource Brokers.

Avoid the SNMP/Syslog connector's default newline-delimited format: it spreads one event over many lines.

## Add the parser

In Sophos Fusion, go to Security Operations > Integrations > Custom Parsers, choose Add Custom Parser and paste `BEYONDTRUST_PASSWORDSAFE_LEEF_STANDALONE_CLOUDAUDIT`. Use Run Test with your own lines before you turn it on.

## What you get

Each Password Safe event (agent `pbps`) goes to CloudAudit:

- The event name is the object type and the operation, such as Password Retrieve or Functional Account Add, and Password Change for a password change record. The event type is the category, System or Change.
- The user and user ID, the address in `IPAddress` as the source, the asset and the account from `Target` (such as `Asset:db01.example.com MAccount:sa`) as the target host and user, or `AccountName` on a password change.
- The status is failed when `Failed` is True or `Result` is F, with the comment or details as the error message.
- Retrievals, reads, views and downloads are read-only. Changes to accounts, systems and settings, and password changes, are management events; requests, approvals and sessions are not.
- The object, managed account and managed system IDs go to `resources`. The role, object type, operation, target, details, request and release IDs, change reason (with BeyondTrust's meaning for its letter), comment, workgroup and next change date go to `additional_event_data`.
- The event time comes from `devTime`, which is UTC, else `LogTime`.

Other BeyondInsight events, such as application audit logins (agent `appaudit`) and Discovery Scanner events, aren't read.

## Limits

BeyondTrust documents its LEEF layout with a Discovery Scanner event and lists the Password Safe keys in its QRadar connector and event forwarder field tables, but shows no Password Safe line. The line layout in `samples.log` puts those keys after the common LEEF keys, so it is inferred. The documented examples of object types and operations are only Functional Account, System and Session, and Add, Update and Approve; the other values in the samples (Release Request, Password, Retrieve) are made up. BeyondTrust's severity for Password Safe events has been inverted in some releases, so the parser reads the outcome from `Failed` and `Result`, not `sev`.
