# Set up Ransomware containment chain without Microsoft 365

A template carries no trigger, connections or settings, so you set them up once in your tenant. The playbook ships with dry run on and stays off until you turn it on.

This is [Ransomware containment chain](../ransomware-containment-chain/) without its Microsoft 365 user step and without Ask for approval first, so it needs no Microsoft Graph API connection: Sophos Fusion won't save a configured playbook without a connection for every connector its template lists. Approval before acting needs that connection too, so to hold isolation for an approval, use the Microsoft 365 version.

## 1. The connections

Under Security Operations > Automations > Connectors:

- **Sophos Endpoint (Taegis.SophosEndpoint), Sophos Case (Taegis.Case) and Sophos Detection (Taegis.Alert).** They sign in as the platform and need no credential. A tenant with Sophos Endpoint devices usually has the Sophos Endpoint connection already; add any that's missing from the Connector Library.
- **A chat connection for paging:** Microsoft Teams (a Workflows webhook URL), Slack (an incoming webhook URL) or Google Chat (a space webhook URL). Use Test on it.

Forensic logs go to the AWS S3 bucket set up for forensic snapshots, under Global Settings > Products and Services > Endpoint and Server > Forensic Snapshots, as [Forensic snapshots](https://docs.sophos.com/fusion/customer/help/en-us/index.html?contextId=forensic-snapshot) explains. Without a bucket Sophos refuses the request with "Upload disabled", so turn off Collect forensic logs until you have one.

## 2. Import the template

Under Security Operations > Automations > Playbooks > Templates, choose Import and pick `template.yaml`.

## 3. Configure the playbook

On the template, choose Use this Template. Pick one trigger per configured playbook; to use both, configure the template twice.

- **Trigger, from a detection:** Platform Events, source Alert2, event create, with When does this playbook run? set to Only When:

  ```
  detectionSeverityNice(inputs) == 'Critical' && (['ransom', 'cryptoguard', 'hands-on-keyboard', 'hands on keyboard'].exists(t, detectionTitle(inputs).lowerAscii().contains(t)) || detectionAttackTechniqueIds(inputs).exists(t, t in ['T1486', 'T1490']))
  ```

  Change both this filter and Detection titles to match the titles on your Detections page. Detection triggers only run for high and critical detections.
- **Trigger, by hand:** User Initiated, a Response Action on Case. It acts on the case's detections at or above Minimum severity.
- **Connections:** the Sophos Endpoint, Case and Detection connections.
- **Send Notification Message Interface:** pick Send Notification Message Microsoft Teams, Salesforce Slack or Google Workspace Chat, and your chat connection. Add more than one to page each.
- **Excluded devices:** domain controllers you'd isolate by hand and anything else it must never touch.
- **Steps:** every step is on except Isolate servers. Turn off any step you don't want.
- **Max devices per run, Max group devices, Max file hashes per run:** 3, 50 and 3. A run over a limit skips that step and says so.
- **Never block:** add the programs your business runs. A detection that names one, or a file under Windows\System32 or SysWOW64, never has its hashes blocked: it often carries the hash of the program the attacker ran.
- **Dry run:** leave it on.
- **Version:** pin the template version. A configured playbook picks up minor and patch template versions on its own, so pin it to stop a library update from changing what runs.

Save it and leave it off.

## 4. Test it

1. Turn the playbook on with dry run still on.
2. Run it by hand from a test case whose detection names a test device, or wait for a detection.
3. Read the timeline on the case and the page in your channel. Both say what it would do.
4. Turn off dry run when the timeline says what you expect.

## Rollback

Release a device with Restore Host. Turn Adaptive Attack Protection off on the device, or let it expire after 24 hours. Remove a blocked hash from Blocked Items in Global Settings; the timeline names each one. To stop the automation, turn off the playbook.
