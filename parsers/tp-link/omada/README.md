# TP-Link Omada to Sophos NG-SIEM

TP-Link Omada controllers (software, hardware such as the OC200 and OC300, and cloud-based) keep event, alert and audit logs for the controller, the MSP view and each site. The controller's syslog output has no published format, and its webhook sends only the log text and can't add the `Authorization` header HTTP Ingest needs, so the logs are read through the Omada Open API by the example bridge in `bridges/tp-link-omada-logs`, which posts each record to HTTP Ingest as a JSON line. These parsers read those lines.

## Send the logs

1. In Sophos Fusion, set up an HTTP Ingest integration (Security Operations > Integrations > Marketplace, Custom, HTTP Ingest) and copy its URL and key.
2. In Omada, add an Open API application in client mode, with a role that can only view and access to the sites (and, for an MSP, the customers) to read.
3. Run the bridge, as its README describes.

## Add the parsers

Add the parent first, then each child with the parent as its parent parser:

| Parser | Records |
| --- | --- |
| `TPLINK_OMADA_JSON_PARENT` | Every record the bridge sends; events and alerts with other keys stay generic |
| `TPLINK_OMADA_JSON_CHILD_AUTH` | Controller and hotspot operator sign-ins, portal and 802.1X authentication, and remote PPTP and L2TP clients (`LOGIN_OK`, `LOGIN_FL`, `HS_LOGIN_OK`, `HS_LOGIN_FL`, `W_C_PRT_OK`, `W_C_PRT_FL`, `L_C_PTR_OK`, `L_C_PTR_FL`, `OSW_C_1X_OK`, `OSW_C_1X_FL`, `OSG_RC_VPN_OK`, `OSG_RC_VPN_FL`, `OSG_RC_VPN_LO`) to Auth |
| `TPLINK_OMADA_JSON_CHILD_THIRDPARTYALERT` | Gateway attack detections and rogue DHCP servers (`OSG_ATK`, `OSG_SF_ATK`, `OSG_ARP_ATK`, `OSG_LARGE_PING_ATTACK`, `OSG_ROGUE_DHCP_SERVER_DETECTED`) to Thirdparty |
| `TPLINK_OMADA_JSON_CHILD_MGMT` | Every audit log to Management Event |

Use Run Test with your own records before you turn the parsers on.
