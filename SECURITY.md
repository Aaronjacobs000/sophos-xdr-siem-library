# Security policy

The Unofficial Sophos Fusion XDR and SIEM Library, Parser Studio included, is a personal project, not a Sophos product. Report a problem in Sophos NG-SIEM, Sophos Fusion or any other Sophos product to Sophos, as its [responsible disclosure policy](https://www.sophos.com/en-us/legal/sophos-responsible-disclosure-policy) describes.

## Report a vulnerability

Report it privately: open this repository's **Security** tab and choose **Report a vulnerability**. Don't put it in a public issue or pull request.

Say what is affected, how to reproduce it, and what someone could do with it. The reply comes in the private report.

## In scope

- The site: https://aaronjacobs000.github.io/sophos-xdr-siem-library/, Parser Studio included, and the code under `studio/`.
- The library gate and workflows: the checks and merge rules under `tools/`, and the workflows under `.github/workflows/` that check and merge library submissions.
- The playbooks and connectors under `playbooks/` and `connectors/`, and the host allowlist they're checked against.
- The bridges: the scripts and the webhook relay under `bridges/`.

Fixes go to the main branch and the live site. There are no releases to patch.
