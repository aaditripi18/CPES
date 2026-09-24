# M0 validation checklist

Complete this checklist on the controlled Windows 11 lab VM. M0 is complete
only when each applicable item is recorded in the environment record.

- [ ] Exact Windows 11 build is recorded.
- [ ] Elasticsearch 9.4.3 is running.
- [ ] Kibana 9.4.3 is reachable (optional visualization component).
- [ ] Winlogbeat 9.4.3 is configured to ship Windows event logs.
- [ ] Sysmon 15.20 is installed; M1 configuration deployment remains pending.
- [ ] A harmless test event is visible in Elasticsearch after ingestion.
- [ ] The Python 3.12 environment installs `requirements.txt` successfully.
- [ ] The `cpes` package imports successfully.
- [ ] The VM snapshot identifier is recorded after the preceding checks pass.

## Validation result

Record the date, operator, test-event reference, and snapshot identifier in
the environment record. Any failed item blocks M1 until resolved.
