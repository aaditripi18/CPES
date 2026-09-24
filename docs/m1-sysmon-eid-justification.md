# M1 Sysmon configuration justification and validation

`configs/sysmon-config-v1.xml` is the frozen M1 Sysmon configuration for the
CPES controlled Windows endpoint. It implements the technique-scoped event
selection fixed by Project Bible §9.6. It is telemetry collection only: it
contains no CPES logic, feature extraction, correlation, scoring, detection,
or ATT&CK attribution.

## Event-ID justification

| Sysmon EID | Configuration tag | Selected-technique justification |
| --- | --- | --- |
| 1 | `ProcessCreate` | All six selected techniques; supplies ProcessGUID-based process identity, parent references, integrity context, and command line. |
| 6 | `DriverLoad` | Optional BYOVD variant of T1543.003 Windows Service. |
| 7 | `ImageLoad` | T1543.003 Windows Service and T1055.001 DLL Injection. |
| 8 | `CreateRemoteThread` | T1055.001 DLL Injection. |
| 10 | `ProcessAccess` | T1134.001 Token Theft and T1055.001 DLL Injection. |
| 11 | `FileCreate` | T1543.003 Windows Service. |
| 12/13 | `RegistryEvent` | T1548.002 Bypass UAC, T1543.003 Windows Service, and T1546.003 WMI Event Subscription. |
| 19/20/21 | `WmiEvent` | T1546.003 WMI Event Subscription. |

`RegistryEvent` can also represent EID 14 rename activity. The v1 include
filter permits only the create/delete and value-set event types associated with
EIDs 12 and 13, so it does not intentionally collect EID 14. Sysmon's own
configuration-change event (EID 16) is not filterable; it is not a CPES
telemetry event selected by §9.6.

## Manual deployment and minimal validation

Use only the approved M0 Windows endpoint and its established collection path.
The operator must have local administrative rights and Sysmon 15.20 available.

1. Inspect the target Sysmon schema with `sysmon64.exe -? config` and confirm it
   accepts the configuration schema before deployment.
2. Apply `configs/sysmon-config-v1.xml` using the Sysmon configuration update
   command appropriate to the approved M0 installation.
3. Confirm Sysmon reports a successful configuration update.
4. During ordinary controlled validation activity, confirm each configured EID
   appears in the Sysmon Operational log when applicable and is visible through
   the approved M0 collection path.
5. Record the deployment date, configuration filename, validation evidence, and
   post-deployment snapshot identifier in the M0 environment record.

No attack execution, Atomic Red Team run, corpus capture, segmentation, or
labeling is part of this milestone. Those activities begin in M2.

## M1 acceptance criteria

- `sysmon-config-v1.xml` is version-controlled and accepted by Sysmon 15.20.
- The explicitly enabled configuration tags correspond only to the §9.6 EID
  set, with RegistryEvent restricted to EIDs 12 and 13.
- Each configured event ID is confirmed emitting when applicable on the
  controlled endpoint and is observable through the approved M0 environment.
- The environment record contains the required deployment and validation facts.
