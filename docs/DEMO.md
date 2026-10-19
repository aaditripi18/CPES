# CPES in five minutes — demo script

A walkthrough that uses **public data only** (three [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
captures shipped as built-in datasets), so it can be recorded or shown without
the private lab corpus. Every number on screen is computed live by the
unchanged `cpes` package; the outcomes below are what the current code
produces, including the miss.

## Setup (once)

```powershell
pip install -r requirements.txt -r dashboard/requirements.txt
python scripts/fetch_external.py          # public samples + SigmaHQ rules, SHA-256 verified
cd dashboard/web; npm ci; npm run build; cd ../..
python dashboard/run_server.py            # http://127.0.0.1:8790
```

Or with Docker. The image contains no third-party or private data; mount the
downloaded public data read-only (run `scripts/fetch_external.py` on the host first):

```powershell
docker build -t cpes-dashboard .
docker run --rm -p 127.0.0.1:8790:8790 -v "${PWD}/external:/app/external:ro" cpes-dashboard
```

## Script

| # | Screen | Do | Say |
|---|---|---|---|
| 1 | **Overview** | Open the dashboard. | "CPES scores privilege escalation over the whole process chain, not one event. Everything here is computed by the research package; the dashboard adds no scoring of its own." |
| 2 | **Datasets → Public sample: UAC bypass via eventvwr.exe** | Open it, show validation (every record mapped or rejected with a reason), then **Start run** with *Also run SigmaHQ core rules* ticked. | "Raw Windows event log in, validated record by record." |
| 3 | **Run → Incidents** | Open `INC-0001`. | "One incident. Sigma saw the attacker's PowerShell touching the Event Viewer hijack key; CPES names the process that *gained* privilege, `eventvwr.exe` at High integrity, and its resolver links it back to that registry write. The ATT&CK tags and the ECS alert export come from the same record." |
| 4 | **Report (.md)** · **ATT&CK layer** · **ECS alerts** | Click each download; optionally drop the layer into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). | "Hand-off formats an analyst or a SIEM can use directly." |
| 5 | **Lineage** | From the incident, click *lineage* on the outcome process. | "The reconstructed process tree; parents missing from the telemetry are drawn as placeholders, never guessed." |
| 6 | **Public sample: RoguePotato** → run with Sigma → **Incidents** | Open the critical incident. | "Token impersonation. CPES has no RoguePotato rule, yet its structural service test fires: a SYSTEM process running from a user-writable path. Note the caveat on screen: the ATT&CK tag is what the *signal* was designed for, not a verified attribution." |
| 7 | **Public sample: UACME method 56 (WSReset)** → run with Sigma → **Incidents** | Show that every incident says *CPES did not flag an elevated process*. | "An honest miss: this binary is not on CPES's auto-elevation list, so CPES stays silent and only Sigma alerts. Our evasion test measured exactly this (33/33 → 0/33), and the generic 'unexplained privilege gain' test is the planned answer." |
| 8 | **Evaluation** | Show the protocols table and a ledger entry. | "Every result is a protocol written down before it ran, with the code fingerprint and input hashes recorded. Held-out test: the v2 model did *not* improve, so it was not adopted." |
| 9 | **Live** | Replay a dataset at max speed. | "The same engine streaming: windows are scored as they close, and live alerts matched the hindsight result 160/160 on the lab corpus." |

## Recording tips

* 1280×800 window, browser zoom 100%; the sidebar fits without scrolling.
* For a GIF, steps 2–4 alone (about 40 s) carry the main idea.
* Do not record the lab-corpus datasets (`lab-corpus-*`): they contain lab host
  identifiers and are private. The public samples carry only their original
  public identifiers.
