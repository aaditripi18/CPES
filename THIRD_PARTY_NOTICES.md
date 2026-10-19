# Third-party notices

CPES's own code and documentation are released under the MIT License (see
[LICENSE](LICENSE)).

## Fonts bundled with the dashboard

The full license texts sit next to the font files in
[dashboard/web/public/fonts](dashboard/web/public/fonts) and are served with the
dashboard.

| Font | File | License | Source |
|---|---|---|---|
| Hanken Grotesk | `dashboard/web/public/fonts/hanken-grotesk.woff2` | SIL Open Font License 1.1 ([OFL-HankenGrotesk.txt](dashboard/web/public/fonts/OFL-HankenGrotesk.txt)) | Copyright 2021 The Hanken Grotesk Project Authors, https://github.com/marcologous/hanken-grotesk |
| JetBrains Mono | `dashboard/web/public/fonts/jetbrains-mono.woff2` | SIL Open Font License 1.1 ([OFL-JetBrainsMono.txt](dashboard/web/public/fonts/OFL-JetBrainsMono.txt)) | Copyright 2020 The JetBrains Mono Project Authors, https://github.com/JetBrains/JetBrainsMono |

The fonts are redistributed unmodified apart from format (WOFF2), and are not
sold on their own. Their licenses apply to the font files only.

## Data and rules used in the evaluation (not redistributed)

None of these is stored in this repository. `scripts/fetch_external.py`
downloads each file from its source and verifies it against the SHA-256 pins in
[configs/external-datasets.json](configs/external-datasets.json).

| Input | Used for | License | Source |
|---|---|---|---|
| EVTX-ATTACK-SAMPLES, *Privilege Escalation* folder @ `4ceed2f` | external evaluation, dashboard example datasets | GPL-3.0 | Samir Bousseaden, https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES |
| OTRF Security-Datasets, `atomic/windows` @ `d9d40ef` | held-out and test captures | MIT | Open Threat Research Forge, https://github.com/OTRF/Security-Datasets |
| SigmaHQ rules, release `r2026-07-01` | comparison and incident correlation | Detection Rule License 1.1 | SigmaHQ, https://github.com/SigmaHQ/sigma |

Rule titles shown in the dashboard and in `results/` come from the SigmaHQ
rules and remain under the Detection Rule License.
