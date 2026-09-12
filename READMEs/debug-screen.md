# Independent X11 screenshots

`virtuoso-bridge screenshot` uses SKILL and requires a responsive CIW.
For blocked forms, use the independent SSH/X11 commands:

```sh
virtuoso-bridge screen -p v231 -o desktop.png
virtuoso-bridge list-windows -p v231
virtuoso-bridge screen -p v231 --window-id 0x123456 -o form.png
```

Use a window id returned by `list-windows`. Window capture includes the frame,
does not activate the window, and rejects unmapped or ambiguous targets. The
desktop backend requires `gnome-screenshot`; the window backend requires system
Python with PyGTK2. Both use the interactive Virtuoso process's DISPLAY and
XAUTHORITY. Capture children drop EDA LD_LIBRARY_PATH/LD_PRELOAD overrides.
Existing output files are never overwritten. JSON results report
`skill_executed: false`; capture does not start or restart the daemon.

For stable remote scratch paths across interactive and service accounts, set
`VB_CLIENT_ID_<profile>` in the local Bridge environment. Request status can
read the recorded previous setup's ledger when the current path is inaccessible;
`ledger_source_path` identifies the actual file used. This diagnostic fallback
does not establish completion: request reconciliation still validates the exact
request identity and terminal proof.
