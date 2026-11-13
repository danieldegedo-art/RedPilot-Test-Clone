"""RedPilot RP-001 terminal-first console (CLI/TUI).

A dependency-light, terminal-native console in the RedPilot website palette:
  * `theme`    -- the exact `--qa-*` palette as 24-bit ANSI.
  * `model`    -- pure UI state (log ring-buffer, command palette, pane layout).
  * `render`   -- width-correct ANSI screen composition.
  * `commands` -- command registry wiring the console to the real bounded modules.
  * `app`      -- the raw-terminal event loop (+ a non-TTY demo path).

Launch: `python -m app.cli` (interactive) or `python -m app.cli --demo [cmd ...]`.
"""
