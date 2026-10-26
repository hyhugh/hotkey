
A simple windows cli util that adds global hotkeys that toggles the visibility of a window.


sample config has been provided in `sample_config.toml`

For single-instance tray apps such as Telegram, set `activate_via_exe = true`.
The shortcut minimizes the active main window; otherwise it runs the existing
process's executable without arguments so the app restores itself, including
after closing to the tray. Only enable this for apps whose launcher activates
the existing instance. The default is `false`, which uses native window APIs.
