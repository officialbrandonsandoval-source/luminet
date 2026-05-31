#!/usr/bin/env osascript
-- Open the macOS Internet Sharing settings pane.
-- This script does not click or change settings. It only opens the right place.

tell application "System Settings"
    activate
    reveal pane id "com.apple.Sharing-Settings.extension"
end tell

delay 1

tell application "System Events"
    tell process "System Settings"
        set frontmost to true
    end tell
end tell
