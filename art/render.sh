#!/usr/bin/env bash
# Renders the README previews from art/mock/*.html with headless Chrome.
# The mocks imitate the Magento admin; they are not screenshots of a running store.
# Set CHROME=/path/to/chrome-headless-shell if it isn't on the PATH.
set -euo pipefail
cd "$(dirname "$0")"

CHROME=${CHROME:-$(command -v chromium || command -v chromium-browser || command -v google-chrome || command -v chrome-headless-shell || true)}
[ -x "$CHROME" ] || { echo "Chrome not found; set CHROME=/path/to/chrome" >&2; exit 1; }

shot() { # name, window size
    "$CHROME" --headless --no-sandbox --hide-scrollbars --allow-file-access-from-files \
        --force-device-scale-factor=2 --window-size="$2" \
        --screenshot="$PWD/$1.png" "file://$PWD/mock/$3.html" 2>/dev/null
    echo "art/$1.png"
}

shot preview-grid 1280,640 grid
shot preview-email 760,640 email
shot preview-config 1280,1000 config
shot banner 1000,500 banner
