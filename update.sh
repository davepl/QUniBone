#!/usr/bin/env bash
set -euo pipefail

REMOTE="ubvmstor01:~/source/repos/Quinibone/"
DEST="$HOME/"

rsync -avz --prune-empty-dirs \
  --include '*/' \
  --include '*/02_src/***' \
  --exclude '*' \
  "$REMOTE" "$DEST"
  