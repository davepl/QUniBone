#!/usr/bin/env bash
set -euo pipefail

REMOTE="dave@ubvmstor01:~/source/repos/QUniBone/"
DEST="$HOME/"

rsync -avz --prune-empty-dirs \
  --exclude ".git" \
  --exclude "update.sh" \
  --include '*/' \
  --include '*/02_src/***' \
  "$REMOTE" "$DEST"