#!/usr/bin/env bash
set -euo pipefail

# Get the current session name (accept optional argument, fallback to 'fuzzer')
SESSION="${1:-$(tmux display-message -p '#S' 2>/dev/null || echo "fuzzer")}"
# List of common shells to identify "idle" panes
SHELLS_REGEX="^(bash|zsh|fish|sh|ksh|csh|dash)$"

tmux has-session -t "$SESSION" 2>/dev/null || exit 0

echo "Sending Ctrl-C to all panes in session: $SESSION..."

# 1. Send Ctrl+C to all live panes in the current session
while IFS=' ' read -r dead pane_id; do
  if [ "$dead" = "0" ] && [ -n "$pane_id" ]; then
    tmux send-keys -t "$pane_id" C-c 2>/dev/null || true
  fi
done < <(tmux list-panes -s -t "$SESSION" -F "#{pane_dead} #{pane_id}" 2>/dev/null || true)

echo "Waiting for processes to exit..."

# 2. Wait loop
TIMEOUT="${KILL_TIMEOUT:-10}" # Max wait time in seconds (optional safety net)
MAX_TICKS=$(( TIMEOUT * 2 ))
TICKS=0

while (( TICKS < MAX_TICKS )); do
  BUSY_PANES=0

  # Iterate over all panes to check if they are busy
  # format: pane_dead, pane_pid, pane_current_command
  while IFS=' ' read -r dead pid cmd; do
    # Exited panes left open by remain-on-exit are no longer running
    if [ "$dead" != "0" ] || [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
      continue
    fi

    # Check if the command running is a shell
    if [[ "$cmd" =~ $SHELLS_REGEX ]]; then
      # It's a shell. Check if it has child processes (foreground jobs).
      # pgrep -P $pid returns child PIDs. If output is not empty, shell is busy.
      if pgrep -P "$pid" > /dev/null; then
        BUSY_PANES=$((BUSY_PANES + 1))
      fi
    else
      # It's not a shell (e.g., vim, top, afl-fuzz, ruby running directly).
      # Pane is alive and not exited yet, so it is busy.
      BUSY_PANES=$((BUSY_PANES + 1))
    fi
  done < <(tmux list-panes -s -t "$SESSION" -F "#{pane_dead} #{pane_pid} #{pane_current_command}" 2>/dev/null || true)

  if (( BUSY_PANES == 0 )); then
    echo "All panes are idle. Killing session."
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    exit 0
  fi

  sleep 0.5
  TICKS=$((TICKS + 1))
done

# 3. Force kill if timeout reached
echo "Timeout reached. Force killing session."
tmux kill-session -t "$SESSION" 2>/dev/null || true
