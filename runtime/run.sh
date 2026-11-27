#!/usr/bin/env bash
set -euo pipefail

if [ -n "${FUZZ_DEBUG_RUN:-}" ]; then
    set -x
fi

paths_env=$(ruby ./bin/topology.rb paths --relative --shell) || exit $?
while IFS= read -r -d '' k && IFS= read -r -d '' v; do
    if [[ "$k" =~ ^WORKSPACE_[A-Z0-9_]+$ ]]; then
        printf -v "$k" '%s' "$v"
    fi
done < <(ruby -rshellwords -e '
  ARGV[0].to_s.each_line do |line|
    line = line.chomp
    next if line.empty?
    key, raw_val = line.split("=", 2)
    abort "run.sh: invalid paths line: #{line.inspect}" unless key&.match?(/\AWORKSPACE_[A-Z0-9_]+\z/)
    tokens = Shellwords.split(raw_val.to_s)
    abort "run.sh: unexpected multi-token path for #{key}: #{raw_val.inspect}" if tokens.size > 1
    $stdout.write("#{key}\0#{tokens.empty? ? "" : tokens[0]}\0")
  end
' "$paths_env")
wait "$!" || exit $?
AFL_DIR=${1:-${WORKSPACE_AFL_DIR:-./tmp/fuzz/afl}}
CORPUS_DIR=${2:-${WORKSPACE_CORPUS_DIR:-./tmp/fuzz/corpus}}
BUILD_DIR=${FUZZ_BUILD_DIR:-${WORKSPACE_BUILD_DIR:-./tmp/fuzz/build}}
if [ -n "${1:-}" ]; then
    FUZZ_DIR=${FUZZ_DIR:-$(dirname "$1")}
    LOGS_DIR="$FUZZ_DIR/logs"
    SEEDS_BACKUP_DIR="$FUZZ_DIR/seeds"
    BIN_DIR="$FUZZ_DIR/bin"
    SNAPSHOT_DIR="$FUZZ_DIR/snapshot"
else
    FUZZ_DIR=${FUZZ_DIR:-${WORKSPACE_DIR:-$(dirname "$AFL_DIR")}}
    LOGS_DIR="${WORKSPACE_LOGS_DIR:-$FUZZ_DIR/logs}"
    SEEDS_BACKUP_DIR="${WORKSPACE_SEEDS_DIR:-$FUZZ_DIR/seeds}"
    BIN_DIR="${WORKSPACE_BIN_DIR:-$FUZZ_DIR/bin}"
    SNAPSHOT_DIR="${WORKSPACE_SNAPSHOT_DIR:-$FUZZ_DIR/snapshot}"
fi
WORKER_LOGS_DIR="$LOGS_DIR/workers"
RUN_LOG="$LOGS_DIR/run.log"
SESSION="fuzzer"
KILL_SH="./runtime/kill.sh"
STATUS_RB="./runtime/status.rb"
TOPOLOGY_RB="./bin/topology.rb"

mkdir -p "$AFL_DIR" "$LOGS_DIR" "$WORKER_LOGS_DIR"
if [ -n "${FUZZ_DAEMON:-}" ] || [ ! -t 1 ]; then
    printf '# [%s] Campaign container run.sh starting\n' "$(date -u +%FT%TZ)" > "$RUN_LOG"
    exec > >(tee -a "$RUN_LOG") 2>&1
fi

cleanup() {
    local -i rc=$?
    local reason=${1:-EXIT}
    trap '' TERM INT
    trap - EXIT
    rm -f /tmp/.fuzzer.tmux.ready "${LAUNCH_JSON:-}"
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        bash "$KILL_SH" "$SESSION" || true
    fi
    rm -rf "$SEEDS_BACKUP_DIR"
    if [ -n "${GEN_SEEDS_MAP:-}" ] || [ -n "${GEN_SEEDS_DIRS:-}" ]; then
        ruby -rfileutils -rjson -e '
          dst = ARGV[0]
          raw = ARGV[1].to_s
          parsed = raw.empty? ? nil : JSON.parse(raw)
          if parsed.is_a?(Hash) && !parsed.empty?
            parsed.each do |gid, src|
              gid_s = gid.to_s
              next if gid_s.empty? || gid_s.include?("/") || gid_s == "." || gid_s == ".." || !Dir.exist?(src.to_s)
              unread = []
              Dir.children(src).each do |f|
                next if f.start_with?(".")
                p = File.join(src, f)
                st = begin
                  File.stat(p)
                rescue SystemCallError
                  next
                end
                unread << p if st.file? && (st.atime.to_i <= 1 || st.atime == st.mtime)
                break if unread.size >= 5000
              end
              next if unread.empty?
              gen_dst = File.join(dst, gid_s)
              FileUtils.mkdir_p(gen_dst)
              unread.each_with_index { |p, idx| FileUtils.cp(p, File.join(gen_dst, "#{idx}_#{File.basename(p)}")) }
            end
          else
            dirs = JSON.parse(ARGV[2].to_s.empty? ? "[]" : ARGV[2])
            unread = []
            dirs.each do |src|
              next unless Dir.exist?(src)
              Dir.children(src).each do |f|
                next if f.start_with?(".")
                p = File.join(src, f)
                st = begin
                  File.stat(p)
                rescue SystemCallError
                  next
                end
                unread << p if st.file? && (st.atime.to_i <= 1 || st.atime == st.mtime)
                break if unread.size >= 5000
              end
              break if unread.size >= 5000
            end
            if unread.any?
              FileUtils.mkdir_p(dst)
              unread.each_with_index { |p, idx| FileUtils.cp(p, File.join(dst, "#{idx}_#{File.basename(p)}")) }
            end
          end
        ' "$SEEDS_BACKUP_DIR" "${GEN_SEEDS_MAP:-}" "${GEN_SEEDS_DIRS:-}" || true
    fi
    case "$reason" in
        TERM|INT) exit 0 ;;
        *) exit "$rc" ;;
    esac
}

mkdir -p "$AFL_DIR"

# Snapshot compiled fuzzer binaries and script/lib/harness dependencies into
# $BIN_DIR and $SNAPSHOT_DIR so later edits to harnesses/, triage/, or $BUILD_DIR
# do not impact a currently running fuzz campaign or its initial triage.
ruby ./runtime/provenance.rb snapshot "$BUILD_DIR" "$BIN_DIR" "$SNAPSHOT_DIR" || exit 1
if [ -e "$SNAPSHOT_DIR/runtime/kill.sh" ]; then
    KILL_SH="$SNAPSHOT_DIR/runtime/kill.sh"
fi
if [ -f "$SNAPSHOT_DIR/runtime/status.rb" ]; then
    STATUS_RB="$SNAPSHOT_DIR/runtime/status.rb"
fi
if [ -f "$SNAPSHOT_DIR/bin/topology.rb" ]; then
    TOPOLOGY_RB="$SNAPSHOT_DIR/bin/topology.rb"
fi

export AFL_AUTORESUME=1
export AFL_FUZZER_STATS_UPDATE_INTERVAL=1
export AFL_FUZZER_LOOPCOUNT=10000
export AFL_SYNC_TIME="${AFL_SYNC_TIME:-5}"

# --- Trap Signals ---
# Trap SIGINT (Ctrl+C) and SIGTERM (docker stop)
trap 'cleanup TERM' TERM
trap 'cleanup INT' INT
trap 'cleanup EXIT' EXIT

LAUNCH_JSON="$FUZZ_DIR/.launch.plan.json"
ruby "$TOPOLOGY_RB" plan-launch --build-dir "$BUILD_DIR" --fuzz-dir "$FUZZ_DIR" --corpus-dir "$CORPUS_DIR" --bin-dir "$BIN_DIR" > "$LAUNCH_JSON" || exit $?

PRIMARY_AFL_DIR="$(ruby -rjson -e 'puts JSON.parse(File.read(ARGV[0])).fetch("primary_afl_dir")' "$LAUNCH_JSON")" || exit $?
GEN_SEEDS_DIRS="$(ruby -rjson -e 'puts JSON.generate(JSON.parse(File.read(ARGV[0])).fetch("generator_seeds_dirs", []))' "$LAUNCH_JSON")" || exit $?
GEN_SEEDS_MAP="$(ruby -rjson -e 'puts JSON.generate(JSON.parse(File.read(ARGV[0])).fetch("generator_seeds_map", {}))' "$LAUNCH_JSON")" || exit $?

mapfile -t WORKER_NAMES < <(ruby -rjson -e 'JSON.parse(File.read(ARGV[0])).fetch("workers").each { |w| puts w.fetch("id") }' "$LAUNCH_JSON")
wait "$!" || exit $?
mapfile -t WORKER_CMDS < <(ruby -rjson -e 'JSON.parse(File.read(ARGV[0])).fetch("workers").each { |w| puts w.fetch("cmd") }' "$LAUNCH_JSON")
wait "$!" || exit $?
rm -f "$LAUNCH_JSON"

if (( ${#WORKER_NAMES[@]} == 0 )); then
    echo "run.sh: topology produced zero active workers" >&2
    exit 1
fi

echo "Starting tmux session with ${#WORKER_NAMES[@]} fuzzer workers..."

if [ -n "${TERM:-}" ]; then
    export TERM="xterm-256color"
fi

rm -f /tmp/.fuzzer.tmux.ready

# Window 0: Fleet status dashboard
printf -v dash_cmd 'ruby %q %q' "$STATUS_RB" "$PRIMARY_AFL_DIR"
for w in "${WORKER_NAMES[@]}"; do
    printf -v w_q ' %q' "$w"
    dash_cmd+="$w_q"
done
tmux -2 new-session -d -s "$SESSION" -n "dashboard" "$dash_cmd"
tmux set-option -g default-terminal "tmux-256color"
tmux set-option -g remain-on-exit on

# Windows 1..N: One window per worker declared by topology.json
for (( i = 0; i < ${#WORKER_NAMES[@]}; i++ )); do
    wname="${WORKER_NAMES[$i]}"
    wcmd="${WORKER_CMDS[$i]}"
    wlog="$WORKER_LOGS_DIR/$wname.log"
    printf '# [%s] worker=%s cmd=%s\n' "$(date -u +%FT%TZ)" "$wname" "$wcmd" > "$wlog"
    pane_id=$(tmux new-window -P -F '#{pane_id}' -d -t "$SESSION" -n "$wname" "$wcmd") || exit $?
    printf -v wlog_q '%q' "$wlog"
    if ! tmux pipe-pane -o -t "$pane_id" "cat >> $wlog_q"; then
        tmux capture-pane -p -J -t "$pane_id" >> "$wlog" 2>/dev/null || true
        echo "Error: Worker '$wname' exited immediately during startup:" >&2
        tail -n 30 "$wlog" >&2 || true
        exit 1
    fi
done

tmux select-window -t "$SESSION:0"
kill_sh_sh="'${KILL_SH//\'/\'\\\'\'}'"
kill_cmd="bash $kill_sh_sh"
kill_cmd="${kill_cmd//\\/\\\\}"
kill_cmd="${kill_cmd//\"/\\\"}"
tmux bind-key -n C-c confirm-before -p "Stop all fuzzers and exit? (y/n) [Tip: press Ctrl+B then d to detach]" "run-shell \"$kill_cmd\""
: > /tmp/.fuzzer.tmux.ready

echo "Fuzzers started."

if [ -t 0 ] && [ -t 1 ] && [ -z "${FUZZ_DAEMON:-}" ]; then
    echo "Attaching to dashboard (Window 0)."
    tmux -2 attach-session -t "$SESSION"
else
    echo "Running in daemon mode. Attach with: docker exec -it \${CONTAINER} tmux -2 attach-session -t $SESSION"
fi

while tmux has-session -t "$SESSION" 2>/dev/null; do
    sleep 1 &
    wait $!
done

exit 0
