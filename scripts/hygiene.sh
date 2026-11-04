#!/bin/sh
# Repository hygiene checks that complement scripts/secret-scan.sh.
#   hygiene.sh --msg FILE    reject a commit message with a trailer or a tool signature (commit-msg hook)
#   hygiene.sh --tree        scan every tracked file for tool signatures and personal paths
#   hygiene.sh --history     check the message and the identity of every commit reachable from HEAD
# Exit status: 0 clean, 1 findings, 2 usage error.
set -eu

mode=${1:-}
case "$mode" in --msg|--tree|--history) ;; *) echo "usage: hygiene.sh --msg FILE|--tree|--history" >&2; exit 2 ;; esac

owner_name='kienpt'
owner_mail='kienphan.dev@gmail.com'

# The words are assembled from pieces so that this file does not match its own patterns.
vendors='cla''ude|anth''ropic|open''ai|chat''gpt|gpt-[0-9]|co''pilot|co''dex|gem''ini|cur''sor|aider|windsurf'
signatures='co-authored-by|signed-off-by|generated (by|with|using)|written (by|with) (an? )?(ai|llm|bot)|ai-generated'
message_re="($vendors|$signatures)"
# a home directory of the owner or of a build machine must not leak into the tree
paths_re='/(Users|home)/[a-z][a-z0-9._-]*/(workspace|projects|work)'

found=0
report() { printf 'hygiene: %s: %s\n' "$1" "$2" >&2; found=1; }

check_message() { # label, text
  if printf '%s\n' "$2" | grep -E -i -q -e "$message_re"; then report "$1" "message contains a trailer or a tool signature"; fi
}

case "$mode" in
  --msg)
    file=${2:?usage: hygiene.sh --msg FILE}
    check_message "commit message" "$(grep -v '^#' "$file")"
    ;;
  --tree)
    for f in $(git ls-files); do
      [ "$f" = scripts/hygiene.sh ] && continue
      [ "$f" = Cargo.lock ] && continue
      if git grep -I -n -E -i -q -e "$message_re" -- "$f"; then
        report "$f" "contains a tool name or signature"
      fi
      if git grep -I -n -E -q -e "$paths_re" -- "$f"; then
        report "$f" "contains a home directory path"
      fi
    done
    ;;
  --history)
    for c in $(git rev-list HEAD); do
      short=$(printf '%.8s' "$c")
      check_message "commit $short" "$(git log -1 --format=%B "$c")"
      ident=$(git log -1 --format='%an <%ae> | %cn <%ce>' "$c")
      expected="$owner_name <$owner_mail> | $owner_name <$owner_mail>"
      [ "$ident" = "$expected" ] || report "commit $short" "author or committer is not $owner_name <$owner_mail>"
    done
    ;;
esac

if [ "$found" -ne 0 ]; then exit 1; fi
echo "hygiene: clean ($mode)"
