#!/usr/bin/env bash
# Preventive leak guard, run by the .githooks/ hooks
# (enable with: git config core.hooksPath .githooks).
#
# Blocks tenant references before they leave the working machine; the ci.yml
# leak-guard job is the server-side backstop for anything that slips past
# (e.g. a push made with --no-verify).
#
# The pattern list is deliberately NOT in this repo — shipping it would leak
# the very strings it protects. It lives at ~/.config/iamkit/leak-patterns.txt
# (override with IAMKIT_LEAK_PATTERNS), one extended regex per line.
# Matched content is never echoed; only offending paths are.
set -euo pipefail

PATTERNS="${IAMKIT_LEAK_PATTERNS:-$HOME/.config/iamkit/leak-patterns.txt}"
ALLOWED_AUTHORS="$(git rev-parse --show-toplevel)/.github/leak-allowed-authors.txt"

# Whole files allowed to reference the public org identity, same set as ci.yml.
allowed_path() {
  case "$1" in
    LICENSE|README.md|.github/leak-allowed-authors.txt) return 0 ;;
    *) return 1 ;;
  esac
}

# Outside contributors never have the pattern list, so a missing file cannot
# block them: warn loudly and pass — the CI leak-guard job scans every push
# and PR with the real list. Maintainers seeing this warning have a
# misconfigured clone and should restore the file before pushing.
[ -r "$PATTERNS" ] || {
  echo "leak-guard: pattern file missing: $PATTERNS" >&2
  echo "leak-guard: continuing UNSCANNED — CI remains the backstop." >&2
  echo "leak-guard: maintainers: restore the file (one regex per line) or" >&2
  echo "leak-guard: point IAMKIT_LEAK_PATTERNS at it before pushing." >&2
  exit 0
}

bad=0
flag() { echo "leak-guard: pattern match in $1" >&2; bad=1; }

scan_ident() {
  local author committer pair
  author=$(git var GIT_AUTHOR_IDENT | sed 's/ [0-9][0-9]* [+-][0-9][0-9]*$//')
  committer=$(git var GIT_COMMITTER_IDENT | sed 's/ [0-9][0-9]* [+-][0-9][0-9]*$//')
  pair="$author $committer"
  if grep -qiE -f "$PATTERNS" <<<"$pair" \
      && ! grep -qxiE -f "$ALLOWED_AUTHORS" <<<"$pair"; then
    flag "git identity '$pair' — set this repo's user.name/user.email to the sanctioned OSS identity"
  fi
}

scan_staged() {
  local path
  while IFS= read -r path; do
    allowed_path "$path" && continue
    if git show ":$path" | grep -qiE -f "$PATTERNS"; then
      flag "staged file $path"
    fi
  done < <(git diff --cached --name-only --diff-filter=ACMR)
}

scan_range() { # $1 = rev range or single rev
  local sha path
  while read -r sha path; do
    [ -n "$path" ] || continue
    allowed_path "$path" && continue
    [ "$(git cat-file -t "$sha")" = blob ] || continue
    if git cat-file -p "$sha" | grep -qiE -f "$PATTERNS"; then
      flag "$path (blob $sha)"
    fi
  done < <(git rev-list --objects "$1")
  # Author, committer, and message of every outgoing commit.
  if git log --format='%an <%ae> %cn <%ce>%n%s%n%b' "$1" \
      | grep -iE -f "$PATTERNS" \
      | grep -qvxiE -f "$ALLOWED_AUTHORS"; then
    flag "commit metadata (author/committer/message) in $1"
  fi
}

case "${1:?usage: leak-guard.sh pre-commit|commit-msg <file>|pre-push}" in
  pre-commit)
    scan_ident
    scan_staged
    ;;
  commit-msg)
    if grep -qiE -f "$PATTERNS" "${2:?commit-msg mode needs the message file}"; then
      flag "commit message"
    fi
    ;;
  pre-push)
    zero=0000000000000000000000000000000000000000
    while read -r _local_ref local_sha _remote_ref remote_sha; do
      [ "$local_sha" = "$zero" ] && continue # ref deletion: nothing leaves
      if [ "$remote_sha" = "$zero" ] || ! git cat-file -e "$remote_sha" 2>/dev/null; then
        range="$local_sha"
      else
        range="$remote_sha..$local_sha"
      fi
      scan_range "$range"
    done
    ;;
  *)
    echo "leak-guard: unknown mode: $1" >&2
    exit 2
    ;;
esac

exit "$bad"
