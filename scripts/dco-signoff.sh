#!/usr/bin/env bash
# Copyright (C) 2026 ADMRN (admrn.com)
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

signoff_re='^Signed-off-by: [^<[:space:]][^<]* <[^<>[:space:]]+@[^<>[:space:]]+>$'

# grep -q returns at the first match and closes the pipe. pipefail then turns
# the writer's SIGPIPE into a failed check, so a long message that contains
# the sign-off is reported missing. Read the whole input.
author_signoff_ok() {
  local name="$1"
  local email="$2"
  local message="$3"
  local expected="Signed-off-by: ${name} <${email}>"
  if ! printf '%s\n' "$expected" | grep -E "$signoff_re" >/dev/null; then
    return 1
  fi
  printf '%s\n' "$message" | grep -Fx -e "$expected" >/dev/null
}

# Merge commits stay on this rule: the last trailer block, and any well-formed
# Signed-off-by line in it. The line does not have to name the author.
legacy_trailer_signoff_ok() {
  git interpret-trailers --parse | grep -E "$signoff_re" >/dev/null
}

if ! printf '%s' "$BASE_SHA" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "base SHA is not a commit id" >&2
  exit 1
fi
if ! printf '%s' "$HEAD_SHA" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "head SHA is not a commit id" >&2
  exit 1
fi

if ! git cat-file -e "${HEAD_SHA}^{commit}" \
  && printf '%s' "$PR_NUMBER" | grep -Eq '^[0-9]+$'; then
  git fetch --no-tags origin "+refs/pull/${PR_NUMBER}/head"
fi
if ! git cat-file -e "${BASE_SHA}^{commit}" \
  && printf '%s' "$BASE_REF" | grep -Eq '^[A-Za-z0-9._/-]+$'; then
  git fetch --no-tags origin "+refs/heads/${BASE_REF}:refs/remotes/origin/${BASE_REF}"
fi
if ! git cat-file -e "${BASE_SHA}^{commit}" || ! git cat-file -e "${HEAD_SHA}^{commit}"; then
  echo "pull request commits are not in this checkout" >&2
  exit 1
fi

missing=0
count=0
commits="$(git rev-list "${BASE_SHA}..${HEAD_SHA}")"
if [ -n "$commits" ]; then
  while IFS= read -r commit; do
    [ -n "$commit" ] || continue
    count=$((count + 1))
    if git rev-parse --verify --quiet "${commit}^2" >/dev/null; then
      if ! git --no-pager log -1 --format='%B' "$commit" | legacy_trailer_signoff_ok; then
        echo "missing Signed-off-by trailer: $(git rev-parse --short "$commit") $(git --no-pager log -1 --format='%s' "$commit")"
        missing=1
      fi
      continue
    fi
    message="$(git --no-pager log -1 --format='%B' "$commit")"
    name="$(git --no-pager log -1 --no-use-mailmap --format='%an' "$commit")"
    email="$(git --no-pager log -1 --no-use-mailmap --format='%ae' "$commit")"
    if ! author_signoff_ok "$name" "$email" "$message"; then
      echo "missing Signed-off-by trailer: $(git rev-parse --short "$commit") $(git --no-pager log -1 --format='%s' "$commit")"
      missing=1
    fi
  done <<< "$commits"
fi

echo "checked ${count} commit(s) in ${BASE_SHA}..${HEAD_SHA}"
exit "$missing"
