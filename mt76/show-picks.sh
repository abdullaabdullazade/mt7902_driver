#!/bin/sh
# show-picks.sh - list openwrt/mt76 commits not yet cherry-picked into this tree.
#
# Run it from your morrownr/mt76 clone. It needs a git remote named "openwrt"
# pointing at the openwrt mt76 repo. If you do not have one yet:
#
#     git remote add openwrt https://github.com/openwrt/mt76.git
#
# It reads the "(cherry picked from commit ...)" lines that git cherry-pick -x
# adds, so keep using -x and this stays accurate.
#
# To drop a commit you have decided not to take, put its id in skip-picks.txt
# beside this script, one per line, reason after a #:
#
#     a1b2c3d4e5f6  # mt7981 firmware, not a chip we ship
#
# Short or long id, either works. Skipped commits stop showing up in the list.

set -u

REMOTE=openwrt
BRANCH=master

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "Not inside a git repository. cd into your morrownr/mt76 clone first."
    exit 1
fi

if ! git remote | grep -qx "$REMOTE"; then
    echo "No '$REMOTE' remote found. Add it once with:"
    echo
    echo "    git remote add $REMOTE https://github.com/openwrt/mt76.git"
    echo
    exit 1
fi

if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = true ]; then
    echo "This is a shallow clone, so the history that says what has already"
    echo "been picked is not here and every commit would be listed. Deepen it:"
    echo
    echo "    git fetch --unshallow"
    echo
    exit 1
fi

skipfile=$(dirname "$0")/skip-picks.txt
skiplist=""
if [ -f "$skipfile" ]; then
    skiplist=$(sed 's/#.*//' "$skipfile" | tr -d ' \t' | grep -v '^$')
fi

# true when $1, a full commit id, starts with any id listed in skip-picks.txt
is_skipped() {
    _full=$1
    _oldifs=$IFS
    IFS='
'
    for _id in $skiplist; do
        case "$_full" in
        "$_id"*)
            IFS=$_oldifs
            return 0
            ;;
        esac
    done
    IFS=$_oldifs
    return 1
}

echo "Fetching $REMOTE ..."
if ! git fetch -q "$REMOTE"; then
    echo "Could not fetch $REMOTE. Check your connection and the remote URL."
    exit 1
fi

if ! git merge-base HEAD "$REMOTE/$BRANCH" >/dev/null 2>&1; then
    echo "This tree and $REMOTE/$BRANCH share no history, so there is nothing"
    echo "to compare. Check that $REMOTE points at the openwrt mt76 repo."
    exit 1
fi

applied=$(git log --grep='cherry picked from commit' \
    | sed -n 's/.*cherry picked from commit \([0-9a-f]\{7,\}\).*/\1/p')

echo
echo "Commits in $REMOTE/$BRANCH not yet picked here (oldest first):"
echo

git log --reverse --no-merges --format='%H %h %s' "HEAD..$REMOTE/$BRANCH" \
    | while read -r full short subject; do
        case "$applied" in
        *"$full"*)
            continue
            ;;
        esac
        if is_skipped "$full"; then
            continue
        fi
        printf '  %s  %s\n' "$short" "$subject"
    done

echo
if [ -n "$skiplist" ]; then
    printf 'Skipping %s commit(s) listed in %s.\n\n' \
        "$(printf '%s\n' "$skiplist" | grep -c .)" "$(basename "$skipfile")"
fi
echo "Nothing listed means you are caught up. Pick the rest oldest first,"
echo "and keep using 'git cherry-pick -x' so they stay tracked."
