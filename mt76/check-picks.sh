#!/bin/sh
# check-picks.sh - say which of the outstanding openwrt commits will apply
# cleanly, and what is blocking the rest.
#
# show-picks.sh tells you what has not been taken yet. This tells you which
# of those you can take right now with no work at all.
#
# Run it from your morrownr/mt76 clone, same as show-picks.sh. It works in a
# scratch copy, so your tree is left alone and there is nothing to abort.

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

is_skipped() {
    _full=$1
    _oldifs=$IFS
    IFS='
'
    for _id in $skiplist; do
        case "$_full" in
        "$_id"*) IFS=$_oldifs; return 0 ;;
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

todo=$(git log --reverse --no-merges --format='%H %h %s' "HEAD..$REMOTE/$BRANCH" \
    | while read -r full short subject; do
        case "$applied" in
        *"$full"*) continue ;;
        esac
        is_skipped "$full" && continue
        printf '%s %s %s\n' "$full" "$short" "$subject"
    done)

total=$(printf '%s\n' "$todo" | grep -c .)
if [ "$total" -eq 0 ]; then
    echo
    echo "Nothing outstanding. You are caught up."
    exit 0
fi

echo "Testing $total commits ..."

scratch=$(mktemp -d)
git worktree add -q --detach "$scratch" HEAD || exit 1

clean=$(dirname "$0")/picks-clean.txt
blocked=$(dirname "$0")/picks-blocked.txt
: > "$clean"
: > "$blocked"

printf '%s\n' "$todo" | while read -r full short subject; do
    [ -z "$full" ] && continue
    if git -C "$scratch" cherry-pick --no-commit "$full" >/dev/null 2>&1; then
        printf '%s\n' "$short" >> "$clean"
    else
        stops=$(git -C "$scratch" diff --name-only --diff-filter=U | tr '\n' ' ')
        printf '%-10s %-34s %s\n' "$short" "${stops:-unknown}" "$subject" >> "$blocked"
    fi
    git -C "$scratch" cherry-pick --abort >/dev/null 2>&1
    git -C "$scratch" reset -q --hard HEAD
done

# Applying is not the same as building. 4f05b869 applied cleanly and still
# broke the build below 7.1, and 302d9cb2 applies cleanly then includes a
# header from a series this tree never took. So build each one before
# offering it.
broke=$(dirname "$0")/picks-broken.txt
: > "$broke"
buildable=no
if [ -s "$clean" ]; then
    # Build the tree as it stands first. If that fails there is no kernel to
    # build against, and without this check every pick gets blamed for it.
    if make -C "$scratch" >/dev/null 2>&1 </dev/null; then
        buildable=yes
    fi
fi

if [ "$buildable" = yes ]; then
    echo "Building each one, this takes a few minutes ..."
    while read -r short; do
        [ -z "$short" ] && continue
        git -C "$scratch" cherry-pick -x "$short" >/dev/null 2>&1 </dev/null || {
            git -C "$scratch" cherry-pick --abort >/dev/null 2>&1 </dev/null
            continue
        }
        if make -C "$scratch" >/dev/null 2>&1 </dev/null; then
            continue
        fi
        why=$(make -C "$scratch" 2>&1 </dev/null | sed -n 's/.*error: //p' | head -1)
        printf '%-10s %s\n' "$short" "${why:-build failed}" >> "$broke"
        git -C "$scratch" reset -q --hard HEAD~1 </dev/null
    done < "$clean"
    make -C "$scratch" clean >/dev/null 2>&1
    if [ -s "$broke" ]; then
        awk '{print $1}' "$broke" > "$scratch/.broken-ids"
        grep -v -x -F -f "$scratch/.broken-ids" "$clean" > "$clean.keep"
        mv "$clean.keep" "$clean"
    fi
fi

git worktree remove --force "$scratch" >/dev/null 2>&1
rmdir "$scratch" 2>/dev/null

[ -s "$broke" ] || rm -f "$broke"
nbroke=$([ -f "$broke" ] && grep -c . "$broke" || echo 0)
nclean=$(grep -c . "$clean")
nblocked=$(grep -c . "$blocked")

echo
if [ "$buildable" = yes ]; then
    printf '  %s apply cleanly and build\n' "$nclean"
else
    printf '  %s apply cleanly, not build-tested\n' "$nclean"
fi
[ "$nbroke" -gt 0 ] && printf '  %s apply cleanly but break the build\n' "$nbroke"
printf '  %s will not apply\n' "$nblocked"
echo

if [ "$nclean" -gt 0 ] && [ "$buildable" = no ]; then
    echo "No line to paste, because nothing could be built. make failed on this"
    echo "tree before any pick was added, so there is no kernel here to build"
    echo "against. Applying is not building: 302d9cb2 takes no conflict and then"
    echo "includes a header this tree has never had."
    echo
    echo "Install the headers for the kernel you are running and run this again"
    echo "and you get a line that has been built."
    echo
    echo "The $nclean that apply are in picks-clean.txt if you want to look."
    echo
fi

if [ "$nclean" -gt 0 ] && [ "$buildable" = yes ]; then
    echo "To take all of them, oldest first, copy and paste this line:"
    echo
    printf '    git cherry-pick -x %s\n' "$(tr '\n' ' ' < "$clean" | sed 's/ *$//')"
    echo
    echo "Every one of them was built here before it went on that line. Build"
    echo "again on your own kernel before you push, this tree supports several."
    echo
fi

if [ "$nbroke" -gt 0 ]; then
    echo "These apply with no conflict and then break the build, so they are"
    echo "left off the line above. They are in picks-broken.txt:"
    echo
    sed 's/^/    /' "$broke"
    echo
fi

if [ "$nblocked" -gt 0 ]; then
    echo "The rest are in picks-blocked.txt with the file that stops each one."
    top=$(sed 's/ [a-z0-9]*: .*//' "$blocked" | cut -d' ' -f2- \
        | tr ' ' '\n' | grep . | sort | uniq -c | sort -rn | head -1)
    topn=$(printf '%s\n' "$top" | awk '{print $1}')
    topf=$(printf '%s\n' "$top" | awk '{print $2}')
    if [ "${topn:-0}" -gt 2 ]; then
        printf '%s of them are stopped by the same file, %s.\n' "$topn" "$topf"
    fi
fi
