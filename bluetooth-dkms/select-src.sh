#!/bin/sh
# Print the bundled source trees in the order to try them for kernel $1:
# the newest src/linux-X.Y not newer than the kernel first, then the older
# ones (closest first), then the newer ones (closest first). Distribution
# kernels backport API changes — Ubuntu's 6.14 carries the later hci_dev
# quirks rework, for one — so the version number alone cannot decide; the
# build tries each in turn until one compiles.
k=$1; dir=$(dirname "$0")/src
kmaj=${k%%.*}; rest=${k#*.}; kmin=${rest%%[!0-9]*}
knum=$((kmaj * 1000 + kmin))
for d in "$dir"/linux-*; do
	[ -d "$d" ] || continue
	v=${d##*linux-}; n=$(( ${v%%.*} * 1000 + ${v#*.} ))
	if [ "$n" -le "$knum" ]; then echo "0 $((knum - n)) $d"; else echo "1 $((n - knum)) $d"; fi
done | sort -k1,1n -k2,2n | awk '{print $3}'
