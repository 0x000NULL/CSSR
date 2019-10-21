#!/bin/bash

TMP="README.tmp"
OUT="README.md"

awk '!/^[0-9]{1,}\. \[/ { print } ' README.md > $TMP

export COUNT=0
ls *.md | fgrep -v 'README.md' | sort | while read FILENAME; do
	DESC=$(grep '^# ' $FILENAME | head -1 | sed -e 's/^# //g')
	COUNT=$(($COUNT + 1))
	echo "$COUNT. [$DESC](./$FILENAME)" >> $TMP
done

mv $TMP $OUT
