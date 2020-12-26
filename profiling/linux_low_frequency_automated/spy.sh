#!/bin/bash
if [[ "$3" = "" ]]; then
  echo "usage: ./spy.sh <sleep before test> <test duration> <binary/library>"
  exit 0
fi
filesize=$(stat -c%s "$3")
if [[ "$filesize" -gt "0" ]]; then
  echo "file size is $filesize bytes"
else
  echo "file does not exist..."
fi
i=$1
while [[ $i -gt 0 ]]; do
  echo "please prepare... starting test in $i seconds..."
  sleep 1
  i=$((i - 1))
done
filesize=$(printf "%x" "$filesize")
./spy 20 7f096f594000-7f096f67f000 r-xp 00000000 103:07 1186641                   /usr/lib/x86_64-linux-gnu/libgdk-3.so.0.2200.30 | ../../exploitation/multi_spy/spy $3

