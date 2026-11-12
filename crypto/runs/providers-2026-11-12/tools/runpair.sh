#!/bin/bash
# runpair.sh <provider> [A items]: the HTTP/1.1 items, then --h2 (idle 60 s, 20 kB body)
cd "$(dirname "$0")"
p=$1; items=${2:-A9,A11,A1,A2,A4,A5,A6,A7,A12,A10}
bash -c "source ~/.extra >/dev/null 2>&1; python3 -I check.py $p a $items" > out/a.$p.txt 2>&1
bash -c "source ~/.extra >/dev/null 2>&1; python3 -I check.py $p h2 --h2-idle 60 --h2-body-bytes 20000" > out/h2.$p.txt 2>&1
echo done > out/done.$p
