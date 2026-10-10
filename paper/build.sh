#!/usr/bin/env bash
# Build the paper PDF. Requires pandoc + xelatex.
set -euo pipefail
cd "$(dirname "$0")"
pandoc paper.md -o paper.pdf \
  --pdf-engine=xelatex \
  -V geometry:margin=1in \
  -V fontsize=10pt \
  -V mainfont="Times New Roman" \
  -V monofont="Menlo" \
  -V monofontoptions="Scale=0.85" \
  -V colorlinks=true \
  --toc
echo "built: $(pwd)/paper.pdf"
