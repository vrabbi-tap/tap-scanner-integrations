#!/bin/bash

set -eu

SCAN_FILE=$1
SUMMARY_OUTPUT_FILE=$2
SCAN_DIR=$3
ORIGIN=$4

pushd $SCAN_DIR &> /dev/null
trivy fs . --server $TRIVY_SERVER --format cyclonedx --security-checks vuln > $SCAN_FILE

if [[ -d .git ]]; then
  DIGEST=`git log -n 1 --format=%H`
  URI=`git config --get remote.origin.url`
elif [[ -n "${REVISION:-}" ]] && [ "$ORIGIN" = "blob" ]; then
  DIGEST=$REVISION
  URI=$REPOSITORY
fi

critical=0
high=0
medium=0
low=0
unknown=0

for row in $(cat $SCAN_FILE | jq -r '.vulnerabilities[] | @base64'); do
  VULN=`echo ${row} | base64 --decode`
  if [[ `echo $VULN | jq '.ratings[] | select(.severity == "critical")'` != "" ]]; then
    critical=$((critical+1))
  elif [[ `echo $VULN | jq '.ratings[] | select(.severity == "high")'` != "" ]]; then
    high=$((high+1))
  elif [[ `echo $VULN | jq '.ratings[] | select(.severity == "medium")'` != "" ]]; then
    medium=$((medium+1))
  elif [[ `echo $VULN | jq '.ratings[] | select(.severity == "low")'` != "" ]]; then
    low=$((low+1))
  elif [[ `echo $VULN | jq '.ratings[] | select(.severity == "info")'` != "" ]]; then
    low=$((low+1))
  else
    unknown=$((unknown+1))
  fi
done

cat << EOF > $SUMMARY_OUTPUT_FILE
scan:
  cveCount:
    critical: $critical
    high: $high
    medium: $medium
    low: $low
    unknown: $unknown
  scanner:
    name: Trivy
    vendor: Aqua
    version: 0.34.0
  reports:
  - /workspace/scan.json
EOF


cat $SCAN_FILE | jq '.metadata.component.name="'$URI'"' | jq '.metadata.component.version="'$DIGEST'"' > $SCAN_FILE.tmp && mv $SCAN_FILE.tmp $SCAN_FILE

cat $SCAN_FILE
cat $SUMMARY_OUTPUT_FILE

popd &> /dev/null

