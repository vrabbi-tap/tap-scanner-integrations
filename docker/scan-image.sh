#!/bin/bash
set -eu
SCAN_DIR=$1
SCAN_FILE=$2
PULL_IMAGE=""

if [[ $# -gt 2 ]]
then
    PULL_IMAGE=$3
fi

# move to a dir with write permissions
pushd $SCAN_DIR &> /dev/null

if [[ -z $PULL_IMAGE ]]
then
    ARGS=$IMAGE
else
    krane pull $IMAGE myimage
    ARGS="--input myimage"
fi

trivy image $ARGS --server $TRIVY_SERVER -format cyclonedx --security-checks vuln > $SCAN_FILE
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

cat << EOF > $SCAN_DIR/out.yaml
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

# Extract name and digest and update the cyclonedx output to comply with the needs of the metadata store
NAME=`cat $SCAN_FILE | jq -r '.metadata.component.properties[] | select(.name == "aquasecurity:trivy:RepoDigest") | .value | split("@") | .[0]'`
DIGEST=`cat $SCAN_FILE | jq -r '.metadata.component.properties[] | select(.name == "aquasecurity:trivy:RepoDigest") | .value | split("@") | .[1]'`
if [[ -z $NAME ]]; then
  NAME=`echo $IMAGE | awk -F "@" '{print $1}'`
fi
if [[ -z $DIGEST ]]; then
  DIGEST=`echo $IMAGE | awk -F "@" '{print $2}'`
fi
if [[ -z $DIGEST ]]; then
  if [[ -z $PULL_IMAGE ]]; then
    DIGEST=`krane digest --tarball myimage`
  else
    DIGEST=`krane digest $IMAGE`
  fi
fi
cat $SCAN_FILE | jq '.metadata.component.name="'$NAME'"' | jq '.metadata.component.version="'$DIGEST'"' > $SCAN_FILE.tmp && mv $SCAN_FILE.tmp $SCAN_FILE

cat $SCAN_FILE
cat $SCAN_DIR/out.yaml
