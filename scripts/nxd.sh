#!/bin/bash
# Simple script to check for NXDOMAINS | Allows for large file list.
# Will add this to subjack.go later.
# ./nxd.sh domains.txt

max=$(cat $1 | wc -l)
max=$((max+1))

for ((i=1; i<$max;++i)); do
  r=$(sed -n ${i}p $1)
  domain=$(dig +short CNAME $r)
  if_domain=$(dig +short CNAME $r | wc -l)
  if [ ${if_domain} -eq "1" ]; then
    lines=$(nslookup ${domain} | grep NXDOMAIN | wc -l)
    if [ ${lines} -eq "1" ]; then
      echo "${domain} is dead."
    fi
  fi
done
