#!/bin/bash
# ./cnames.sh example.com
# Just use awk magic to print only the domain: ./cnames.sh example.com | awk '{print $1}'

for domain in `cat $1`; do
  lookup=$(nslookup $domain | grep -i "canonical name" | awk -F'= ' '{print $2}')
  for d in ${lookup}; do
    echo -e "$domain\t$d"
  done
done
