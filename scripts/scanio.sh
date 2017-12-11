#!/bin/bash
# Usage   : ./scanio.sh <version number> <file>
# Example : ./scanio.sh 2017-12-08-1512720001-fdns_a.json.gz cname_list.txt

# Gathering data from scans.io and parsing it into a file called cname,
echo "[+] Downloading Project Sonar (This may take a while)."
wget https://scans.io/data/rapid7/sonar.fdns_v2/$1

echo "[+] Grabbing CNAME records."
zcat $1 | grep 'type":"cname' | awk -F'":"' '{print $3, $5}' | \
  awk -F'"' '{print $1, $3}' | sed -e s/" type "/" "/g >> cname_scanio  

# List of cnames we're going to grep for.
declare -a arr=(
  "\.cloudfront.net"
  "\.s3-website"
  "\.s3.amazonaws.com"
  "w.amazonaws.com"
  "1.amazonaws.com"
  "2.amazonaws.com"
  "s3-external"
  "s3-accelerate.amazonaws.com"
  "\.herokuapp.com"
  "\.herokussl.com"
  "\.herokudns.com"
  "\.wordpress.com"
  "\.pantheonsite.io"
  "domains.tumblr.com"
  "\.wpengine.com"
  "\.desk.com"
  "\.zendesk.com"
  "\.github.io"
  "\.global.fastly.net"
  "\.helpjuice.com"
  "\.helpscoutdocs.com"
  "\.ghost.io"
  "cargocollective.com"
  "redirect.feedpress.me"
  "\.freshdesk.com"
  "\.myshopify.com"
  "\.statuspage.io"
  "\.uservoice.com"
  "\.surge.sh"
)

#Joining elements together.
function join_by { local IFS="$1"; shift; echo "$*"; }
DOMAINS=$(join_by '|' "${arr[@]}")

# Grepping cnames from array.
echo "[+] Sorting CNAME records."
grep -E "${DOMAINS}" cname_scanio >> cname_db

# Sorting cname list
echo "[+] Cleaning up."
cat cname_db | awk '{print $1}' | sort | uniq >> $2

# Clean up.
rm cname_db cname_scanio
echo "[+] Finished."
