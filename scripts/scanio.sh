#!/bin/bash
# Usage : ./scanio.sh <version number> <file>
# Example: ./scanio.sh 2017-12-08-1512720001-fdns_a.json.gz cname_list.txt

# Premium
function ech() {
  spinner=( "|" "/" "-" "\\" )
  while true; do
    for i in ${spinner[@]}; do
      echo -ne "\r[$i] $1"
      sleep 0.15
    done
  done
}

# Joining elements together
function join_by() {
  local IFS=$1
  shift
  echo $*
}

# Kill function
function die() {
  disown $1
  kill -9 $1
  
  length=$(echo -n $3 | wc -m)
  Count=$(($length + 5))
  Clear=$(head -c $Count < /dev/zero | tr '\0' '\040')
  echo -ne "\r $Clear"
  echo -e "\r[*] $2"
}

function run() {
  ech "$1" &
  pid=$!
  eval "$2"
  die $pid "$3" "$1"
}

# Gathering data from scans.io
cmd="wget -q https://scans.io/data/rapid7/sonar.fdns_v2/$1"
run "Downloading $1 (This may take a while)." "$cmd" "Finished Downloading $1"

# Parsing it into a file called cname_scanio

msg="Grepping for CNAME records."
ech $msg &
pid=$!
zcat $1 | grep 'type":"cname' | awk -F'":"' '{print $3, $5}' | \
  awk -F'"' '{print $1, $3}' | sed -e s/" type "/" "/g >> cname_scanio
die $pid "CNAME records grepped." $msg

# List of CNAMEs we're going to grep for
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

# Prepare CNAME grep
DOMAINS=$(join_by '|' ${arr[@]})

# Grepping CNAMEs from the array
cmd="grep -Ei '${DOMAINS}' cname_scanio >> cname_db"
run "Sorting CNAME records." "$cmd" "CNAME records sorted."

# Sorting the CNAME list
cmd="cat cname_db | awk '{print $1}' | sort | uniq >> $2"
run "Cleaning up." "$cmd" "Cleaned up."

# RM files.
rm cname_db cname_scanio
echo "[+] Finished."
