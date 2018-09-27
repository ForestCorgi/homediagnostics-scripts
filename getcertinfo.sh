#!/bin/sh

rm certinfo.txt

for cert in *.crt; do
  echo "== $cert ==" >> certinfo.txt
  openssl x509 -text -noout -in $cert >> certinfo.txt
  echo "" >> certinfo.txt
done
