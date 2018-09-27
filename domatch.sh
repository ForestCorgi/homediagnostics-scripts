#!/bin/sh

rm matches.txt

for key in *.key; do
  echo "$(openssl rsa -noout -modulus -in $key | openssl md5) - $key" >> matches.txt
done

for key in *.public; do
  echo "$(openssl rsa -noout -modulus -pubin -in $key | openssl md5) - $key" >> matches.txt
done

for cert in *.crt; do
  echo "$(openssl x509 -noout -modulus -in $cert | openssl md5) - $cert" >> matches.txt
done

sort matches.txt > matches_sorted.txt

mv matches_sorted.txt matches.txt
