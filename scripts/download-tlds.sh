#!/bin/bash

curl https://data.iana.org/TLD/tlds-alpha-by-domain.txt | tail +2 | tr '[:upper:]' '[:lower:]' | sed -e 's/^/./' > ../packaging/config/known.tld
