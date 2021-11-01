#!/usr/bin/env bash



docker run --name bess-pfcpiface -td --restart on-failure \
	--net host \
	-v "$PWD/conf/upf.json":/conf/upf.json \
	upf-epc-pfcpiface:"$(<VERSION)" \
	-config /conf/upf.json
