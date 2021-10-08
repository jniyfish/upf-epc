#!/bin/bash

echo $(docker -a -q)
docker stop $(docker ps -a -q)
docker rm $(docker ps -a -q)
