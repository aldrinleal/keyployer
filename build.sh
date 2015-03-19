#!/bin/bash

mvn package

if [ ! -d bin ]; then
  mkdir bin
fi

cat stub.sh target/keyployer-0.0.1.jar > bin/keyployer

chmod 755 bin/keyployer
