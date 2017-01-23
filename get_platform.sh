#!/bin/bash

OS_NAME="unknown"
version="unknown"

OS=$(uname -s)

case ${OS} in
  Darwin)
    version=$(sw_vers -productVersion)
    case $version in
      10.12*)
        OS_NAME="sierra"
      ;;
      10.11*)
        OS_NAME="elcapitan"
      ;;
      10.10*)
        OS_NAME="yosemite"
      ;;
      10.9*)
        OS_NAME="mavericks"
      ;;
        esac
  ;;

  Linux)
    . /etc/*-release >/dev/null 2>&1
    if [ -n "${DISTRIB_ID}" ]
    then
      OS_NAME=${DISTRIB_ID}
      version=${DISTRIB_RELEASE}
    fi

    if [ -f /etc/redhat-release ]
    then
      data=($(cat /etc/redhat-release))
      OS_NAME=${data[0]}
      version=${data[2]}
    fi
  ;;
esac

echo "${OS} ${OS_NAME} ${version}"

