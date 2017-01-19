#!/bin/bash

WORKDIR=$(dirname ${0})

PLAT_DATA=($(${WORKDIR}/get_platform.sh))
OS="${PLAT_DATA[0]}"
OS_NAME="${PLAT_DATA[1]}"
version="${PLAT_DATA[2]}"

[ -z "${OS}" ] && echo "Could not detect OS" && exit 1
[ -z "${OS_NAME}" ] && echo "Could not detect OS_NAME" && exit 1
[ -z "${OS}" ] && echo "Could not detect OS version" && exit 1

EXT_DIR=${WORKDIR}/php-extensions/${OS}/${OS_NAME}
PHP=$(which php)

if [ -d "${EXT_DIR}" ]
then
  local_extensions=$(cd ${EXT_DIR}; \ls -1 *.so)

  for extension in ${local_extensions}
  do
    ${PHP} -m | grep ${extension/\.so} >/dev/null 2>&1
    if [ ${?} -ne 0 ]
    then
      extensions+=" -d extension=${EXT_DIR}/${extension} "
    fi
  done
fi

${PHP} ${extensions} ${@}
