#!/bin/bash

# -------------------------------------------------------------------------- #
# Copyright 2010-2017, OpenNebula Systems                                    #
#                                                                            #
# Licensed under the Apache License, Version 2.0 (the "License"); you may    #
# not use this file except in compliance with the License. You may obtain    #
# a copy of the License at                                                   #
#                                                                            #
# http://www.apache.org/licenses/LICENSE-2.0                                 #
#                                                                            #
# Unless required by applicable law or agreed to in writing, software        #
# distributed under the License is distributed on an "AS IS" BASIS,          #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   #
# See the License for the specific language governing permissions and        #
# limitations under the License.                                             #
#--------------------------------------------------------------------------- #

if [ -z "${TARGET}" ]; then
    echo 'Error: env. variable TARGET not set' >&2
    exit 1
fi

###

if [ -z "${RELEASE}" ]; then
    if git describe --contains $(git rev-parse HEAD) &>/dev/null; then
        RELEASE=1
    else
        DATE=${DATE:-$(date +%Y%m%d)}
        GIT=$(git rev-parse --short HEAD)
        RELEASE="${DATE}git${GIT}"
    fi
fi

###

NAME=${NAME:-one-context}
VERSION=${VERSION:-5.6.0}
RELEASE=${RELEASE:-1}
LABEL="${NAME}-${VERSION}"

if [ "${RELEASE}" = '1' ]; then
    FILENAME=${FILENAME:-${NAME}-${VERSION}.${TARGET}}
else
    FILENAME=${FILENAME:-${NAME}-${VERSION}-${RELEASE}.${TARGET}}
fi

# cleanup
if [ -z "${OUT}" ]; then
    OUT="out/${FILENAME}"
    mkdir -p $(dirname "${OUT}")
    rm -rf "${OUT}"
fi

set -e

if [ "${TARGET}" = 'msi' ]; then
    if [ ! -f rhsrvany.exe ]; then
        if [ -f /usr/share/virt-tools/rhsrvany.exe ]; then
            cp /usr/share/virt-tools/rhsrvany.exe .
        else
            echo 'Missing rhsrvany.exe' >&2
            exit 1
        fi
    fi

    wixl -D Version="${VERSION}" -o "${OUT}" package.wxs

elif [ "${TARGET}" = 'iso' ]; then
    mkisofs -J -R -input-charset utf8 \
        -m '*.iso' \
        -V "${LABEL}" \
        -o "${OUT}" \
        $(dirname "${OUT}")

else
    echo "Error: Invalid target '${TARGET}'" >&2
    exit 1
fi

echo $(basename ${OUT})
