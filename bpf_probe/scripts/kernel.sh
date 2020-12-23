#!/usr/bin/env bash

set -e

export K=${1%-*-*}
if [ ${K#*.*.} == "0" ]
then export K=${K%.*}; export M=${K%.*}
else export M=${K%.*.*}
fi

wget -cq https://cdn.kernel.org/pub/linux/kernel/v$M.x/linux-$K.tar.xz
mkdir /kernel
tar -xf linux-$K.tar.xz --directory=/kernel
cd /kernel
pushd linux-$K
make defconfig
make modules_prepare
popd
