#! /bin/bash

if [ -d build ] ; then
    rm -r build
fi

mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cp compile_commands.json ..
