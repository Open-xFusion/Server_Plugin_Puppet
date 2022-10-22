#!/bin/bash
# Copyright © xFusion Digital Technologies Co., Ltd. 2022. All rights reserved.
# First, the build pipeline downloads the uREST-Linux-*.tar.gz package to the build directory.
# Then, execute the current script.
# Finally, perform the packaging operation.

puppet_path=$(dirname "$PWD")

# decompression
mkdir "${puppet_path}/temp"
mv uREST-Linux-*.tar.gz "${puppet_path}/temp"
cd "${puppet_path}/temp"
tar -zxvf uREST-Linux-*.tar.gz

# Copy the files to the specified directory
mv ./bin "${puppet_path}/files/REST-Linux"
mv "${puppet_path}/files/REST-Linux/bin/urest" "${puppet_path}/files/REST-Linux/bin/rest"
sed -i -e "s/.\/..\/redfish\/lib/.\/..\/redfish\/lib:.\/..\/libs/" "${puppet_path}/files/REST-Linux/bin/rest"
mv ./ibmc_client "${puppet_path}/files/REST-Linux"
mv ./python "${puppet_path}/files/REST-Linux"
mv ./redfish "${puppet_path}/files/REST-Linux"
mv ./tools "${puppet_path}/files/REST-Linux"
# According to reserved_scripts.txt, copy the required uRest scripts to the specified directory.
cd ../build
cat reserved_scripts.txt | grep -v ^# | grep -v ^$ | while read line
do
    mv "${puppet_path}/temp/scripts/$line" "${puppet_path}/files/REST-Linux/scripts"
done

# Clean up temporary files
rm -rf "${puppet_path}/temp"

