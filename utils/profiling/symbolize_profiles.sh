#!/bin/bash

# This script symbolizes and collects CPU profiles from irohad running in
# docker container.
# Its purpose is to use the same environment as the irohad container to
# produce correct address to symbol name translation in dumps, while keeping
# interactions with the irohad container at minimum.
# The original use case included low memory limit inside irohad container, so
# that symbolsizers failed to run inside it, and also minimal cpu affection
# inside container.
#
# The script copies the profile dumps from the target container and creates
# another one using the same image. It copies itself into the target container
# and starts itself with special argument `remote'. This way it understands that
# it is running in the target environment and starts symbolizing the symbols.
# When it is done, the container is removed, and the symbolized profiles are
# copied to the defiled path.
#
# Usage: set the variables at the beginning of the script and launch it in the
# host container, specifying some container with profiled irohad as an argument.
# You can safely fetch data from several containers, as the results get stored
# inside a subdirectory matching the container name.


# where to store symbolized profiles
LOCAL_OUT_DIR=~/symbolized_profiles

# where the profile dumps are (probably you want the same path you specified in -profiling_path) inside container
REMOTE_INP_DIR=/tmp/profiles

# the order of samples amount to produce (number of samples will be between 10^(n-1) and 10^n where n is the order)
SAMPLES_NUMBER_ORDER=2


if [[ $1 != 'remote' ]]; then
  container=$1
  # check that container is running
  if [[ ! $(docker ps -q -f name=${container}) ]]; then
    echo "no such container: ${container}"
    exit 1
  fi

  echo preparing data...

  tmp_dir=$(mktemp --tmpdir -d symbolize_profiles.XXXXXX)
  mkdir ${tmp_dir}/input
  docker cp ${container}:${REMOTE_INP_DIR} ${tmp_dir}/input
  [[ -f pprof ]] || wget -O pprof 'https://raw.githubusercontent.com/gperftools/gperftools/master/src/pprof'
  cp pprof ${tmp_dir}
  cp "$0" ${tmp_dir}/symbolize_profiles.sh

  echo running symbolizer...

  # create a container to run symbolization from the same image
  image=$(docker container inspect -f '{{.Config.Image}}' ${container})
  docker run \
    -v ${tmp_dir}:/root/data \
    --entrypoint /root/data/symbolize_profiles.sh \
    --rm \
    ${image} \
    remote

  echo copying results...

  mkdir -p ${LOCAL_OUT_DIR}/${container}/
  cp -r ${tmp_dir}/symbolized_profiles/* ${LOCAL_OUT_DIR}/${container}/

  rm -rf ${tmp_dir} || sudo rm -rf ${tmp_dir}

  echo done! data are available at ${LOCAL_OUT_DIR}/${container}.

else ##-- inside-container launch --##
  # install the needed packages if they are not already there
  dpkg --get-selections | grep binutils || apt -y install binutils
  dpkg --get-selections | grep file || apt -y install file

  local_output_dir=/root/data/symbolized_profiles
  mkdir -p ${local_output_dir}

  input_path=/root/data/input/${REMOTE_INP_DIR##*/}
  for d in ${input_path}/*; do
    subdir=${d##*/}
    echo "Symbolizing profiles in ${subdir}..."
    mkdir -p ${local_output_dir}/${subdir}/
    # search files with given zeros amount at number ending, which gives #SAMPLES_NUMBER_ORDER results
    name_filter=""
    name_filter_zeros=$(($(find ${input_path}/${subdir}/ -type f | wc -l | wc -c) - SAMPLES_NUMBER_ORDER - 1))
    if ((name_filter_zeros > 0)); then name_filter=$(echo '000000000' | cut -c 1-${name_filter_zeros}); fi
    ls ${local_output_dir}/${subdir}
    find ${input_path}/${subdir}/ -type f -name "cpu.*${name_filter}.*.prof" -exec bash -c "\
        name=\${0##*/}
        out_path=\"${local_output_dir}/${subdir}/\${name}.sym\"
        if [[ -e \"\$out_path\" ]]; then echo \"\${name} already symbolized, skipping\"; else
          echo processing \${name}...;
          /root/data/pprof --raw /usr/bin/irohad \"\$0\" 2>/dev/null > \"\${out_path}\"
        fi" \
      {} \;
  done

  # allow the host to recursively remove this directory
  chmod -R a+rw /root/data
fi
