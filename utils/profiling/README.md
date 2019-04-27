# Notes and tools for profiling Iroha using `google-perftools`

First you should build configure CMake with `PROFILING` flag, which links irohad
against google profiling libs and adds a CLI flag to enable profiling.
Set PROFILING to one of `CPU`, `HEAP` or `ALL` to enable the corresponding
profilings.
When this flag is enabled, irohad will periodically write memory and/or cpu
usage profiles to specified directory.
These can be later inspected with google pprof tool.

To get reasonable symbol names, the exact binary that produced the dumps is also
necessary.

Sometimes you may want to profile an iroha inside a docker container.
The container may not be suitable for analysing the profiles and maybe even for
symbolizing the profiles (imagine that it has very limited resourses, or you do
not want to launch heavyweight processes inside it to preserve the statistics.

For this reasons, or just to automate your profiles collection you may need
the script `symbolize_profiles.sh`.
It symbolizes and collects CPU profiles from irohad running in docker container.
Its purpose is to use the same environment as the irohad container to produce
correct address to symbol name translation in dumps, while keeping interactions
with the irohad container at minimum.
For more details please refer to the header comment in the script.

The profiles produced by google-perftools can be analyzed using `pprof`.
It can be installed with google-perftools package or obtained from
https://github.com/gperftools/gperftools/blob/master/src/pprof
You may want to see some tendencies along an `iroha` run.
For this purpose you may use the `--base` flag of `pprof`, that subtracts one
profile from another.
But if you want to get a tendency from several consequtive profiles, you may
need a modified version of `pprof` that can be found at
https://github.com/MBoldyrev/gperftools/blob/feature/pprof-linear-tendency/src/pprof
It generalizes the approach of `--base` flag, accumulating the profiles with
evenly distributed weights from -1.0 to 1.0. Be sure to specify the profiles
in order of time they represent, from oldest to newest.

