# CacheSniper

This is a proof of concept of the work done for "Aim, Wait, Shoot: How the CacheSniper Technique Improves Unprivileged Cache Attacks" 

This code was designed for Intel processors with TSX enabled and Linux Systems. In case your processor has TSX disabled, enable it under your own risk.

`Warning: this is a proof-of-concept, only useful for trying out the techniques described in CacheSniper and easing its utilization for research. Use it under your own risk.`

## Requirements

It requires Hugepages and assumes they are mounted on `/mnt/hugetlbfs/`. This value can be modified by changing the value of FILE_NAME.
The mount point must be created previously:

`$ sudo mkdir /mnt/hugetlbfs`.

Once reserved, hugepages can be mounted:

`$ sudo mount -t hugetlbfs none /mnt/hugetlbfs`

Note that this may require to use `sudo` for the examples or to change the permissions of the `/mnt/hugetlbfs/` folder.

To enable a fixed amount of huge pages, after a reboot the number of huge pages must be set:

`$ echo 100 > /proc/sys/vm/nr_hugepages`

To check that 100 huge pages are indeed available:

`$ cat /proc/meminfo | grep HugePages`

Check if your cpu supports TSX

`cat /proc/cpuinfo | grep rtm`

Check if it has any mitication enabled against TAA

`/sys/devices/system/cpu/vulnerabilities/tsx_async_abort`
