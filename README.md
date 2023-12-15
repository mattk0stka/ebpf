# ebpf

The system call for interacting with eBPF ist `bpf()`, helper functions start with `pbf_` and the different types of BPF programs are identifies with names that start with `BPF_PROG_TYPE`.


### Loading Programm into the Kernel
```bash 
 $ bpftool prog load network.bpf.o /sys/fs/bpf/network
```

 This loads the eBPF from compiled object file and pins it to the location */sys/fs/bpf/network*