# ebpf

The system call for interacting with eBPF ist `bpf()`, helper functions start with `pbf_` and the different types of BPF programs are identifies with names that start with `BPF_PROG_TYPE`.


### Loading Program into the Kernel
```bash 
 $ bpftool prog load network.bpf.o /sys/fs/bpf/network
```

 This loads the eBPF compiled object file and pins it to the location */sys/fs/bpf/network*

 ### Attaching to an Event
 The object file has to mach the type of event it's being attached to (in this case it's an XDP program).
 ```bash
 $ bpftool prog list # look fo id
 $ bpftool prog show id <id> --pretty

 $ bpftool net attach xdp id <id> dev eth0

 # list all network-attached eBPF

 $ bpftool net list

 # check trace output
 $ cat /sys/kernel/ debug/tracing/trace_pipe
 ``` 