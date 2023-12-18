#!/usr/bin/python3  
from bcc import BPF

program = r"""
// macro for creating a map to pass message from kernel to user space
BPF_PERF_OUTPUT(output); 
 
struct data_t {     
   int pid;
   int uid;
   char command[16];
   char message[12];
};
 
int hello(void *ctx) {
   struct data_t data = {}; 
   char message[12] = "Hello World";
 
   // helper function that gets the ID of the process. Return 64-bit.Process ID int the top 32bits 
   data.pid = bpf_get_current_pid_tgid() >> 32;

   // helper function for obtaining the user ID
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   
   // helper fun for getting the name of the executbale 
   bpf_get_current_comm(&data.command, sizeof(data.command));

   // copies message into tge right place in the data structure
   bpf_probe_read_kernel(&data.message, sizeof(data.message), message); 
 
   // puts data into the map
   output.perf_submit(ctx, &data, sizeof(data)); 
 
   return 0;
}
"""

b = BPF(text=program) 
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
 
# callback function 
def print_event(cpu, data, size):  
   data = b["output"].event(data)
   print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")

# opens the perf ring buffer. provided function is the callback func to be used whenever there is data 
b["output"].open_perf_buffer(print_event) 
# if there is any data available, print_event will be called
while True:   
   b.perf_buffer_poll()