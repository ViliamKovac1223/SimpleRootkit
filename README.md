# Rootkit
This is a very small personal and educational project. This basic rootkit can
hide its network activity on device, hide its processes, and files. Project
actually stands on several parts, first is user space code, it handles all other
parts, their proper loading, and integrating them together. Then we have ebpf
program that handles hiding files and processes (technically still file
descriptors like ``/proc/<process_id>``). Kernel module that hides network
activity. And finally payload, this is separate independent program, that main
part will run as a separate process.

## Loader
This is the main part of this project that loads everything else. This runs at
userspace, and loads epbf program and kernel module into the kernel space. It
also communicates with them in the runtime. At the start of the program it reads
configuration, and setups everything accordingly.

## EBPF Program
Ebpf part of this rookit is responsible for hiding files and processes. The way
this rootkit is hiding processes is by hiding certain directories in
``/proc/``. Inside of ``/proc/`` directory are directories that represent all
processes in Linux. By hiding certain directory there, we can make illusion
that process doesn't exist. But how does this rootkit hide the directory? Lets
start with how to get information about what is inside of the ``/proc/``. For
efficient listing entries from directory (like ``/proc/``) programs use
(usually indirectly) ``getdents64`` syscall. This syscall is very efficient at
reading what is inside of a directory, and it reads it into the buffer of type
``struct linux_dirent * dirp``. So after its done (successfully) reading, we
have two things, first its return value which is how many bytes it did read,
and ``dirp`` which represents a structure of a single entry in directory. There
are several fields in ``struct linux_dirent * dirp``, one of them is
``d_reclen``, which is size of this single entry. If we add this size to the
original address of ``dirp`` we get next entry address. This is all the context
we need to understand how this rootkit hides files. With ebpf program we hook
onto ``getdents64`` syscall, and when we find file we want to hide, we
artificially increase size of a previous entry, so when we calculate address of
next entry, this one will be skipped over, effectively hiding it. Okay but what
about a first entry, what if we want to hide first entry, there is no previous
entry to hide it behind. In that case, we copy second entry to the place of the
first, and increase its size. Meaning the second entry will become first, and
by increasing its size we skip through the original second entry. So the
original first entry has effectively disappeared. But what if there is only one
entry ... well in that case, there is nothing we can do with ebpf program. The
way to solve this is to modify return value (number of bytes read) of
``getdents64`` to zero, but epbf is very picky about what return values can
modified. So this case can't be solved with ebpf program, the only way to solve
this is to rewrite this to the kernel module. But this project started because
I wanted to learn about ebpf, so this solution would kinda defeat the purpose
of this project.

## Rnet Module
This project also have kernel module that hides network activity, this was
originally planed to be done in ebpf instead of a kernel module, but I found
this impossible because I needed it to rewrite a return value of syscall. So
kernel module it is.

In this kernel module we hook into ``tcp4_seq_show`` syscall that essentially
shows tcp netwok activity. When it finds network connection match between ip
address and port that needs to be hidden. We change return value of this syscall
to ``EACCES`` that represents an error that will make program like ``netstat``
to ignore this connection, and not show it to the user.

## Persistence Module
This kernel module was designed to be running at the boot time, and start up
the rootkit itself. Once loaded, module cannot be unloaded by standard means.
This module provides persistence to this rootkit, since it loads at bootime,
and starts rest of the rootkit.

## Payload
Because this project is educational, the payload here is really just a
placeholder program that doesn't do much.

## Configuration
Bellow we can see the example configuration for this rootkit. At the start the
rootkit reads this file, and behave accordingly. Configuration file is mostly
self-explanatory. Interesting things that can be configured here, are network
connections to hide, and by providing inodes you can hide more files, other
than what rootkit hides by default.

```
rnet:
  # Path to the kernel module
  path: ./bin/rnet.ko
  name: rnet
  # Ip addresses and ports to hide
  ips_and_ports: 
    - ip: <example ip>
    - port: <example port>

bpf_program_config:
  # Additional inodes to hide
  # inodes:
    # - <additional_inodes>
  hide_host: true
  hide_payload: true
  hide_config: true

rt:
  module_path: ./bin/rt.ko
  module_name: rt
  program_path: ./bin/main

payload:
  path: ./bin/payload
```

# How to Test This Project
To start with, I really recommend to use this project inside of the virtual
machine (VM) for your own safety. Other than that, in next sections lets
explain how to setup your development environment, VM for testing, and how to
compile this project.

## Compilation and Dependencies
Below we can see command to install basic dependencies for compiling this
project. Once installed you should be able to compile this project.

```
sudo apt-get install gcc-multilib build-essential libc6-dev libbpf-dev bpftrace linux-headers-$(uname -r) clang net-tools libyaml-cpp-dev
```

To compile this project all you need is to run ``make all``. Bellow you can see
reference for compiling only certain parts of this project.
```
make user  # Compiles main part of this project, bin/main binary
make ernel_ebpf # Compiles ebpf part of this project
make kernel_module  # Compiles kernel module
make payload # Compiles payload binary
```

You can run this project by running the following command.
```
sudo ./bin/main
```

## Dev environment
I found out that code editors and their LSP servers have problem reading this
codebase without instructions on how its compiled. This problem comes from the
fact that this project have many parts that needs to be compiled separately,
and in different manners. I recommend to generate ``compile_commands.json`` by
running following commands.

```
make clean
bear -- make
```

## VM for testing
What VM you use its really up to you. Here I will describe what I used, and how
to replicate my VM setup. I used
[Vagrant](https://developer.hashicorp.com/vagrant) for managing VM box, the
base for my VM was ``ubuntu-24.04``, after first bootup to VM it is necessary
to install all dependencies from previous section. After that it is also nice
to synchronize files between your development machine and your testing machine.
For that I recommend to add this to your Vagrantfile.
```
  config.vm.synced_folder ".", "/home/vagrant/project", type: "rsync",
    rsync__exclude: [
      ".git/",
      ".gitignore",
      ".vagrant",
      "compile_commands.json",
      "Vagrantfile"
    ]
```
After that all you have to do sync your file is to run this command ``vagrant rsync``.

Here is a list of useful commands for vagrant.

```
vagrant up
vagrant reload
vagrant ssh # Automatically ssh you into machine from current terminal
vagrant rsync
vagrant halt

# This will delete a VM, and next bootup you will have to install all dependencies again
vagrant destroy
```

## Running, Installing, and Uninstalling
This project can be installed with persistence to the machine. Once installed
the rootkit gets running during boot time and it will remain running. To
uninstall it you have to delete its system configuration and kernel module file
from file system. After that you have to reboot system for changes to be
active, since rootkit module cannot be unloaded (by design). But for testing
and playing around I only recommend to run this rootkit without installing it,
and only in virtual machine. Bellow you can list of commands for running,
installing, and uninstalling.

```
sudo ./bin/main --run
sudo ./bin/main --install
make uninstall
```

Here is a list of manual commands for uninstalling.
```
sudo rm /etc/modules-load.d/rt.conf
sudo rm /etc/modprobe.d/rt.conf
sudo rm /lib/modules/$(uname -r)/rt.ko
```

``main`` binary also supports arguments for ``--cwd=/path/rootkit/folder``.
This option allows you to set current working directory of the running rootkit.

# Disclaimer
This software and code is not intended to be used in a harmful way, and I do
not take any responsibility for it. The software and the code is provided as
is, without warranty of any kind.
