# memdump

## What

Dump the memory of a process on a unixy system. Memdump should work on x86,
x86_64, ARM, and probably other architectures, as long as it is a unixy system
that supports the PTRACE API.

# Why

It's nice sometimes just to be able to see what's in the memory of a process
and grep for interesting things without having to spin up GDB or do any other
crazy stuff. I haven't seen another a tool that dumps memory the way I want, so
I made one. Also I was bored and felt like learning the ptrace API, so I
figured this would be a nice tool to write.

## How

<pre>
$ cc memdump.c -o memdump
$ ./memdump -h
Usage: ./memdump <segment(s)> [opts] -p <pid>

Options:
   -A              dump all segments
   -D              dump data segments
   -S              dump the stack
   -H              dump the heap
   -d &lt;dir&gt;        save dumps to custom directory
   -p &lt;pid&gt;        pid of the process to dump
   -h              this menu
$ sudo ./memdump -S -H -p $(pgrep skype)
$ strings *.dump | grep your_password
your_password
</pre>

## What about Android? (YMMV)

You need the Android NDK with your platform's gcc binary in your PATH. Change
architecture as needed. This may not work on all devices and kernel versions,
but it worked for me on Android 4.4 on an emulated Nexus 4. You must be root on
your Android device to run memdump.

<pre>
$ arm-linux-gnueabi-gcc memdump.c -o memdump -march=armv7-a -static
$ adb push memdump /data/local/tmp
$ adb shell
# cd /data/local/tmp
# ps
# ./memdump -d dumptest -D -S -H -p &lt;pid&gt;
# ls dumptest
a6895000-a6897000.dump
a6898000-a6995000.dump
a6995000-a699b000.dump
a699c000-a6a99000.dump
a6a99000-a6a9f000.dump
a6aa0000-a6b9d000.dump
a6b9d000-a6ba3000.dump
...
</pre>

# Contribute

Feel free to clean up the code or add a feature in a pull request. Let me know
if you have any questions.

# License

http://www.wtfpl.net/txt/copying/
