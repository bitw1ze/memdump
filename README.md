# memdump

## What

Dump the memory of a process on a unixy system.

# Why

It's nice sometimes just to be able to see what's in the memory of a process
and grep for stuff without having to spin up GDB or do any other crazy stuff. I
haven't seen a tool that dumps memory the way I want. Also I was bored and felt
like learning the ptrace API, so I figured this would be a nice tool to write.

## How

<pre>
$ cc memdump.c -o memdump
$ ./memdump -h
Usage: ./memdump [opts] -p <pid>

Options:
   -a              dump all segments
   -b              dump the stack
   -c              dump the heap
   -d &lt;dir&gt;        save dumps to custom directory &lt;dir&gt;
   -p &lt;pid&gt;        pid of the process to dump
   -h              this menu
$ sudo ./memdump -b -c -p $(pgrep skype)
$ strings *.dump | grep your_password
your_password
</pre>

# Contribute

Feel free to clean up the code or add a feature in a pull request. Let me know
if you have any questions.

# License

http://www.wtfpl.net/txt/copying/
