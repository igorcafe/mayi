# May I read your `~/.ssh/id_rsa`?

`mayi` intercepts potentially dangerous Linux system calls and prompts the user for confirmation before executing them.

## Example

```shell
$ mayi cat ../../.ssh/id_rsa                 
May I read '/home/igor/.ssh/id_rsa'? [Y/n]: n
cat: ../../.ssh/id_rsa: Permission denied
```

## Status

This project is currently a proof of concept and **I'm NOT a security researcher**.

For now I only implemented this "gate" for `openat` system call.
