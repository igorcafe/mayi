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

### Handled system calls

- `open`, `creat`, `openat`, `openat2`

Can open files in read and/or write mode. Can even truncate them.

- `unlink`, `unlinkat`

Deletes files.

- `rename`, `renameat`, `renameat2`

Renames and/or moves files, but can also replace them.

### TO-DO

- `truncate`, `ftruncate`

Can erase the file content.

- `chmod`, `fchmod`, `fchmodat`

Changes file permissions.

- `chown`, `fchown`, `lchown`, `fchownat`

Changes file owner.

- `link`, `linkat`, `symlink`, `symlinkat`

Dangerous, because a hard link or a symlink can change the contents of a real file somewhere else.
The proper solution may be to always follow the links on open/truncate and similar operations.

- `mkdir`, `mkdirat`

Creates directory.
Maybe not so important to handle?

- `mknod`, `mknodat`

Can create regular files, devices, named pipes...
Maybe not so important to handle?


### Not planned

System calls that aren't harmful enough to care, or are already covered by broader filesystem permissions.

- `rmdir`

Removes an empty directory.

- `access`, `faccessat`, `faccessat2`

Checks user permission to access file.

- `stat`, `fstat`, `lstat`, `newfstatat`

Read metadata about the file.

- `getdents`, `getdents64`

Read the contents of a directory.
Needs to open the directory file first, which is already covered by `open`.

- `readlink`, `readlinkat`

Reads the path a symbolic link points to.