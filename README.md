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
- `unlink`, `unlinkat`
- `rename`, `renameat`, `renameat2`

### TO-DO

- `truncate`, `ftruncate`
- `chmod`, `fchmod`, `fchmodat`
- `chown`, `fchown`, `lchown`, `fchownat`
- `link`, `linkat`, `symlink`, `symlinkat`
- `mkdir`, `mkdirat`
- `mknod`, `mknodat`

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