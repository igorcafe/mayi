# May I read your `~/.ssh/id_rsa`?

`mayi` intercepts potentially dangerous Linux system calls and prompts the user for confirmation before executing them.

## Example

Intercepting open system calls:

```shell
$ mayi bash steal_ssh.sh
May I read your '/home/igor/.ssh/id_rsa'?
[Y/n]: n
cat: /home/igor/.ssh/id_rsa: Permission denied
```

Intercepting rename system calls:

```shell
$ mayi mv old new
May I move or rename '/home/igor/Git/mayi/old' to '/home/igor/Git/mayi/new'?
[Y/n]: 
```

Intercepting deletion system calls:

```shell
$ mayi rm yourfile
May I delete your '/home/igor/Git/mayi/yourfile'?
[Y/n]: n
rm: cannot remove 'yourfile': Permission denied
```

Config example:
```ini
[*] # global config
/etc/.* = read write
/run/.* = read write
/var/.* = read write
/usr/.* = read write
/lib.* = read write
/bin/.* = read write
/tmp/.* = read write
/run/.* = read write
/proc/.* = read write
/sys/.* = read write
/dev/.* = read write

[emacs] # per program config

# env variables works too
$PWD/.* = read write
$HOME = read
$HOME/.gitconfig = read
$HOME/\.emacs.* = read write
```

## Status

This project is currently a proof of concept and I'm NOT a security researcher.

### Handled system calls

- [X] `open`, `creat`, `openat`, `openat2`: can open files in read and/or write mode. Can even truncate them. TODO: make sure truncate scenarios are really covered.

- [X] `unlink`, `unlinkat`: deletes files.

- [X] `rename`, `renameat`, `renameat2`: renames and/or moves files, but can also replace them.

- [ ] `truncate`, `ftruncate`: can erase the file content.

- [ ] `chmod`, `fchmod`, `fchmodat`: changes file permissions.

- [ ] `chown`, `fchown`, `lchown`, `fchownat`: changes file owner.

- [ ] `link`, `linkat`, `symlink`, `symlinkat`: dangerous, because a hard link or a symlink can change the contents of a real file somewhere else.
The proper solution may be to always follow the links on open/truncate and similar operations.

- [ ] TODO: handle networking, sockets, addresses, and so on. Requires adapting the config file.

### Not planned

System calls that aren't harmful enough to care, or are already covered by broader filesystem permissions.

- `rmdir`: removes an empty directory.

- `mkdir`, `mkdirat`: creates directory. Maybe not so important to handle?

- `mknod`, `mknodat`: can create regular files, devices, named pipes... Maybe not so important to handle?

- `access`, `faccessat`, `faccessat2`: checks user permission to access file.

- `stat`, `fstat`, `lstat`, `newfstatat`: read metadata about the file.

- `getdents`, `getdents64`: Read the contents of a directory. Needs to open the directory file first, which is already covered by `open`.

- `readlink`, `readlinkat`: Reads the path a symbolic link points to.