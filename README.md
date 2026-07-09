# May I read your `~/.ssh/id_rsa`?

`mayi` intercepts potentially dangerous Linux system calls and prompts the user for confirmation before executing them.

It detects a program trying to read, write, delete or rename a file and prompts the user to confirm the action.

## Showcase


Config example:

```ini
[*] # global config
/etc/.* = allow
/run/.* = allow
/var/.* = allow
/usr/.* = allow
/lib.* = allow
/bin/.* = allow
/tmp/.* = allow
/run/.* = allow
/proc/.* = allow
/sys/.* = allow
/dev/.* = allow
dirs = read

[emacs] # per program config
popup = true  # prompt permission using a graphical popup instead of terminal
$HOME/\.gitconfig = read  # environment variables work too
$HOME/\.emacs.* = allow
$HOME/dotfiles.* = allow
$HOME/Git/.* = allow
```

Launch the program, for example, emacs:

```shell
$ mayi emacs
```

If I try to read or write to any path not configured, it will prompt me to allow or deny:

If I deny Emacs will show an error message:

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