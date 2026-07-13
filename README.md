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

If I try to read or write to any path not configured, it will ask if i allow:

<img width="704" height="453" alt="image" src="https://github.com/user-attachments/assets/16913c07-2820-48cc-81fb-3e9022975f62" />

If I deny Emacs will fail to open the file with permission denied.

You can even run a bash session under mayi:

```ini
[bash]
popup = true
dirs = read
$HOME/secret = deny
$HOME/public = allow
```

And any child process will be constrained by mayi:

<img width="654" height="259" alt="image" src="https://github.com/user-attachments/assets/911c7712-0d55-4d40-84c6-ba2893bf65ef" />

### Other prompts

<img width="582" height="326" alt="image" src="https://github.com/user-attachments/assets/f62ad358-6508-49ca-812d-b4ee19d27fab" />

<img width="628" height="350" alt="image" src="https://github.com/user-attachments/assets/a4a6c6fc-fd32-4acb-98a8-317f54b88fbd" />


## Status

This project is currently a proof of concept and I'm NOT a security researcher.

### Known issues

~~Currently `mayi` just approve or deny a system call.~~
~~For path operations that's not enough, because while a thread can ask to read a innocent file, such as `~/.editorconfig`, another thread can change this buffer to another path, like `~/.ssh/id_rsa`.~~

~~If the child process is able to change the path buffer and mayi sends a `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, it will allow the child process to read a different path from the one allowed.~~

~~The way to (probably) fix this is by resolving the system calls in the supervisor with its own copied paths, and to send the file descriptor to the child process, when applicable. I plan to do that soon.~~

Now fixed. Performing file operations in the supervisor process.

Another issue is that some programs can launch other programs without being child processes, like KDE "Open with...".
Since it's not a child process, it cannot be constrained by mayi.

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
