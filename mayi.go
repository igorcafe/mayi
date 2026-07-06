package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "args: ", os.Args)
		fmt.Fprintln(os.Stderr, "missing target program")
		os.Exit(1)
	}

	if os.Args[1] == "--child" {
		err := runChild(context.Background())
		panic(err)
	}

	log.SetFlags(log.Lshortfile)
	log.SetOutput(io.Discard)

	if os.Args[1] == "-v" {
		log.SetOutput(os.Stderr)
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}

	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		panic(err)
	}

	parentSock := sockets[0]
	childSock := sockets[1]

	err = runParent(context.Background(), childSock, parentSock)
	if err != nil {
		panic(err)
	}
}

type SeccompData struct {
	Nr   int32
	Arch uint32
	IP   uint64
	Args [6]uint64
}

type SeccompNotif struct {
	ID    uint64
	Pid   uint32
	Flags uint32
	Data  SeccompData
}

type SeccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

func runParent(ctx context.Context, childSock, parentSock int) error {
	err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	if err != nil {
		return err
	}

	initialPid, err := syscall.ForkExec(
		"/proc/self/exe",
		append([]string{"/proc/self/exe", "--child"}, os.Args[1:]...),
		&syscall.ProcAttr{
			Env: os.Environ(),
			Files: []uintptr{
				uintptr(0),
				uintptr(1),
				uintptr(2),
				uintptr(childSock),
			},
		},
	)
	if err != nil {
		return err
	}

	err = unix.Close(childSock)
	if err != nil {
		return err
	}

	fd, err := recvFD(parentSock)
	if err != nil {
		return err
	}

	var configs []Config

	configPath := os.Getenv("MAYI_CONFIG")
	if configPath == "" {
		if os.Getenv("HOME") != "" {
			configPath = path.Join(os.Getenv("HOME"), "/.config/mayi.ini")
		}
	}

	if configPath != "" {
		fmt.Fprintf(os.Stderr, "loading config from: %s\n", configPath)
		file, err := os.Open(configPath)
		if err == nil {
			defer file.Close()
			configs, err = parseConfig(file)
			// fmt.Printf("%+#v\n", configs)
			if err != nil {
				return err
			}
		}
	}

	stdin := bufio.NewScanner(os.Stdin)

	for {
		req := SeccompNotif{}
		_, _, errno := unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(fd),
			unix.SECCOMP_IOCTL_NOTIF_RECV,
			uintptr(unsafe.Pointer(&req)),
		)
		if errno == unix.ENOENT {
			break
		}
		if errno != 0 {
			fmt.Printf("%d: %s\n", errno, errno)
			return errno
		}

		respDeny := SeccompNotifResp{
			ID:    req.ID,
			Error: -int32(unix.EACCES),
		}

		respAllow := SeccompNotifResp{
			ID:    req.ID,
			Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE,
		}

		resp := respDeny

		intent, err := parseSyscallIntent(req, configs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rename(%d): %v\n", req.Data.Nr, err)
			return err
		}

		perm := permForIntent(configs, intent)

		if perm == PermDeny {
			fmt.Fprintln(os.Stderr, "Permission denied for", intent.Actions[0].Path, intent.Actions[1].Path)
			resp = respDeny
		} else if perm == PermAsk {
			fmt.Fprintf(os.Stderr, "%s\n[Y/n]: ", intent.Prompt)
			if !stdin.Scan() {
				resp = respDeny
			} else if strings.ContainsAny(stdin.Text(), "Nn") {
				resp = respDeny
			} else {
				resp = respAllow
			}
		} else {
			resp = respAllow
		}

		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(fd),
			unix.SECCOMP_IOCTL_NOTIF_SEND,
			uintptr(unsafe.Pointer(&resp)),
		)
		if errno == unix.ENOENT {
			break
		}
		if errno != 0 {
			log.Printf("%d: %s\n", errno, errno)
			return errno
		}
	}

	var status unix.WaitStatus
	_, err = unix.Wait4(initialPid, &status, 0, nil)
	if err != nil {
		return err
	}

	if status.Exited() {
		os.Exit(status.ExitStatus())
	}

	if status.Signaled() {
		os.Exit(1)
	}

	return nil
}

func parseSyscallIntent(req SeccompNotif, configs []Config) (Intent, error) {
	var intent Intent

	switch req.Data.Nr {
	case unix.SYS_OPEN, unix.SYS_CREAT, unix.SYS_OPENAT, unix.SYS_OPENAT2:
		dirfd := unix.AT_FDCWD
		rawPath := uintptr(0)
		flags := unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC

		switch req.Data.Nr {
		case unix.SYS_OPEN:
			rawPath = uintptr(req.Data.Args[0])
			flags = int(int32(req.Data.Args[1]))
		case unix.SYS_CREAT:
			rawPath = uintptr(req.Data.Args[0])
		case unix.SYS_OPENAT:
			dirfd = int(int32(req.Data.Args[0]))
			rawPath = uintptr(req.Data.Args[1])
			flags = int(int32(req.Data.Args[2]))
		case unix.SYS_OPENAT2:
			dirfd = int(int32(req.Data.Args[0]))
			rawPath = uintptr(req.Data.Args[1])
			// TODO: handle arg[2] open_how
		default:
			panic("wtf?")
		}

		path, err := readProcessString(int(req.Pid), rawPath)
		if err != nil {
			return intent, err
		}

		path, err = resolveProcessPath(int(req.Pid), dirfd, path)
		if err != nil {
			return intent, err
		}

		read := false
		write := false
		var prompt string

		switch flags & unix.O_ACCMODE {
		case unix.O_RDONLY:
			read = true
			prompt = fmt.Sprintf("May I read your '%s'?", path)
		case unix.O_WRONLY:
			write = true
			prompt = fmt.Sprintf("May I write your '%s'?", path)
		case unix.O_RDWR:
			read = true
			write = true
			prompt = fmt.Sprintf("May I read AND write your '%s'?", path)
		default:
			// TODO:
			read = true
			write = true
			prompt = fmt.Sprintf("May I potentially read AND write your '%s'?", path)
		}

		return Intent{
			Program: os.Args[1],
			Prompt:  prompt,
			Actions: []Action{
				{
					Path:  path,
					Read:  read,
					Write: write,
				},
			},
		}, nil

	case unix.SYS_UNLINK, unix.SYS_UNLINKAT:
		dirfd := unix.AT_FDCWD
		rawPath := uintptr(0)

		switch req.Data.Nr {
		case unix.SYS_UNLINK:
			rawPath = uintptr(req.Data.Args[0])
		case unix.SYS_UNLINKAT:
			dirfd = int(int32(req.Data.Args[0]))
			rawPath = uintptr(req.Data.Args[1])
		}

		path, err := readProcessString(int(req.Pid), rawPath)
		if err != nil {
			return intent, err
		}

		path, err = resolveProcessPath(int(req.Pid), dirfd, path)
		if err != nil {
			return intent, err
		}

		return Intent{
			Program: os.Args[1],
			Prompt:  fmt.Sprintf("May I delete your '%s'?", path),
			Actions: []Action{
				{
					Path:  path,
					Read:  false,
					Write: true,
				},
			},
		}, nil

	case unix.SYS_RENAME, unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2:
		oldDirfd := unix.AT_FDCWD
		newDirfd := unix.AT_FDCWD
		rawOldPath := uintptr(0)
		rawNewPath := uintptr(0)

		switch req.Data.Nr {
		case unix.SYS_RENAME:
			rawOldPath = uintptr(req.Data.Args[0])
			rawNewPath = uintptr(req.Data.Args[1])
		case unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2:
			oldDirfd = int(int32(req.Data.Args[0]))
			rawOldPath = uintptr(req.Data.Args[1])
			newDirfd = int(int32(req.Data.Args[2]))
			rawNewPath = uintptr(req.Data.Args[3])
			// TODO: args[4] in renameat2 is a set of flags, should i care?
		}

		oldPath, err := readProcessString(int(req.Pid), rawOldPath)
		if err != nil {
			return intent, err
		}

		oldPath, err = resolveProcessPath(int(req.Pid), oldDirfd, oldPath)
		if err != nil {
			return intent, err
		}

		newPath, err := readProcessString(int(req.Pid), rawNewPath)
		if err != nil {
			return intent, err
		}

		newPath, err = resolveProcessPath(int(req.Pid), newDirfd, newPath)
		if err != nil {
			return intent, err
		}

		return Intent{
			Program: os.Args[1],
			Prompt:  fmt.Sprintf("May I move or rename '%s' to '%s'?", oldPath, newPath),
			Actions: []Action{
				{
					Path:  oldPath,
					Read:  false,
					Write: true,
				},
				{
					Path:  newPath,
					Read:  false,
					Write: true,
				},
			},
		}, nil
	}

	return intent, errors.New("Syscall handling not implemented")
}

func resolveProcessPath(pid int, dirfd int, path string) (string, error) {
	if len(path) == 0 {
		return path, errors.New("invalid path")
	}

	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}

	path = regexp.MustCompile(`/{2,}`).ReplaceAllString(path, "/")
	if path[0] == '/' {
		return path, nil
	}

	var cwd string
	var err error

	if dirfd == unix.AT_FDCWD {
		cwd, err = os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	} else {
		cwd, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
	}

	return filepath.Join(cwd, path), err
}

func readProcessString(pid int, addr uintptr) (string, error) {
	buf := make([]byte, 1024)
	local := []unix.Iovec{
		{
			Base: &buf[0],
			Len:  uint64(len(buf)),
		},
	}

	remote := []unix.RemoteIovec{
		{
			Base: addr,
			Len:  len(buf),
		},
	}

	n, err := unix.ProcessVMReadv(pid, local, remote, 0)
	if err != nil {
		return "", err
	}

	if n < 0 {
		return "", errors.New("couldn't read process memory")
	}
	buf = buf[:n]

	n = slices.Index(buf, 0)
	if n < 0 {
		return "", errors.New("didn't read a null terminated string")
	}

	return unsafe.String(&buf[0], n), nil
}

func runChild(ctx context.Context) error {
	var err error
	childSock := 3

	bpfStmt := func(code uint16, k uint32) unix.SockFilter {
		return unix.SockFilter{
			Code: code,
			K:    k,
		}
	}

	bpfJump := func(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
		return unix.SockFilter{
			Code: code,
			Jt:   jt,
			Jf:   jf,
			K:    k,
		}
	}

	filter := []unix.SockFilter{
		bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0),

		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_OPEN, 0, 1),
		bpfStmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_USER_NOTIF),

		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_CREAT, 0, 1),
		bpfStmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_USER_NOTIF),

		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_OPENAT, 0, 1),
		bpfStmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_USER_NOTIF),

		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_OPENAT2, 0, 1),
		bpfStmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_USER_NOTIF),

		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_UNLINK, 0, 1),
		bpfStmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_USER_NOTIF),

		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_UNLINKAT, 0, 1),
		bpfStmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_USER_NOTIF),

		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_RENAME, 0, 1),
		bpfStmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_USER_NOTIF),

		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_RENAMEAT, 0, 1),
		bpfStmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_USER_NOTIF),

		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_RENAMEAT2, 0, 1),
		bpfStmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_USER_NOTIF),

		bpfStmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW),
	}

	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	r1, _, syserr := unix.Syscall(
		unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER,
		uintptr(unsafe.Pointer(&prog)),
	)
	fd := int(r1)
	if syserr != 0 {
		return syserr
	}

	if err := sendFD(childSock, fd); err != nil {
		return err
	}

	arg, err := exec.LookPath(os.Args[2])
	if err != nil {
		return err
	}

	err = unix.Exec(arg, os.Args[2:], os.Environ())
	return err
}

type Perm int

const (
	PermDeny Perm = iota
	PermAsk
	PermAllow
)

type Intent struct {
	Program string
	Prompt  string
	Actions []Action
}

type Action struct {
	Path  string
	Read  bool
	Write bool
}

type Config struct {
	Program string
	Pattern *regexp.Regexp
	Read    Perm
	Write   Perm
}

func permForIntent(configs []Config, intent Intent) Perm {
	perm := PermAllow
	found := false

	for _, action := range intent.Actions {
		for _, conf := range slices.Backward(configs) {
			if intent.Program != conf.Program && conf.Program != "*" {
				continue
			}
			if !conf.Pattern.MatchString(action.Path) {
				continue
			}

			found = true

			// if any action is denied, the whole operation is denied
			if (action.Read && conf.Read == PermDeny) || (action.Write && conf.Write == PermDeny) {
				return PermDeny
			}

			// otherwise, if any action requires asking, we should ask
			if (action.Read && conf.Read == PermAsk) || (action.Write && conf.Write == PermAsk) {
				perm = PermAsk
			}
		}
	}

	if !found {
		return PermAsk
	}

	return perm
}

func parseConfig(r io.Reader) ([]Config, error) {
	var configs []Config
	scanner := bufio.NewScanner(r)
	var program string

	for scanner.Scan() {
		line := scanner.Text()
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			program = line[1 : len(line)-1]
			continue
		}

		chunks := strings.Split(line, "=")
		if len(chunks) != 2 {
			continue
		}

		if program == "" {
			continue
		}

		var conf Config

		key := strings.TrimSpace(chunks[0])
		key = regexp.MustCompile(`\$\w+`).ReplaceAllStringFunc(key, func(prev string) string {
			key := prev[1:]
			env := os.Getenv(key)
			return env
		})

		var err error
		conf.Pattern, err = regexp.Compile("^" + key + "$")
		if err != nil {
			fmt.Fprintln(os.Stderr, "[mayi] ignoring invalid regexp:", line)
		}
		conf.Program = program

		val := strings.TrimSpace(chunks[1])

		if strings.Contains(val, "write:deny") {
			conf.Write = PermDeny
		} else if strings.Contains(val, "write:ask") {
			conf.Write = PermAsk
		} else if strings.Contains(val, "write") {
			conf.Write = PermAllow
		}

		if strings.Contains(val, "read:deny") {
			conf.Read = PermDeny
		} else if strings.Contains(val, "read:ask") {
			conf.Read = PermAsk
		} else if strings.Contains(val, "read") {
			conf.Read = PermAllow
		}

		if strings.Contains(val, "deny") && conf.Read != PermDeny && conf.Write != PermDeny {
			conf.Read = PermDeny
			conf.Write = PermDeny
		}

		configs = append(configs, conf)
	}

	return configs, scanner.Err()
}

func sendFD(sock int, fd int) error {
	rights := unix.UnixRights(fd)
	return unix.Sendmsg(sock, []byte{0}, rights, nil, 0)
}

func recvFD(sock int) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))

	_, oobn, _, _, err := unix.Recvmsg(sock, buf, oob, 0)
	if err != nil {
		return -1, err
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, err
	}

	for _, msg := range msgs {
		fds, err := unix.ParseUnixRights(&msg)
		if err != nil {
			return -1, err
		}
		if len(fds) > 0 {
			return fds[0], nil
		}
	}

	return -1, fmt.Errorf("no fd received")
}
