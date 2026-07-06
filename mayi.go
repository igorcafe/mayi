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
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

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

	log.SetOutput(io.Discard)

	if os.Args[1] == "-v" {
		log.SetFlags(log.Lshortfile)
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

func runParent(ctx context.Context, childSock, parentSock int) error {
	err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	if err != nil {
		return err
	}

	pid, err := syscall.ForkExec(
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

	fd, err := RecvFD(parentSock)
	if err != nil {
		return err
	}

	var configs []Config

	file, err := os.Open("/home/igor/.config/mayi.ini")
	if err == nil {
		defer file.Close()
		configs, err = ParseConfig(file)
		// fmt.Printf("%+#v\n", configs)
		if err != nil {
			return err
		}
	}

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

		var resp SeccompNotifResp

		if req.Data.Nr == unix.SYS_OPENAT {
			resp, err = handleSyscallOpen(pid, req, configs)
			if err != nil {
				fmt.Print(err)
			}
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
	_, err = unix.Wait4(pid, &status, 0, nil)
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

func handleSyscallOpen(pid int, req SeccompNotif, configs []Config) (resp SeccompNotifResp, err error) {
	resp = SeccompNotifResp{
		ID:    req.ID,
		Flags: 0,
		Error: -int32(unix.EACCES),
	}
	stdin := bufio.NewScanner(os.Stdin)

	dirfd := int(int32(req.Data.Args[0]))
	addr := uintptr(req.Data.Args[1])
	flags := int(req.Data.Args[2])

	path, err := readProcessString(pid, addr)
	if err != nil {
		return
	}

	path, err = resolveProcessPath(pid, dirfd, path)
	if err != nil {
		return
	}

	read := false
	write := false

	switch flags & unix.O_ACCMODE {
	case unix.O_RDONLY:
		read = true
	case unix.O_WRONLY:
		write = true
	case unix.O_RDWR:
		read = true
		write = true
	}

	intent := Intent{
		Program: os.Args[1],
		Path:    path,
		Read:    read,
		Write:   write,
	}
	conf, _ := FindConfigMatch(configs, intent)
	// fmt.Printf("conf: %+#v\n", conf)
	perm := conf.PermForIntent(intent)

	if perm == PermDeny {
		fmt.Fprintln(os.Stderr, "Permission denied for", path)
		resp.Flags = 0
		resp.Error = -int32(unix.EACCES)
		return
	}
	if perm == PermAsk {
		fmt.Fprint(os.Stderr, "May I read your "+path+"?\n[Y/n]: ")
		if !stdin.Scan() {
			return
		}
		if strings.ContainsAny(stdin.Text(), "Nn") {
			return
		}
	}

	log.Printf("Permission auto allowed for %s\nPattern: %s", path, conf.Pattern.String())
	resp.Error = 0
	resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	return
}

func resolveProcessPath(pid int, dirfd int, path string) (string, error) {
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

	if err := SendFD(childSock, fd); err != nil {
		return err
	}

	arg, err := exec.LookPath(os.Args[2])
	if err != nil {
		return err
	}

	err = unix.Exec(arg, os.Args[2:], os.Environ())
	return err
}

func ProcessCWD(pid, dirfd int) (string, error) {
	if dirfd == unix.AT_FDCWD {
		return os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	} else {
		return os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
	}
}

type Perm int

const (
	PermDeny Perm = iota
	PermAsk
	PermAllow
)

type Intent struct {
	Program string
	Path    string
	Read    bool
	Write   bool
}

type Config struct {
	Program string
	Pattern *regexp.Regexp
	Read    Perm
	Write   Perm
}

func (c Config) PermForIntent(intent Intent) Perm {
	if intent.Read && c.Read == PermDeny {
		return PermDeny
	}
	if intent.Write && c.Write == PermDeny {
		return PermDeny
	}

	if intent.Read && c.Read == PermAsk {
		return PermAsk
	}
	if intent.Write && c.Write == PermAsk {
		return PermAsk
	}

	return PermAllow
}

func ParseConfig(r io.Reader) ([]Config, error) {
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

func FindConfigMatch(configs []Config, intent Intent) (Config, bool) {
	for _, conf := range slices.Backward(configs) {
		if intent.Program != conf.Program && conf.Program != "*" {
			continue
		}
		if !conf.Pattern.MatchString(intent.Path) {
			continue
		}
		return conf, true
	}

	return Config{
		Program: intent.Program,
		Pattern: regexp.MustCompile(".*"),
		Read:    PermAsk,
		Write:   PermAsk,
	}, false
}

func SendFD(sock int, fd int) error {
	rights := unix.UnixRights(fd)
	return unix.Sendmsg(sock, []byte{0}, rights, nil, 0)
}

func RecvFD(sock int) (int, error) {
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
