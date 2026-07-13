//go:build linux && amd64

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
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

var configs []Config

var program string

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "args: ", os.Args)
		fmt.Fprintln(os.Stderr, "missing target program")
		os.Exit(1)
	}

	if os.Args[1] == "--child" {
		err := runChild()
		panic(err)
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

type SeccompNotif struct {
	ID    uint64
	Pid   uint32
	Flags uint32
	Data  SeccompData
}

type SeccompData struct {
	Nr   int32
	Arch uint32
	IP   uint64
	Args [6]uint64
}

type SeccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

type SeccompNotifAddFD struct {
	ID         uint64
	Flags      uint32
	SrcFD      uint32
	NewFD      uint32
	NewFDFlags uint32
}

func runParent(ctx context.Context, childSock, parentSock int) error {
	usePopup := false
	log.SetFlags(log.Lshortfile)
	log.SetOutput(io.Discard)

	// TODO: use flag package in future if i feel its necessary
	for {
		if os.Args[1] == "-v" {
			log.SetOutput(os.Stderr)
			os.Args = append(os.Args[:1], os.Args[2:]...)
			continue
		}

		if os.Args[1] == "-popup" {
			usePopup = true
			os.Args = append(os.Args[:1], os.Args[2:]...)
			continue
		}

		break
	}

	program = path.Base(os.Args[1])

	// necessary to run seccomp without privileges.
	// the limitation is that the child process can't use sudo or similar.
	// `mayi sudo ls` wont work, but `sudo mayi ls` will.
	err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	if err != nil {
		return err
	}

	// make child process treat mayi process as their "init process", in a sense
	// that any orphan process will be reparented to mayi, instead of PID 1.
	// we can only (easily) read memory from descendant processes, so this fixes
	// programs that spawn a lot of processes.
	err = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
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
	log.Printf("initial PID: %d", initialPid)

	err = unix.Close(childSock)
	if err != nil {
		return err
	}

	seccompFD, err := recvFD(parentSock)
	if err != nil {
		return err
	}

	configPath := os.Getenv("MAYI_CONFIG")
	if configPath == "" {
		if os.Getenv("HOME") != "" {
			configPath = path.Join(os.Getenv("HOME"), "/.config/mayi.ini")
		}
	}

	if configPath != "" {
		log.Printf("loading config from: %s\n", configPath)
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

	promptUser := func(intent Intent) bool {
		for {
			fmt.Fprintf(os.Stderr, "%s\n[y/n]: ", intent.Prompt)
			if !stdin.Scan() {
				_ = stdin.Err()
				time.Sleep(500 * time.Millisecond)
				continue
			}
			text := strings.ToLower(strings.TrimSpace(stdin.Text()))
			if text == "n" {
				return false
			}
			if text != "y" {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return true
		}
	}

	for _, conf := range slices.Backward(configs) {
		if conf.Program != "*" && conf.Program != program {
			continue
		}
		if conf.Key == "popup" && conf.Val == "true" {
			usePopup = true
			break
		}
	}

	if usePopup {
		if _, err := exec.LookPath("zenity"); err != nil {
			return errors.New("zenity is required to use popup")
		}
		promptUser = func(intent Intent) bool {
			cmd := exec.CommandContext(
				ctx,
				"zenity",
				"--question",
				"--title",
				"mayi",
				"--text",
				intent.Program+": "+intent.Prompt,
			)

			err := cmd.Run()
			if err == nil {
				return true
			}

			return false
		}
	}

	for {
		req := SeccompNotif{}
		_, _, errno := unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(seccompFD),
			unix.SECCOMP_IOCTL_NOTIF_RECV,
			uintptr(unsafe.Pointer(&req)),
		)
		// TODO: understand when this syscall returns ENOENT
		// right now i check if the process exited, and if not i just ignore
		// ENOENT and repeat the loop
		if errno == unix.ENOENT {
			var status unix.WaitStatus
			wpid, err := unix.Wait4(initialPid, &status, unix.WNOHANG, nil)
			if err != nil {
				return err
			}

			if wpid == 0 {
				continue
			}

			if status.Exited() {
				os.Exit(status.ExitStatus())
			}

			if status.Signaled() {
				os.Exit(1)
			}
			continue
		}
		if errno != 0 {
			fmt.Printf("%d: %s\n", errno, errno)
			return errno
		}

		resp, err := processSeccompNotifReq(seccompFD, req, promptUser)
		if err != nil {
			fmt.Fprintln(os.Stderr, "processSeccompNotifReq: ", err)
		}

		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(seccompFD),
			unix.SECCOMP_IOCTL_NOTIF_SEND,
			uintptr(unsafe.Pointer(&resp)),
		)
		if errno == unix.ENOENT {
			var status unix.WaitStatus
			wpid, err := unix.Wait4(initialPid, &status, unix.WNOHANG, nil)
			if err != nil {
				return err
			}

			if wpid == 0 {
				continue
			}

			if status.Exited() {
				os.Exit(status.ExitStatus())
			}

			if status.Signaled() {
				os.Exit(1)
			}
			continue
		}
		if errno != 0 {
			log.Printf("%d: %s\n", errno, errno)
			return errno
		}
	}
}

func requestPermission(intent Intent, promptUser func(Intent) bool) Perm {
	perm := permForIntent(configs, intent)

	switch perm {
	case PermDeny, PermAllow:
	case PermAsk:
		log.Print("asking permission for ", intent)
		accepted := promptUser(intent)
		if accepted {
			perm = PermAllow
		} else {
			perm = PermDeny
		}

		for _, action := range intent.Actions {
			read := PermAsk
			if action.Read {
				read = perm
			}

			write := PermAsk
			if action.Write {
				write = perm
			}

			configs = append(configs, Config{
				Program: intent.Program,
				Pattern: regexp.MustCompile("^" + regexp.QuoteMeta(action.Path) + "$"),
				Read:    read,
				Write:   write,
			})
		}
	default:
		perm = PermDeny
	}

	if perm == PermDeny {
		fmt.Fprint(os.Stderr, "Permission denied for: ")
		for _, action := range intent.Actions {
			fmt.Fprint(os.Stderr, action.Path, ", ")
		}
		fmt.Fprintln(os.Stderr)
	}

	return perm
}

// describe what the syscall is trying to do.
func processSeccompNotifReq(seccompFD int, req SeccompNotif, promptUser func(Intent) bool) (SeccompNotifResp, error) {
	respDeny := SeccompNotifResp{
		ID:    req.ID,
		Error: -int32(unix.EACCES),
	}

	switch req.Data.Nr {
	case unix.SYS_OPEN, unix.SYS_CREAT, unix.SYS_OPENAT, unix.SYS_OPENAT2:
		dirfd := unix.AT_FDCWD
		rawPath := uintptr(0)
		flags := unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC
		mode := uint32(0)

		switch req.Data.Nr {
		case unix.SYS_OPEN:
			rawPath = uintptr(req.Data.Args[0])
			flags = int(int32(req.Data.Args[1]))
			mode = uint32(req.Data.Args[2])
		case unix.SYS_CREAT:
			rawPath = uintptr(req.Data.Args[0])
			mode = uint32(req.Data.Args[1])
		case unix.SYS_OPENAT:
			dirfd = int(int32(req.Data.Args[0]))
			rawPath = uintptr(req.Data.Args[1])
			flags = int(int32(req.Data.Args[2]))
			mode = uint32(req.Data.Args[3])
		case unix.SYS_OPENAT2:
			dirfd = int(int32(req.Data.Args[0]))
			rawPath = uintptr(req.Data.Args[1])
			// TODO: handle arg[2] open_how
		default:
			panic("wtf?")
		}

		// O_PATH is used to open the file as a "relative directory".
		// The kernel doesn't allow reading, writing nor changing metadata.
		// This kind of file descriptor cannot be transfered using seccomp,
		// but we shouldn't(?) worry about TOCTOU in this case since this
		// operation doesn't seem dangerous.
		if flags&unix.O_PATH != 0 {
			return SeccompNotifResp{
				ID:    req.ID,
				Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE,
			}, nil
		}

		realPath, err := readProcessString(int(req.Pid), rawPath)
		if err != nil {
			return respDeny, fmt.Errorf("open(%d): %w", req.Data.Nr, err)
		}

		realPath, err = resolveProcessPath(int(req.Pid), dirfd, realPath)
		if err != nil {
			return respDeny, fmt.Errorf("open(%d): %w", req.Data.Nr, err)
		}

		read := false
		write := false
		var prompt string

		switch flags & unix.O_ACCMODE {
		case unix.O_RDONLY:
			read = true
			prompt = fmt.Sprintf("May I read from '%s'?", realPath)
		case unix.O_WRONLY:
			write = true
			prompt = fmt.Sprintf("May I write to '%s'?", realPath)
		case unix.O_RDWR:
			read = true
			write = true
			prompt = fmt.Sprintf("May I read AND write to '%s'?", realPath)
		default:
			// TODO:
			read = true
			write = true
			prompt = fmt.Sprintf("May I potentially read AND write your '%s'?", realPath)
		}

		intent := Intent{
			Program: program,
			Prompt:  prompt,
			Actions: []Action{
				{
					Path:  realPath,
					Read:  read,
					Write: write,
				},
			},
		}

		if requestPermission(intent, promptUser) == PermAllow {
			fd, err := unix.Openat(unix.AT_FDCWD, realPath, flags, mode)
			if errno, as := errors.AsType[unix.Errno](err); as {
				return SeccompNotifResp{
					ID:    req.ID,
					Error: -int32(errno),
				}, nil
			}
			if err != nil {
				return respDeny, nil
			}
			defer unix.Close(fd)

			addfd := SeccompNotifAddFD{
				ID:    req.ID,
				SrcFD: uint32(fd),
			}

			childFD, _, errno := unix.Syscall(
				unix.SYS_IOCTL,
				uintptr(seccompFD),
				unix.SECCOMP_IOCTL_NOTIF_ADDFD,
				uintptr(unsafe.Pointer(&addfd)),
			)
			if errno != 0 {
				return respDeny, errno
			}

			return SeccompNotifResp{
				ID:  req.ID,
				Val: int64(childFD),
			}, nil
		}

		return respDeny, nil

	case unix.SYS_UNLINK, unix.SYS_UNLINKAT:
		dirfd := unix.AT_FDCWD
		rawPath := uintptr(0)
		flags := 0

		switch req.Data.Nr {
		case unix.SYS_UNLINK:
			rawPath = uintptr(req.Data.Args[0])
		case unix.SYS_UNLINKAT:
			dirfd = int(int32(req.Data.Args[0]))
			rawPath = uintptr(req.Data.Args[1])
			flags = int(int32(req.Data.Args[2]))
		}

		realPath, err := readProcessString(int(req.Pid), rawPath)
		if err != nil {
			return respDeny, fmt.Errorf("unlink(%d): %w", req.Data.Nr, err)
		}

		realPath, err = resolveProcessPath(int(req.Pid), dirfd, realPath)
		if err != nil {
			return respDeny, fmt.Errorf("unlink(%d): %w", req.Data.Nr, err)
		}

		intent := Intent{
			Program: program,
			Prompt:  fmt.Sprintf("May I delete your '%s'?", realPath),
			Actions: []Action{
				{
					Path:  realPath,
					Read:  false,
					Write: true,
				},
			},
		}

		if requestPermission(intent, promptUser) == PermAllow {
			err := unix.Unlinkat(unix.AT_FDCWD, realPath, flags)
			if errno, as := errors.AsType[unix.Errno](err); as {
				return SeccompNotifResp{
					ID:    req.ID,
					Error: -int32(errno),
				}, nil
			}
			if err != nil {
				return respDeny, nil
			}

			return SeccompNotifResp{
				ID: req.ID,
			}, nil
		}

		return respDeny, nil

	case unix.SYS_RENAME, unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2:
		oldDirfd := unix.AT_FDCWD
		newDirfd := unix.AT_FDCWD
		rawOldPath := uintptr(0)
		rawNewPath := uintptr(0)
		flags := uint(0)

		switch req.Data.Nr {
		case unix.SYS_RENAME:
			rawOldPath = uintptr(req.Data.Args[0])
			rawNewPath = uintptr(req.Data.Args[1])
		case unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2:
			oldDirfd = int(int32(req.Data.Args[0]))
			rawOldPath = uintptr(req.Data.Args[1])
			newDirfd = int(int32(req.Data.Args[2]))
			rawNewPath = uintptr(req.Data.Args[3])
			flags = uint(req.Data.Args[4])
		}

		oldPath, err := readProcessString(int(req.Pid), rawOldPath)
		if err != nil {
			return respDeny, fmt.Errorf("rename(%d): %w", req.Data.Nr, err)
		}

		oldPath, err = resolveProcessPath(int(req.Pid), oldDirfd, oldPath)
		if err != nil {
			return respDeny, fmt.Errorf("rename(%d): %w", req.Data.Nr, err)
		}

		newPath, err := readProcessString(int(req.Pid), rawNewPath)
		if err != nil {
			return respDeny, fmt.Errorf("rename(%d): %w", req.Data.Nr, err)
		}

		newPath, err = resolveProcessPath(int(req.Pid), newDirfd, newPath)
		if err != nil {
			return respDeny, fmt.Errorf("rename(%d): %w", req.Data.Nr, err)
		}

		intent := Intent{
			Program: program,
			Prompt:  fmt.Sprintf("May I rename '%s' to '%s'?", oldPath, newPath),
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
		}

		if requestPermission(intent, promptUser) == PermAllow {
			err := unix.Renameat2(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, flags)
			if errno, as := errors.AsType[unix.Errno](err); as {
				return SeccompNotifResp{
					ID:    req.ID,
					Error: -int32(errno),
				}, nil
			}
			if err != nil {
				return respDeny, nil
			}

			return SeccompNotifResp{
				ID: req.ID,
			}, nil
		}

		return respDeny, nil
	}

	return respDeny, errors.New("Syscall handling not implemented")
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

// uses syscall process_vm_readv to read process memory at address addr
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

	err2 := fmt.Errorf("process_vm_readv(pid=%d - addr=%X)", pid, addr)

	n, err := unix.ProcessVMReadv(pid, local, remote, 0)
	if err != nil {
		{
			b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
			log.Printf("process %d status: %s - %v", pid, string(b), err)
		}
		return "", fmt.Errorf("%w: %w", err2, err)
	}

	if n < 0 {
		return "", fmt.Errorf("%w: couldn't read process memory", err2)
	}
	buf = buf[:n]

	n = slices.Index(buf, 0)
	if n < 0 {
		return "", fmt.Errorf("%w: didn't read a null terminated string", err2)
	}

	return unsafe.String(&buf[0], n), nil
}

func runChild() error {
	// we need to ensure the Exec in the end is running on the same OS thread as the one
	// we installed seccomp, otherwise it won't have any effect...
	// I found this bug running a loop 1000 times doing mayi cat ~/secret
	// TODO: add a test for this
	runtime.LockOSThread()

	var err error

	// inherited at ForkExec
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
		// LD at register A (default) a Word (amd64 = 8 bytes) from the absolute address 0,
		// which is the start of the system call data struct, where its number (see req.Data.Nr) is located
		bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0),

		// jmp to next line (user notify) if syscall is open, otherwise skip next like
		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_OPEN, 0, 1),
		bpfStmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_USER_NOTIF),

		// and the same idea as before repeats until the end.
		// it may be more efficient to just have a single RET statement and make all jumps to a single place
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

		// if its none of the intercepted system calls, just allow it
		bpfStmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW),
	}

	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	r1, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER,
		uintptr(unsafe.Pointer(&prog)),
	)
	fd := int(r1)
	if errno != 0 {
		return errno
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

func (p Perm) String() string {
	switch p {
	case PermDeny:
		return "DENY"
	case PermAsk:
		return "ASK"
	case PermAllow:
		return "ALLOW"
	default:
		panic("wtf")
	}
}

// TODO: make it more flexible.
// Maybe use "inherited" types for Action instead of a []Action, for example
// RenameAction, OpenAction, DeleteAction. These types can even contain the
// system call number and arguments, which will make  calling the syscall
// from the supervisor easier.
// Or even just use a single Action type capable of holding all that info.
// That will also remove the need of the `Prompt` key, since the caller
// could make the prompt from the action type, affected paths (if any)...
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

// Initially config would be just a path regexp and the permissions on that path.
// But now I'm expanding it to allow other types of keys and values.
// Maybe I should rewrite this type
type Config struct {
	Program string
	Key     string
	Val     string
	Pattern *regexp.Regexp
	Read    Perm
	Write   Perm
}

func (c Config) String() string {
	pattern := ""
	if c.Pattern != nil {
		pattern = c.Pattern.String()
	}
	return fmt.Sprintf(
		`{Program: "%s", Key: "%s", Val: "%s", Pattern: "%s", Read: %s, Write: %s}`,
		c.Program,
		c.Key,
		c.Val,
		pattern,
		c.Read.String(),
		c.Write.String(),
	)
}

func permForIntent(configs []Config, intent Intent) Perm {
	perm := PermAllow
	found := false

	for _, action := range intent.Actions {
		for _, conf := range slices.Backward(configs) {
			if intent.Program != conf.Program && conf.Program != "*" {
				continue
			}
			switch conf.Key {
			case "dirs":
				stat, err := os.Stat(action.Path)
				if err != nil {
					// fmt.Fprintf(os.Stderr, "failed to stat %s: %v\n", action.Path, err)
					continue
				}
				if !stat.IsDir() {
					continue
				}
			default:
				if conf.Pattern == nil || !conf.Pattern.MatchString(action.Path) {
					continue
				}
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
			break
		}
	}

	if !found {
		return PermAsk
	}

	return perm
}

// parses the .ini file, expands $ENV variables... paths must start with /
// otherwise they will be considered special keywords, like dirs and popup.
// see mayi.example.ini
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

		key := strings.TrimSpace(chunks[0])
		key = regexp.MustCompile(`\$\w+`).ReplaceAllStringFunc(key, func(prev string) string {
			key := prev[1:]
			env := os.Getenv(key)
			return env
		})

		conf := Config{
			Program: program,
			Key:     key,
			Read:    PermAsk,
			Write:   PermAsk,
		}

		if strings.HasPrefix(key, "/") {
			var err error
			conf.Pattern, err = regexp.Compile("^" + key + "$")
			if err != nil {
				fmt.Fprintln(os.Stderr, "[mayi] ignoring invalid regexp:", line)
			}
		}

		val := strings.TrimSpace(chunks[1])
		conf.Val = val
		for field := range strings.FieldsSeq(val) {
			switch field {
			case "write:deny":
				conf.Write = PermDeny
			case "write:ask":
				conf.Write = PermAsk
			case "write", "write:allow":
				conf.Write = PermAllow
			case "read:deny":
				conf.Read = PermDeny
			case "read:ask":
				conf.Read = PermAsk
			case "read", "read:allow":
				conf.Read = PermAllow
			case "allow":
				conf.Read = PermAllow
				conf.Write = PermAllow
			case "deny":
				conf.Read = PermDeny
				conf.Write = PermDeny
			case "ask":
				conf.Read = PermAsk
				conf.Write = PermAsk
			}
		}

		configs = append(configs, conf)
	}

	return configs, scanner.Err()
}

// passes a file descriptor from one process to the other via socket
func sendFD(sock int, fd int) error {
	rights := unix.UnixRights(fd)
	return unix.Sendmsg(sock, []byte{0}, rights, nil, 0)
}

// receives a file descriptor from the socket
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
