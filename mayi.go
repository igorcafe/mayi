package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "args: ", os.Args)
		fmt.Fprintln(os.Stderr, "missing target program")
		os.Exit(1)
	}

	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)

	if os.Args[1] == "--child" {
		fmt.Println("child!")
		childSock := 3
		_, err = unix.Write(childSock, []byte("hi"))
		if err != nil {
			panic(err)
		}

		for {
		}
		return
	}

	parentSock := sockets[0]
	childSock := sockets[1]

	pid, err := syscall.ForkExec(
		"/proc/self/exe",
		append([]string{"/proc/self/exe", "--child"}, os.Args[2:]...),
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
		panic(err)
	}

	err = unix.Close(childSock)
	if err != nil {
		panic(err)
	}

	buf := make([]byte, 10)
	_, err = unix.Read(parentSock, buf)
	if err != nil {
		panic(err)
	}
	fmt.Println("recv:", string(buf))

	cwd, err := ProcessCWD(pid, unix.AT_FDCWD)
	if err != nil {
		panic(err)
	}

	fmt.Println("cwd", cwd)

	var configs []Config

	file, err := os.Open("/home/igor/.config/mayi.ini")
	if err == nil {
		defer file.Close()
		configs, err = ParseConfig(file)
		// fmt.Printf("%+#v\n", configs)
		if err != nil {
			panic(err)
		}
	}

	conf, found := FindConfigMatch(configs, Intent{
		Program: "emacs",
		Path:    "/home/igor/.ssh",
		Read:    true,
		Write:   false,
	})

	fmt.Printf("%v - %+#v\n", found, conf)
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
	Pattern string
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
		text := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
			program = text[1 : len(text)-1]
			continue
		}

		chunks := strings.Split(text, "=")
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

		conf.Pattern = key
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

		configs = append(configs, conf)
	}

	return configs, scanner.Err()
}

func FindConfigMatch(configs []Config, intent Intent) (Config, bool) {
	for _, conf := range slices.Backward(configs) {
		if intent.Program != conf.Program && conf.Program != "*" {
			continue
		}
		if match, _ := path.Match(conf.Pattern, intent.Path); !match {
			continue
		}
		return conf, true
	}

	return Config{
		Program: intent.Program,
		Pattern: "*",
		Read:    PermAsk,
		Write:   PermAsk,
	}, false
}
