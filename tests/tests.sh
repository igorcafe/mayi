#!/usr/bin/env bash

set -euo pipefail

rm -rf tmp
mkdir -p tmp
export MAYI_CONFIG="$PWD/tmp/mayi.ini"
echo '\
[*]
/nix/store/.* = read
/run/current-system/.* = read
' > "$MAYI_CONFIG"

test () {
    msg="$1"
    code="$2"

    if out=$(eval "$code" 2>&1)
    then
	echo -e "\e[32mPASS\e[0m: $msg"
	true
    else
	echo -e "\e[31mFAIL\e[0m: $msg:\n\$ $code\n\n$out"
	false
    fi
}

test 'mayi.c compiles' 'gcc ../mayi.c -Wall -o tmp/mayi'

test 'mayi.go compiles' 'CGO_ENABLED=0 go build -o tmp/mayi ../mayi.go'

#test 'mayi.c tests' 'gcc ../mayi.c -Wall -DTEST -o tmp/test && ./tmp/test'

test 'syscall.c compiles' 'gcc syscall.c -Wall -Wextra -o tmp/syscall'


test 'ls disallowed' '! echo "n" | ./tmp/mayi ls'
test 'ls allowed' 'echo "" | ./tmp/mayi ls'
test 'ls allowed' 'echo "Y" | ./tmp/mayi ls'

test 'touch disallowed' '! echo "n" | ./tmp/mayi touch tmp/touch'
test 'touch allowed' 'echo "" | ./tmp/mayi touch tmp/touch'
#test 'touch disallowed again' '! echo "n" | mayi touch '$touch_path''

printf '' > tmp/existing-open
test 'open read disallowed' '! echo "n" | ./tmp/mayi ./tmp/syscall open tmp/existing-open r'
test 'open read allowed' 'echo "" | ./tmp/mayi ./tmp/syscall open tmp/existing-open r'

test 'open create disallowed' '! echo "n" | ./tmp/mayi ./tmp/syscall open tmp/created-open wc'
test 'open create allowed' 'echo "" | ./tmp/mayi ./tmp/syscall open tmp/created-open wc'

test 'creat disallowed' '! echo "n" | ./tmp/mayi ./tmp/syscall creat tmp/created-creat'
test 'creat allowed' 'echo "" | ./tmp/mayi ./tmp/syscall creat tmp/created-creat'

printf '' > tmp/existing-openat
test 'openat read disallowed' '! echo "n" | ./tmp/mayi ./tmp/syscall openat tmp/existing-openat r'
test 'openat read allowed' 'echo "" | ./tmp/mayi ./tmp/syscall openat tmp/existing-openat r'

test 'openat create disallowed' '! echo "n" | ./tmp/mayi ./tmp/syscall openat tmp/created-openat wc'
test 'openat create allowed' 'echo "" | ./tmp/mayi ./tmp/syscall openat tmp/created-openat wc'

printf '' > tmp/existing-openat2
test 'openat2 read disallowed' '! echo "n" | ./tmp/mayi ./tmp/syscall openat2 tmp/existing-openat2 r'
test 'openat2 read allowed' 'echo "" | ./tmp/mayi ./tmp/syscall openat2 tmp/existing-openat2 r'

test 'openat2 create disallowed' '! echo "n" | ./tmp/mayi ./tmp/syscall openat2 tmp/created-openat2 wc'
test 'openat2 create allowed' 'echo "" | ./tmp/mayi ./tmp/syscall openat2 tmp/created-openat2 wc'

printf '' > tmp/delete-unlink
test 'unlink disallowed' '! echo "n" | ./tmp/mayi ./tmp/syscall unlink tmp/delete-unlink'
test 'unlink disallowed keeps file' '[ -e tmp/delete-unlink ]'
test 'unlink allowed' 'echo "" | ./tmp/mayi ./tmp/syscall unlink tmp/delete-unlink'
test 'unlink allowed deletes file' '[ ! -e tmp/delete-unlink ]'

printf '' > tmp/delete-unlinkat
test 'unlinkat disallowed' '! echo "n" | ./tmp/mayi ./tmp/syscall unlinkat tmp/delete-unlinkat'
test 'unlinkat disallowed keeps file' '[ -e tmp/delete-unlinkat ]'
test 'unlinkat allowed' 'echo "" | ./tmp/mayi ./tmp/syscall unlinkat tmp/delete-unlinkat'
test 'unlinkat allowed deletes file' '[ ! -e tmp/delete-unlinkat ]'

printf '' > tmp/delete-rm
test 'rm disallowed' '! echo "n" | ./tmp/mayi rm tmp/delete-rm'
test 'rm disallowed keeps file' '[ -e tmp/delete-rm ]'
test 'rm allowed' 'echo "" | ./tmp/mayi rm tmp/delete-rm'
test 'rm allowed deletes file' '[ ! -e tmp/delete-rm ]'

mkdir -p tmp/delete-rm-r
printf '' > tmp/delete-rm-r/file
test 'rm -r disallowed' '! echo "n" | ./tmp/mayi rm -r tmp/delete-rm-r'
test 'rm -r disallowed keeps directory' '[ -d tmp/delete-rm-r ]'
test 'rm -r disallowed keeps file' '[ -e tmp/delete-rm-r/file ]'
test 'rm -r allowed' 'printf "\n\n\n" | ./tmp/mayi rm -r tmp/delete-rm-r'
test 'rm -r allowed deletes directory' '[ ! -e tmp/delete-rm-r ]'

printf '' > tmp/rename-old
test 'rename disallowed' '! echo "n" | ./tmp/mayi ./tmp/syscall rename tmp/rename-old tmp/rename-new'
test 'rename disallowed keeps old path' '[ -e tmp/rename-old ]'
test 'rename disallowed keeps new path missing' '[ ! -e tmp/rename-new ]'
test 'rename allowed' 'echo "" | ./tmp/mayi ./tmp/syscall rename tmp/rename-old tmp/rename-new'
test 'rename allowed removes old path' '[ ! -e tmp/rename-old ]'
test 'rename allowed creates new path' '[ -e tmp/rename-new ]'

printf '' > tmp/renameat-old
test 'renameat disallowed' '! echo "n" | ./tmp/mayi ./tmp/syscall renameat tmp/renameat-old tmp/renameat-new'
test 'renameat disallowed keeps old path' '[ -e tmp/renameat-old ]'
test 'renameat disallowed keeps new path missing' '[ ! -e tmp/renameat-new ]'
test 'renameat allowed' 'echo "" | ./tmp/mayi ./tmp/syscall renameat tmp/renameat-old tmp/renameat-new'
test 'renameat allowed removes old path' '[ ! -e tmp/renameat-old ]'
test 'renameat allowed creates new path' '[ -e tmp/renameat-new ]'

printf '' > tmp/renameat2-old
test 'renameat2 disallowed' '! echo "n" | ./tmp/mayi ./tmp/syscall renameat2 tmp/renameat2-old tmp/renameat2-new'
test 'renameat2 disallowed keeps old path' '[ -e tmp/renameat2-old ]'
test 'renameat2 disallowed keeps new path missing' '[ ! -e tmp/renameat2-new ]'
test 'renameat2 allowed' 'echo "" | ./tmp/mayi ./tmp/syscall renameat2 tmp/renameat2-old tmp/renameat2-new'
test 'renameat2 allowed removes old path' '[ ! -e tmp/renameat2-old ]'
test 'renameat2 allowed creates new path' '[ -e tmp/renameat2-new ]'
