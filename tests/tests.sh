#!/usr/bin/env bash

set -euo pipefail

rm -rf tmp
mkdir -p tmp

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
