package main

import (
	"fmt"
	"runtime"
	"unsafe"
)

/*
#include <shadow.h>
#include <crypt.h>
#include <string.h>
#include <stdlib.h>
#cgo linux LDFLAGS: -lcrypt
*/
import "C"

func AuthPasswd(name string, passwd string) bool {
	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))

	passwdC := C.CString(passwd)
	defer C.free(unsafe.Pointer(passwdC))

	pwd := C.getspnam(nameC)
	if pwd == nil {
		return false
	}
	crypted := C.crypt(passwdC, pwd.sp_pwdp)
	rv := C.strcmp(crypted, pwd.sp_pwdp)
	if rv != 0 {
		return false
	}

	return true
}