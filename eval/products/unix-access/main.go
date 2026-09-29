// unix-access runs a mount-hardening check on Linux agents: it asks the
// kernel whether the agent's effective credentials can read each mount's
// policy file via unix.Faccessat with AT_EACCESS.
package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func agentCanRead(dir, name string) bool {
	err := unix.Faccessat(unix.AT_FDCWD, dir+"/"+name, unix.R_OK, unix.AT_EACCESS)
	return err == nil
}

func main() {
	for _, mount := range os.Args[1:] {
		if !agentCanRead(mount, "policy.conf") {
			fmt.Printf("%s: skip (policy unreadable)\n", mount)
			continue
		}
		fmt.Printf("%s: enforcing policy\n", mount)
	}
}
