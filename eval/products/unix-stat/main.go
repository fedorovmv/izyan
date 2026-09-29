// unix-stat reports filesystem capacity for the node agent: it uses
// unix.Statfs and unix.Geteuid — it never performs access checks.
package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func report(path string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return err
	}
	fmt.Printf("%s: bfree=%d uid=%d\n", path, st.Bfree, unix.Geteuid())
	return nil
}

func main() {
	for _, p := range os.Args[1:] {
		if err := report(p); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
}
