package main

import (
	"fmt"
	"os"

	"tee-test/internal/teeskscli"
)

func main() {
	if err := teeskscli.Run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
