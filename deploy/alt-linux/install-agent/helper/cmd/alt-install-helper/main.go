package main

import (
	"context"
	"os"

	helper "github.com/BorisDruzak/ui_vpn/deploy/alt-linux/install-agent/helper"
)

func main() {
	os.Exit(helper.Main(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
