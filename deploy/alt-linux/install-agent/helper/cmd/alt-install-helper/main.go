package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	helper "github.com/BorisDruzak/ui_vpn/deploy/alt-linux/install-agent/helper"
)

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(), os.Interrupt, syscall.SIGTERM,
	)
	defer stop()
	os.Exit(helper.Main(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
