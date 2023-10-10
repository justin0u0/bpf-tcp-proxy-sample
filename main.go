package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/justin0u0/bpf-tcp-proxy-sample/cmd"
	"github.com/spf13/cobra"
)

func main() {
	c := &cobra.Command{
		Use: "bpf-tcp-proxy-sample",
	}

	c.AddCommand(
		cmd.ProxyCommand(),
		cmd.ServerCommand(),
	)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if err := c.ExecuteContext(ctx); err != nil {
		panic(err)
	}
}
