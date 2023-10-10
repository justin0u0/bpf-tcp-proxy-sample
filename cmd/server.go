package cmd

import (
	"errors"
	"io"
	"log"
	"net"

	"github.com/spf13/cobra"
)

func ServerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "server",
		Run: runServer,
	}
	cmd.Flags().StringP("local", "l", ":8080", "local address")

	return cmd
}

func runServer(cmd *cobra.Command, args []string) {
	ctx := cmd.Context()

	localAddr, err := cmd.Flags().GetString("local")
	if err != nil {
		log.Fatalln("Failed to get local address:", err)
	}

	conn, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalln("Failed to listen:", err)
	}
	defer conn.Close()

	go func() {
		for {
			c, err := conn.Accept()
			if err != nil {
				log.Printf("Failed to accept: %v\n", err)
				continue
			}

			go func() {
				defer c.Close()

				buf := make([]byte, 1024)

				for {
					n, err := c.Read(buf)
					if err != nil {
						if errors.Is(err, io.EOF) {
							break
						}

						log.Println("Failed to read from connection:", err)
						continue
					}
					log.Printf("Received %d bytes %q from TCP %s", n, buf[:n], c.RemoteAddr())

					// echo back
					if _, err := c.Write(buf[:n]); err != nil {
						log.Println("Failed to write to connection:", err)
						continue
					}
				}

				log.Println("Closed connection from", c.RemoteAddr())
			}()
		}
	}()

	<-ctx.Done()
}
