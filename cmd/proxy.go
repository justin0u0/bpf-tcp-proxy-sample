package cmd

import (
	"encoding/hex"
	"log"
	"net"
	"sync"

	"github.com/justin0u0/bpf-tcp-proxy-sample/bpf"
	"github.com/spf13/cobra"
)

func ProxyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "proxy",
		Run: runProxy,
	}
	cmd.Flags().StringP("local", "l", ":8081", "local address")
	cmd.Flags().StringP("remote", "r", "server:8080", "remote address")
	cmd.Flags().BoolP("bpf", "b", false, "enable BPF programs")

	return cmd
}

func runProxy(cmd *cobra.Command, args []string) {
	ctx := cmd.Context()

	enableBPF, err := cmd.Flags().GetBool("bpf")
	if err != nil {
		log.Fatalln("Failed to get enable-bpf:", err)
	}

	if enableBPF {
		objs, err := bpf.LoadObjects()
		if err != nil {
			log.Fatalln("Failed to load objects:", err)
		}
		defer objs.Close()

		{
			cancel, err := bpf.AttachProgram(objs, bpf.ProgramSockops)
			if err != nil {
				log.Fatalf("Failed to attach sockops program: %v\n", err)
			}
			defer cancel()
		}
		{
			cancel, err := bpf.AttachProgram(objs, bpf.ProgramSkSkb)
			if err != nil {
				log.Fatalf("Failed to attach sk_skb program: %v\n", err)
			}
			defer cancel()
		}

		log.Println("BPF programs are attached")
	}

	localAddr, err := cmd.Flags().GetString("local")
	if err != nil {
		log.Fatalf("Failed to get local address: %v", err)
	}
	remoteAddr, err := cmd.Flags().GetString("remote")
	if err != nil {
		log.Fatalf("Failed to get remote address: %v", err)
	}

	conn, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer conn.Close()

	log.Printf("Listening on %s", conn.Addr())

	go func() {
		for {
			lconn, err := conn.Accept()
			if err != nil {
				log.Println("Failed to accept connection:", err)
				continue
			}

			go func() {
				defer lconn.Close()

				rconn, err := net.Dial("tcp", remoteAddr)
				if err != nil {
					log.Printf("Failed to connect to remote: %v\n", err)
					return
				}
				defer rconn.Close()

				log.Printf("Connected to remote server [%s]->[%s]", rconn.LocalAddr(), rconn.RemoteAddr())

				wg := &sync.WaitGroup{}
				wg.Add(2)

				go func() {
					log.Println("Starting to forward traffic from client to server")

					defer wg.Done()

					for {
						buf := make([]byte, 1024)
						n, err := lconn.Read(buf)
						if err != nil {
							log.Println("Failed to read from client:", err)
							return
						}
						log.Printf("Received %d bytes from client\n%s\n", n, hex.Dump(buf[:n]))

						m, err := rconn.Write(buf[:n])
						if err != nil {
							log.Println("Failed to write to server:", err)
							return
						}
						log.Printf("Sent %d bytes to server\n%s\n", m, hex.Dump(buf[:m]))
					}
				}()

				go func() {
					log.Println("Starting to forward traffic from server to client")

					defer wg.Done()

					for {
						buf := make([]byte, 1024)
						n, err := rconn.Read(buf)
						if err != nil {
							log.Println("Failed to read from server:", err)
							return
						}
						log.Printf("Received %d bytes from server\n%s\n\n", n, hex.Dump(buf[:n]))

						m, err := lconn.Write(buf[:n])
						if err != nil {
							log.Println("Failed to write to client:", err)
							return
						}
						log.Printf("Sent %d bytes to client\n%s\n", m, hex.Dump(buf[:m]))
					}
				}()

				wg.Wait()

				log.Println("Connection closed")
			}()
		}
	}()

	<-ctx.Done()
}
