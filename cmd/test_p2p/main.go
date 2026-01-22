package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/yixinin/iroh-go/common"
	"github.com/yixinin/iroh-go/crypto"
	"github.com/yixinin/iroh-go/discovery"
	"github.com/yixinin/iroh-go/magicsock"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: test_p2p <node1|node2>")
		os.Exit(1)
	}

	mode := os.Args[1]

	switch mode {
	case "node1":
		runNode1()
	case "node2":
		runNode2()
	default:
		fmt.Println("Invalid mode. Use 'node1' or 'node2'")
		os.Exit(1)
	}
}

func runNode1() {
	log.Println("Starting Node 1...")

	opts := magicsock.Options{
		RelayMode: common.RelayModeDefault,
		SecretKey: crypto.NewSecretKey(),
		ALPNs:     [][]byte{[]byte(magicsock.DefaultALPN)},
		Discovery: discovery.DefaultDiscovery(),
	}

	ms, err := magicsock.NewMagicSock(opts)
	if err != nil {
		log.Fatalf("Failed to create MagicSock: %v", err)
	}
	defer ms.Close()

	log.Printf("Node 1 started with ID: %s", ms.Id().String())
	log.Printf("Node 1 addresses: %v", ms.Addr().Addrs)

	log.Println("Node 1 is ready. Waiting for connections...")
	time.Sleep(60 * time.Second)
}

func runNode2() {
	log.Println("Starting Node 2...")

	opts := magicsock.Options{
		RelayMode: common.RelayModeDefault,
		SecretKey: crypto.NewSecretKey(),
		ALPNs:     [][]byte{[]byte("test")},
		Discovery: discovery.DefaultDiscovery(),
	}

	ms, err := magicsock.NewMagicSock(opts)
	if err != nil {
		log.Fatalf("Failed to create MagicSock: %v", err)
	}
	defer ms.Close()

	log.Printf("Node 2 started with ID: %s", ms.Id().String())
	log.Printf("Node 2 addresses: %v", ms.Addr().Addrs)

	if len(os.Args) < 3 {
		log.Println("Usage: test_p2p node2 <remote_endpoint_id>")
		os.Exit(1)
	}

	remoteIdStr := os.Args[2]
	remoteId, err := crypto.ParseEndpointId(remoteIdStr)
	if err != nil {
		log.Fatalf("Invalid remote endpoint ID: %v", err)
	}

	log.Printf("Attempting to connect to remote endpoint: %s", remoteIdStr)

	addr := magicsock.EndpointAddr{
		Id:    remoteId,
		Addrs: []common.TransportAddr{},
	}

	conn, err := ms.Connect(addr, []byte("test"))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Conn().CloseWithError(0, "")

	log.Printf("Successfully connected to remote endpoint: %s", remoteIdStr)
	log.Printf("Connection ALPN: %s", string(conn.ALPN()))

	log.Println("Connection established successfully!")
	time.Sleep(10 * time.Second)
}
