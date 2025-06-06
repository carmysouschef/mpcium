package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

func main() {
	const environment = "development"
	// config.InitViperConfig()
	logger.Init(environment, false)

	natsURL := "nats://localhost:4222"
	natsConn, err := nats.Connect(natsURL)
	if err != nil {
		logger.Fatal("Failed to connect to NATS", err)
	}
	defer natsConn.Drain() // drain inflight msgs
	defer natsConn.Close()

	mpcClient := client.NewMPCClient(client.Options{
		NatsConn: natsConn,
		KeyPath:  "/home/viet/Documents/other/mpcium/event_initiator.key",
	})
	err = mpcClient.OnWalletCreationResult(func(event mpc.KeygenSuccessEvent) {
		logger.Info("Received wallet creation result", "event", event)
	})
	if err != nil {
		logger.Fatal("Failed to subscribe to wallet-creation results", err)
	}

	walletID := uuid.New().String()
	if err := mpcClient.CreateWallet(walletID); err != nil {
		logger.Fatal("CreateWallet failed", err)
	}
	logger.Info("CreateWallet sent, awaiting result...", "walletID", walletID)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	fmt.Println("Shutting down.")
}
