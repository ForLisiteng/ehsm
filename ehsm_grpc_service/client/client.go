package main

import (
	"context"
	"log"
	"time"

	pb "proto"

	"google.golang.org/grpc"
)

const (
	address = "localhost:50051"
)

func main() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewKeyManagementServiceClient(conn)

	keyid := "John"
	plaintext := "test"
	aad := "add"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	response, err := c.Encrypt(ctx, &pb.EncryptRequest{Keyid: keyid, Aad: aad, Plaintext: plaintext})
	if err != nil {
		log.Fatalf("encrypt failed: %v", err)
	}
	log.Printf("Ciphertext: %s", response.Ciphertext)
}
