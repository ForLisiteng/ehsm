package main

import (
	"context"
	"log"
	"net"

	pb "github.com/ForLisiteng/ehsm/ehsm_grpc_service/service/proto"

	ehsm "github.com/intel/ehsm/sdk/go"
	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedKeyManagementServiceServer
}

func (s *server) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	client, err := ehsm.NewClient()
	if err != nil {
		return nil, err
	}
	plaintext, err := client.Decrypt(req.Keyid, req.Aad, req.Ciphertext)
	if err != nil {
		return nil, err
	}
	return &pb.DecryptResponse{Plaintext: plaintext}, nil
}
func (s *server) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	client, err := ehsm.NewClient()
	if err != nil {
		return nil, err
	}
	ciphertext, err := client.Encrypt(req.Keyid, req.Aad, req.Plaintext)
	if err != nil {
		return nil, err
	}
	return &pb.EncryptResponse{Ciphertext: ciphertext}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterKeyManagementServiceServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
