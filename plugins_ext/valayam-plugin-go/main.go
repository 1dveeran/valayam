package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	pb "valayam-plugin-go/plugin"
)

type pluginServer struct {
	pb.UnimplementedPluginServiceServer
}

func (s *pluginServer) Init(ctx context.Context, req *pb.InitRequest) (*pb.InitResponse, error) {
	return &pb.InitResponse{Success: true, ErrorMessage: ""}, nil
}

func (s *pluginServer) ValidateConfig(ctx context.Context, req *pb.ValidateConfigRequest) (*pb.ValidateConfigResponse, error) {
	return &pb.ValidateConfigResponse{Valid: true, ErrorMessage: ""}, nil
}

func (s *pluginServer) Execute(req *pb.ExecuteRequest, stream pb.PluginService_ExecuteServer) error {
	finding := map[string]interface{}{
		"template_id":   "go-example",
		"template_name": "Go Example Plugin",
		"severity":      "info",
		"target":        req.Target,
		"matched_at":    "example match from Go",
		"metadata":      map[string]interface{}{},
	}

	findingJson, _ := json.Marshal(finding)

	return stream.Send(&pb.ExecuteResponse{
		FindingJson: string(findingJson),
	})
}

func (s *pluginServer) Shutdown(ctx context.Context, req *pb.ShutdownRequest) (*pb.ShutdownResponse, error) {
	// The core engine will kill the process anyway, but we could gracefully stop here
	go func() {
		os.Exit(0)
	}()
	return &pb.ShutdownResponse{Success: true}, nil
}

func main() {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	addr := lis.Addr().(*net.TCPAddr)
	
	// HashiCorp go-plugin protocol handshake
	fmt.Printf("1|plugin|tcp|127.0.0.1:%d|grpc\n", addr.Port)

	s := grpc.NewServer()
	pb.RegisterPluginServiceServer(s, &pluginServer{})
	
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
