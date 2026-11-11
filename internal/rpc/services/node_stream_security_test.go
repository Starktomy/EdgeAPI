package services

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/TeaOSLab/EdgeCommon/pkg/rpc/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func installTestNodeQueue(t *testing.T, nodeId int64, capacity int) chan *CommandRequest {
	t.Helper()
	queue := make(chan *CommandRequest, capacity)
	nodeLocker.Lock()
	nodeRequestChanMap[nodeId] = queue
	nodeLocker.Unlock()
	t.Cleanup(func() {
		nodeLocker.Lock()
		delete(nodeRequestChanMap, nodeId)
		for id, waiting := range nodeResponseChanMap {
			if waiting.NodeId == nodeId {
				waiting.Close()
				delete(nodeResponseChanMap, id)
			}
		}
		nodeLocker.Unlock()
	})
	return queue
}

func TestSecurityNodeResponseBindsAuthenticatedSession(t *testing.T) {
	const nodeId int64 = 987_601
	queue := installTestNodeQueue(t, nodeId, 1)
	result := make(chan *pb.NodeStreamMessage, 1)
	go func() {
		reply, _ := SendCommandToNode(nodeId, 0, "test", nil, 1, true)
		result <- reply
	}()
	var command *CommandRequest
	select {
	case command = <-queue:
	case <-time.After(time.Second):
		t.Fatal("command was not published")
	}
	reply := &pb.NodeStreamMessage{RequestId: command.Id, IsOk: true}
	if deliverNodeResponse(nodeId+1, queue, reply) {
		t.Fatal("another authenticated node completed this command")
	}
	if deliverNodeResponse(nodeId, make(chan *CommandRequest), reply) {
		t.Fatal("superseded node stream completed this command")
	}
	if !deliverNodeResponse(nodeId, queue, reply) {
		t.Fatal("immediate response was lost; pending reply must be registered before dispatch")
	}
	select {
	case got := <-result:
		if got == nil || !got.IsOk {
			t.Fatalf("expected authenticated reply: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("valid response did not complete command")
	}
}

func TestSecurityNodeCommandCancellationCleansPendingReply(t *testing.T) {
	const nodeId int64 = 987_602
	queue := installTestNodeQueue(t, nodeId, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := sendCommandToNode(ctx, nodeId, 0, "test", nil, 60, true)
		done <- err
	}()
	var command *CommandRequest
	select {
	case command = <-queue:
	case <-time.After(time.Second):
		t.Fatal("command was not published")
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RPC context did not cancel command wait")
	}
	nodeLocker.Lock()
	_, found := nodeResponseChanMap[command.Id]
	nodeLocker.Unlock()
	if found {
		t.Fatal("canceled command retained pending reply")
	}
}

type revocationTestNodeServer struct {
	pb.UnimplementedNodeServiceServer
	queue     chan *CommandRequest
	ticks     chan time.Time
	started   chan struct{}
	validated chan struct{}
	revoke    chan struct{}
}

func (s *revocationTestNodeServer) NodeStream(server pb.NodeService_NodeStreamServer) error {
	close(s.started)
	return receiveNodeStream(server.Context(), server, 987_603, s.queue, func() error {
		select {
		case <-s.revoke:
			return status.Error(codes.Unauthenticated, "credential revoked")
		default:
			select {
			case s.validated <- struct{}{}:
			default:
			}
			return nil
		}
	}, s.ticks)
}

func TestSecurityIdleNodeStreamClosesAfterCredentialRevocation(t *testing.T) {
	fixture := &revocationTestNodeServer{
		queue: installTestNodeQueue(t, 987_603, 1), ticks: make(chan time.Time, 1),
		started: make(chan struct{}), validated: make(chan struct{}, 1), revoke: make(chan struct{}),
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	pb.RegisterNodeServiceServer(server, fixture)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	t.Cleanup(func() { _ = listener.Close() })
	connection, err := grpc.NewClient("passthrough:///revocation-test", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := pb.NewNodeServiceClient(connection).NodeStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-fixture.started:
	case <-ctx.Done():
		t.Fatal("stream server did not start")
	}
	fixture.ticks <- time.Now()
	select {
	case <-fixture.validated:
	case <-ctx.Done():
		t.Fatal("healthy session was not revalidated")
	}
	close(fixture.revoke)
	fixture.ticks <- time.Now()
	if _, err := stream.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("idle revoked session remained open: %v", err)
	}
}

func TestSecurityNodeStreamRevalidationTimeout(t *testing.T) {
	blocked := make(chan struct{})
	defer close(blocked)
	err := revalidateNodeStream(context.Background(), func() error { <-blocked; return nil }, 20*time.Millisecond)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("blocked credential database did not close the stream: %v", err)
	}
}
