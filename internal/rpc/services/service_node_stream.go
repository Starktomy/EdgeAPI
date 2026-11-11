package services

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	teaconst "github.com/TeaOSLab/EdgeAPI/internal/const"
	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	"github.com/TeaOSLab/EdgeAPI/internal/errors"
	"github.com/TeaOSLab/EdgeAPI/internal/goman"
	"github.com/TeaOSLab/EdgeAPI/internal/remotelogs"
	rpcutils "github.com/TeaOSLab/EdgeAPI/internal/rpc/utils"
	"github.com/TeaOSLab/EdgeCommon/pkg/nodeconfigs"
	"github.com/TeaOSLab/EdgeCommon/pkg/rpc/pb"
	"github.com/iwind/TeaGo/logs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var primaryNodeId int64 = 0

// CommandRequest 命令请求相关
type CommandRequest struct {
	Id          int64
	Code        string
	CommandJSON []byte
}

type CommandRequestWaiting struct {
	Timestamp   int64
	NodeId      int64
	RequestChan chan *CommandRequest
	Chan        chan *pb.NodeStreamMessage
	closeOnce   sync.Once
}

func (this *CommandRequestWaiting) Close() {
	this.closeOnce.Do(func() { close(this.Chan) })
}

var nodeResponseChanMap = map[int64]*CommandRequestWaiting{} // request id => response
var commandRequestId = int64(0)

var nodeLocker = &sync.Mutex{}
var nodeRequestChanMap = map[int64]chan *CommandRequest{} // node id => chan

func NextCommandRequestId() int64 {
	return atomic.AddInt64(&commandRequestId, 1)
}

func init() {
	// 清理WaitingChannelMap
	var ticker = time.NewTicker(30 * time.Second)
	goman.New(func() {
		for range ticker.C {
			nodeLocker.Lock()
			for requestId, request := range nodeResponseChanMap {
				if time.Now().Unix()-request.Timestamp > 3600 {
					nodeResponseChanMap[requestId].Close()
					delete(nodeResponseChanMap, requestId)
				}
			}
			nodeLocker.Unlock()
		}
	})
}

// NodeStream 节点stream
func (this *NodeService) NodeStream(server pb.NodeService_NodeStreamServer) error {
	// TODO 使用此stream快速通知边缘节点更新
	// 校验节点
	nodeId, revalidate, err := rpcutils.NewNodeStreamValidator(server.Context())
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(server.Context())
	defer cancel()
	requestChan := make(chan *CommandRequest, 1024)
	nodeLocker.Lock()
	// A reconnect creates a new session. Pending replies from the superseded
	// stream must not complete commands sent to the new one.
	for requestId, waiting := range nodeResponseChanMap {
		if waiting.NodeId == nodeId {
			waiting.Close()
			delete(nodeResponseChanMap, requestId)
		}
	}
	nodeRequestChanMap[nodeId] = requestChan
	atomic.CompareAndSwapInt64(&primaryNodeId, 0, nodeId)
	nodeLocker.Unlock()

	defer func() {
		// Stop command dispatch before any potentially slow database cleanup.
		cancel()
		nodeLocker.Lock()
		if nodeRequestChanMap[nodeId] != requestChan {
			nodeLocker.Unlock()
			return
		}
		delete(nodeRequestChanMap, nodeId)
		for requestId, waiting := range nodeResponseChanMap {
			if waiting.NodeId == nodeId && waiting.RequestChan == requestChan {
				waiting.Close()
				delete(nodeResponseChanMap, requestId)
			}
		}
		if atomic.LoadInt64(&primaryNodeId) == nodeId {
			atomic.StoreInt64(&primaryNodeId, 0)
			for anotherNodeId := range nodeRequestChanMap {
				atomic.StoreInt64(&primaryNodeId, anotherNodeId)
				break
			}
		}
		nodeLocker.Unlock()

		// 修改在线状态
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		cleanupErr := revalidateNodeStream(cleanupCtx, func() error {
			return models.SharedNodeDAO.UpdateNodeActiveContext(cleanupCtx, nodeId, false)
		}, 5*time.Second)
		if cleanupErr != nil {
			remotelogs.Error("NODE_SERVICE", "change node active failed: "+cleanupErr.Error())
		}
	}()

	// 设置API节点
	err = models.SharedNodeDAO.UpdateNodeConnectedAPINodes(nil, nodeId, []int64{teaconst.NodeId})
	if err != nil {
		return err
	}

	var tx = this.NullTx()

	// 是否发送恢复通知
	oldIsActive, err := models.SharedNodeDAO.FindNodeActive(tx, nodeId)
	if err != nil {
		return err
	}
	if !oldIsActive {
		inactiveNotifiedAt, err := models.SharedNodeDAO.FindNodeInactiveNotifiedAt(tx, nodeId)
		if err != nil {
			return err
		}

		// 设置为活跃
		err = models.SharedNodeDAO.UpdateNodeActive(tx, nodeId, true)
		if err != nil {
			return err
		}

		if inactiveNotifiedAt > 0 {
			// 发送恢复消息
			clusterId, err := models.SharedNodeDAO.FindNodeClusterId(tx, nodeId)
			if err != nil {
				return err
			}
			nodeName, err := models.SharedNodeDAO.FindNodeName(tx, nodeId)
			if err != nil {
				return err
			}
			var subject = "节点\"" + nodeName + "\"已经恢复在线"
			var msg = "节点\"" + nodeName + "\"已经恢复在线"
			err = models.SharedMessageDAO.CreateNodeMessage(tx, nodeconfigs.NodeRoleNode, clusterId, nodeId, models.MessageTypeNodeActive, models.MessageLevelSuccess, subject, msg, nil, false)
			if err != nil {
				return err
			}
		}
	}

	// 发送请求
	goman.New(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case commandRequest := <-requestChan:
				if ctx.Err() != nil {
					return
				}
				nodeLocker.Lock()
				current := nodeRequestChanMap[nodeId] == requestChan
				nodeLocker.Unlock()
				if !current {
					return
				}
				// logs.Println("[RPC]sending command '" + commandRequest.Code + "' to node '" + strconv.FormatInt(nodeId, 10) + "'")
				retries := 3 // 错误重试次数
				for i := 0; i < retries; i++ {
					if ctx.Err() != nil {
						return
					}
					err := server.Send(&pb.NodeStreamMessage{
						RequestId: commandRequest.Id,
						Code:      commandRequest.Code,
						DataJSON:  commandRequest.CommandJSON,
					})
					if err != nil {
						if i == retries-1 {
							logs.Println("[RPC]send command '" + commandRequest.Code + "' failed: " + err.Error())
						} else {
							time.Sleep(1 * time.Second)
						}
					} else {
						break
					}
				}
			}
		}
	})

	// Recheck the authoritative machine credential and enabled node without
	// making healthy sessions reconnect whenever the handshake token expires.
	validationTicker := time.NewTicker(30 * time.Second)
	defer validationTicker.Stop()
	return receiveNodeStream(ctx, server, nodeId, requestChan, revalidate, validationTicker.C)
}

type nodeStreamReceive struct {
	message *pb.NodeStreamMessage
	err     error
}

func receiveNodeStream(ctx context.Context, server pb.NodeService_NodeStreamServer, nodeId int64, requestChan chan *CommandRequest, revalidate func() error, ticks <-chan time.Time) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	received := make(chan nodeStreamReceive, 1)
	// Returning from the RPC handler cancels gRPC's Recv even for an idle
	// client. The derived context also prevents a blocked channel publication.
	goman.New(func() {
		for {
			message, err := server.Recv()
			select {
			case received <- nodeStreamReceive{message: message, err: err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	})
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks:
			if err := revalidateNodeStream(ctx, revalidate, 5*time.Second); err != nil {
				return err
			}
		case response := <-received:
			if response.err != nil {
				return response.err
			}
			deliverNodeResponse(nodeId, requestChan, response.message)
		}
	}
}

func revalidateNodeStream(ctx context.Context, validate func() error, timeout time.Duration) error {
	result := make(chan error, 1)
	goman.New(func() { result <- validate() })
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-result:
		return err
	case <-timer.C:
		return status.Error(codes.Unavailable, "node stream credential revalidation timed out")
	}
}

func deliverNodeResponse(nodeId int64, requestChan chan *CommandRequest, response *pb.NodeStreamMessage) bool {
	if response == nil {
		return false
	}
	nodeLocker.Lock()
	defer nodeLocker.Unlock()
	waiting, found := nodeResponseChanMap[response.RequestId]
	if !found || waiting.NodeId != nodeId || waiting.RequestChan != requestChan || nodeRequestChanMap[nodeId] != requestChan {
		return false
	}
	select {
	case waiting.Chan <- response:
		return true
	default:
		return false
	}
}

// SendCommandToNode 向节点发送命令
func (this *NodeService) SendCommandToNode(ctx context.Context, req *pb.NodeStreamMessage) (*pb.NodeStreamMessage, error) {
	// 校验请求
	_, err := this.ValidateAdmin(ctx)
	if err != nil {
		return nil, err
	}

	nodeId := req.NodeId
	if nodeId <= 0 {
		return nil, errors.New("node id should not be less than 0")
	}

	return sendCommandToNode(ctx, req.NodeId, req.RequestId, req.Code, req.DataJSON, req.TimeoutSeconds, true)
}

// SendCommandToNode 向节点发送命令
func SendCommandToNode(nodeId int64, requestId int64, messageCode string, dataJSON []byte, timeoutSeconds int32, forceConnecting bool) (result *pb.NodeStreamMessage, err error) {
	return sendCommandToNode(context.Background(), nodeId, requestId, messageCode, dataJSON, timeoutSeconds, forceConnecting)
}

func sendCommandToNode(ctx context.Context, nodeId int64, requestId int64, messageCode string, dataJSON []byte, timeoutSeconds int32, forceConnecting bool) (result *pb.NodeStreamMessage, err error) {
	nodeLocker.Lock()
	requestChan, ok := nodeRequestChanMap[nodeId]
	nodeLocker.Unlock()

	if !ok {
		if forceConnecting {
			return &pb.NodeStreamMessage{
				RequestId: requestId,
				IsOk:      false,
				Message:   "node '" + strconv.FormatInt(nodeId, 10) + "' not connected yet",
			}, nil
		} else {
			return &pb.NodeStreamMessage{
				RequestId: requestId,
				IsOk:      true,
			}, nil
		}
	}

	requestId = NextCommandRequestId()
	waiting := &CommandRequestWaiting{
		Timestamp: time.Now().Unix(), NodeId: nodeId, RequestChan: requestChan,
		Chan: make(chan *pb.NodeStreamMessage, 1),
	}
	defer func() {
		nodeLocker.Lock()
		if nodeResponseChanMap[requestId] == waiting {
			delete(nodeResponseChanMap, requestId)
			waiting.Close()
		}
		nodeLocker.Unlock()
	}()

	// Register the expected authenticated session before publishing the command.
	nodeLocker.Lock()
	if nodeRequestChanMap[nodeId] != requestChan {
		nodeLocker.Unlock()
		return nil, errors.New("node stream changed before command dispatch")
	}
	nodeResponseChanMap[requestId] = waiting

	select {
	case requestChan <- &CommandRequest{
		Id:          requestId,
		Code:        messageCode,
		CommandJSON: dataJSON,
	}:
		nodeLocker.Unlock()

		// 等待响应
		if timeoutSeconds <= 0 {
			timeoutSeconds = 10
		}
		timeout := time.NewTimer(time.Duration(timeoutSeconds) * time.Second)
		defer timeout.Stop()
		select {
		case resp := <-waiting.Chan:
			if resp == nil {
				return &pb.NodeStreamMessage{
					RequestId: requestId,
					Code:      messageCode,
					Message:   "response timeout",
					IsOk:      false,
				}, nil
			}

			return resp, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
			return &pb.NodeStreamMessage{
				RequestId: requestId,
				Code:      messageCode,
				Message:   "response timeout over " + fmt.Sprintf("%d", timeoutSeconds) + " seconds",
				IsOk:      false,
			}, nil
		}
	default:
		nodeLocker.Unlock()
		return &pb.NodeStreamMessage{
			RequestId: requestId,
			Code:      messageCode,
			Message:   "command queue is full over " + strconv.Itoa(len(requestChan)),
			IsOk:      false,
		}, nil
	}
}
