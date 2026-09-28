// Command device-enrollment-server 启动设备注册服务的 HTTP 接口。
//
// 用法：
//
//	go run ./cmd/server [-addr :8080] [-state ./data/state.json]
//
// -state 指向 JSON 快照文件，留空或传 "/dev/null" 以外的空路径则为纯内存模式。
// 进程重启后会自动从快照恢复全部设备、挑战与轮换状态。
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	deviceenrollment "github.com/chris64233/go-device-enrollment"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP 监听地址")
	statePath := flag.String("state", "data/state.json", "JSON 快照持久化路径（留空为纯内存）")
	challengeTTL := flag.Duration("challenge-ttl", 15*time.Minute, "注册挑战默认有效期")
	rotationWindow := flag.Duration("rotation-window", 10*time.Minute, "密钥轮换确认窗口")
	transferTTL := flag.Duration("transfer-ttl", 15*time.Minute, "跨租户转移接收凭据默认有效期")
	flag.Parse()

	svc, err := deviceenrollment.New(deviceenrollment.Config{
		Store:          deviceenrollment.NewFileStore(*statePath),
		Clock:          deviceenrollment.SystemClock(),
		ChallengeTTL:   *challengeTTL,
		RotationWindow: *rotationWindow,
		TransferTTL:    *transferTTL,
	})
	if err != nil {
		log.Fatalf("init service: %v", err)
	}

	log.Printf("device enrollment server listening on %s (state=%q, challenge-ttl=%s, rotation-window=%s, transfer-ttl=%s)",
		*addr, *statePath, *challengeTTL, *rotationWindow, *transferTTL)
	if err := http.ListenAndServe(*addr, deviceenrollment.NewHandler(svc)); err != nil {
		log.Fatal(err)
	}
}
