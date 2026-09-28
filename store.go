package deviceenrollment

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// snapshot 是服务的完整持久化状态。所有变更都在服务互斥锁内作用于同一快照，
// 再整体落盘，从而保证“消费挑战 + 建立设备”“禁用设备 + 终止轮换”等多步修改原子可见。
type snapshot struct {
	Challenges map[string]*ChallengeRecord `json:"challenges"`
	Devices    map[string]*DeviceRecord    `json:"devices"`
	// ByExternal 保证外部注册号全局唯一，支撑幂等返回与冲突判定。
	ByExternal map[string]string          `json:"by_external"`
	Rotations  map[string]*RotationRecord `json:"rotations"`
	// OpenRotation 记录每台设备当前唯一的未终态轮换。
	OpenRotation map[string]string `json:"open_rotation"`
	// Transfers 是全部转移单（含终态，支撑归属链两端决定查询）。
	Transfers map[string]*TransferRecord `json:"transfers"`
	// OpenTransfer 记录每台设备当前唯一的活动转移。
	OpenTransfer map[string]string `json:"open_transfer"`
	// TransferRequests 支撑发起转移的幂等：请求号 -> 转移单号。
	TransferRequests map[string]string `json:"transfer_requests"`
	// DeviceTransfers 维持设备 -> 其全部转移单号（按创建顺序），供归属历史查询。
	DeviceTransfers map[string][]string `json:"device_transfers"`
}

func newSnapshot() *snapshot {
	return &snapshot{
		Challenges:       map[string]*ChallengeRecord{},
		Devices:          map[string]*DeviceRecord{},
		ByExternal:       map[string]string{},
		Rotations:        map[string]*RotationRecord{},
		OpenRotation:     map[string]string{},
		Transfers:        map[string]*TransferRecord{},
		OpenTransfer:     map[string]string{},
		TransferRequests: map[string]string{},
		DeviceTransfers:  map[string][]string{},
	}
}

// Store 负责快照的持久化。路径为空时退化为纯内存存储（用于测试）。
type Store struct {
	path string
}

// NewFileStore 使用 path 作为 JSON 快照文件。
func NewFileStore(path string) *Store {
	return &Store{path: path}
}

// NewMemoryStore 返回不落盘的存储。
func NewMemoryStore() *Store {
	return &Store{path: ""}
}

// Load 读取快照；文件不存在时返回空快照。
func (s *Store) Load() (*snapshot, error) {
	if s.path == "" {
		return newSnapshot(), nil
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return newSnapshot(), nil
	}
	if err != nil {
		return nil, err
	}
	snap := newSnapshot()
	if len(data) > 0 {
		if err := json.Unmarshal(data, snap); err != nil {
			return nil, err
		}
		if snap.Challenges == nil || snap.Devices == nil || snap.ByExternal == nil ||
			snap.Rotations == nil || snap.OpenRotation == nil || snap.Transfers == nil ||
			snap.OpenTransfer == nil || snap.TransferRequests == nil || snap.DeviceTransfers == nil {
			return nil, errors.New("deviceenrollment: corrupt snapshot: missing collections")
		}
	}
	return snap, nil
}

// Save 以“同目录临时文件 + rename”方式原子落盘，避免崩溃留下半截 JSON。
func (s *Store) Save(snap *snapshot) error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
