package deviceenrollment

import "sync"

// Store 是持久化层的抽象。所有 Put 均为按主键的 upsert。
// Service 在调用 Store 前已用互斥锁串行化所有状态变更，
// 因此实现无需自行处理并发；基于 SQL 的实现应把同一服务方法内的
// 多次读写包进一个事务以保持原子性。
type Store interface {
	PutChallenge(c Challenge)
	GetChallenge(id string) (Challenge, bool)

	PutDevice(d Device)
	GetDevice(id string) (Device, bool)
	GetDeviceByExternalID(externalID string) (Device, bool)

	PutKeyVersion(kv KeyVersion)
	GetKeyVersion(deviceID string, version int) (KeyVersion, bool)
	ListKeyVersions(deviceID string) []KeyVersion

	PutRotation(r Rotation)
	GetRotation(id string) (Rotation, bool)
	ListRotations(deviceID string) []Rotation
}

// MemoryStore 是 Store 的内存参考实现。
type MemoryStore struct {
	mu         sync.Mutex
	challenges map[string]Challenge
	devices    map[string]Device
	byExternal map[string]string
	keys       map[[2]interface{}]KeyVersion
	rotations  map[string]Rotation
}

// NewMemoryStore 创建一个空的内存存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		challenges: make(map[string]Challenge),
		devices:    make(map[string]Device),
		byExternal: make(map[string]string),
		keys:       make(map[[2]interface{}]KeyVersion),
		rotations:  make(map[string]Rotation),
	}
}

func keyOf(deviceID string, version int) [2]interface{} { return [2]interface{}{deviceID, version} }

func cloneKey(kv KeyVersion) KeyVersion {
	kv.PublicKey = append([]byte(nil), kv.PublicKey...)
	return kv
}

func cloneRotation(r Rotation) Rotation {
	r.NewPublicKey = append([]byte(nil), r.NewPublicKey...)
	return r
}

func (m *MemoryStore) PutChallenge(c Challenge) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.challenges[c.ID] = c
}

func (m *MemoryStore) GetChallenge(id string) (Challenge, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.challenges[id]
	return c, ok
}

func (m *MemoryStore) PutDevice(d Device) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.devices[d.ID] = d
	m.byExternal[d.ExternalID] = d.ID
}

func (m *MemoryStore) GetDevice(id string) (Device, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	return d, ok
}

func (m *MemoryStore) GetDeviceByExternalID(externalID string) (Device, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byExternal[externalID]
	if !ok {
		return Device{}, false
	}
	d, ok := m.devices[id]
	return d, ok
}

func (m *MemoryStore) PutKeyVersion(kv KeyVersion) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[keyOf(kv.DeviceID, kv.Version)] = cloneKey(kv)
}

func (m *MemoryStore) GetKeyVersion(deviceID string, version int) (KeyVersion, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kv, ok := m.keys[keyOf(deviceID, version)]
	return cloneKey(kv), ok
}

func (m *MemoryStore) ListKeyVersions(deviceID string) []KeyVersion {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []KeyVersion
	for _, kv := range m.keys {
		if kv.DeviceID == deviceID {
			out = append(out, cloneKey(kv))
		}
	}
	return out
}

func (m *MemoryStore) PutRotation(r Rotation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rotations[r.ID] = cloneRotation(r)
}

func (m *MemoryStore) GetRotation(id string) (Rotation, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rotations[id]
	return cloneRotation(r), ok
}

func (m *MemoryStore) ListRotations(deviceID string) []Rotation {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Rotation
	for _, r := range m.rotations {
		if r.DeviceID == deviceID {
			out = append(out, cloneRotation(r))
		}
	}
	return out
}
