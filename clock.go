package deviceenrollment

import "time"

// Clock 是服务内统一的当前时间来源。
// 挑战过期、轮换确认窗口等所有时间判断都必须通过它获取“现在”，
// 以便测试注入假时钟，也避免不同代码路径使用不一致的时间。
type Clock interface {
	Now() time.Time
}

// SystemClock 使用真实系统时间。
type SystemClock struct{}

// Now 返回当前系统时间。
func (SystemClock) Now() time.Time { return time.Now() }
