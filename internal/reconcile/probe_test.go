package reconcile

import (
	"reflect"
	"testing"
)

// 通配符没有自己的地址可拨。
//
// 按声明顺序取前 N 个，而不是随机或按字典序：声明顺序把注册域放在最前面，
// 那通常是最该被验的那个名字。
func TestProbeHostsSkipsWildcardsInOrder(t *testing.T) {
	got := probeHosts([]string{"example.com", "*.example.com", "www.example.com", "api.example.com"}, 3)
	want := []string{"example.com", "www.example.com", "api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("probeHosts = %v，期望 %v", got, want)
	}
}

// 不做全量：一张 25 个名字的证书每轮拨 25 次握手，收益递减而成本线性增长。
func TestProbeHostsRespectsTheCap(t *testing.T) {
	domains := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"}
	got := probeHosts(domains, 2)
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Errorf("probeHosts = %v，期望前两个", got)
	}
}

// 整张证书都是通配符时没有可拨的名字 —— 这不该报错，只是没什么可验的。
func TestProbeHostsReturnsNothingForAWildcardOnlyCert(t *testing.T) {
	if got := probeHosts([]string{"*.example.com", "*.api.example.com"}, 3); len(got) != 0 {
		t.Errorf("通配符不该被拨，实际 %v", got)
	}
}

// 上限为 0 表示"关掉"，用来在一次排查里临时停掉它。
func TestProbeHostsHandlesAZeroCap(t *testing.T) {
	if got := probeHosts([]string{"example.com"}, 0); got != nil {
		t.Errorf("上限为 0 时应当什么都不拨，实际 %v", got)
	}
}
