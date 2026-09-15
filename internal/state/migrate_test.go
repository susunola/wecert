package state

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// 升级路径必须能在**已有数据**的库上原地进行。
//
// 这个项目的整个立身之本就是"绝不能要求用户删库重建"（丢了 order URL
// 就会撞上 5 certs per exact set of identifiers / 7 days）。
// CREATE TABLE IF NOT EXISTS 不会给已存在的表补字段，所以必须有显式的补列逻辑。
func TestMigrateAddsIdentifiersToLegacyDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// 造一个"旧版本"的 orders 表：没有 identifiers 字段，且已经有数据。
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("打开 sqlite: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE orders (
			cert_name    TEXT PRIMARY KEY,
			order_url    TEXT NOT NULL,
			finalize_url TEXT NOT NULL DEFAULT '',
			cert_url     TEXT NOT NULL DEFAULT '',
			expires_at   INTEGER NOT NULL DEFAULT 0,
			status       TEXT NOT NULL DEFAULT '',
			key_pem      BLOB,
			updated_at   INTEGER NOT NULL DEFAULT 0
		);
		INSERT INTO orders (cert_name, order_url, finalize_url, status, key_pem)
		VALUES ('legacy', 'https://acme.example/order/1', 'https://acme.example/finalize/1', 'pending', x'deadbeef');
	`)
	if err != nil {
		t.Fatalf("构造旧表失败: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("关闭旧库失败: %v", err)
	}

	// 用新版打开：应当自动补列，且旧数据一行不少。
	s, err := Open(path)
	if err != nil {
		t.Fatalf("在旧库上 Open 失败（升级会要求删库就失去意义了）: %v", err)
	}
	defer s.Close()

	o, err := s.GetOrder("legacy")
	if err != nil {
		t.Fatalf("GetOrder 失败: %v", err)
	}
	if o == nil {
		t.Fatal("升级后旧订单丢失")
	}
	if o.OrderURL != "https://acme.example/order/1" {
		t.Errorf("OrderURL = %q", o.OrderURL)
	}
	if o.FinalizeURL != "https://acme.example/finalize/1" {
		t.Errorf("FinalizeURL = %q", o.FinalizeURL)
	}
	// 旧行没有这份信息，必须是空串 —— 上层据此判断"不做集合比对"。
	if o.Identifiers != "" {
		t.Errorf("旧订单的 Identifiers 应为空串，得到 %q", o.Identifiers)
	}
	if string(o.KeyPEM) != "\xde\xad\xbe\xef" {
		t.Errorf("私钥未保留: %x", o.KeyPEM)
	}

	// 补列之后要能正常写入新值。
	o.Identifiers = "a.example.com,b.example.com"
	if err := s.PutOrder(o); err != nil {
		t.Fatalf("补列后写入失败: %v", err)
	}
	got, err := s.GetOrder("legacy")
	if err != nil {
		t.Fatal(err)
	}
	if got.Identifiers != "a.example.com,b.example.com" {
		t.Errorf("Identifiers 往返失败: %q", got.Identifiers)
	}
}

// 迁移必须是幂等的：反复 Open 同一个库不能报错。
func TestMigrateIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	for i := 0; i < 3; i++ {
		s, err := Open(path)
		if err != nil {
			t.Fatalf("第 %d 次 Open 失败: %v", i+1, err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("第 %d 次 Close 失败: %v", i+1, err)
		}
	}
}

// 状态库里存着 ACME 账号私钥和全部生效证书的私钥，
// 落盘权限必须是 0600 —— 不能依赖调用方的 umask。
func TestStateFileIsNotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 上不做 POSIX 权限断言")
	}

	// 模拟最宽松的 umask（0000）：即使这样，文件也必须只有属主可读写。
	old := setUmask(0)
	defer setUmask(old)

	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	_ = s.PutCert(&CertState{Name: "x", KeyPEM: []byte("PRIVATE")})
	_ = s.PutOrder(&Order{CertName: "x", OrderURL: "u"})
	defer s.Close()

	// WAL 模式下 -wal / -shm 也是私钥的副本，一起检查。
	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := path + suffix
		st, err := os.Stat(p)
		if err != nil {
			// 没有 WAL 文件是正常的（干净关闭后会被删掉）。
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := st.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s 权限为 %o，同组/其他用户可访问（应为 0600）", filepath.Base(p), perm)
		}
	}
}

// 父目录不存在时应当自动创建，而不是抛一个难懂的 SQLite 错误。
// 非 systemd 的部署方式（手工跑 -once、e2e 脚本）会走到这条路径。
func TestOpenCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "c", "state.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open 应当自动创建父目录: %v", err)
	}
	defer s.Close()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("状态库未创建: %v", err)
	}
}

// DeleteAuthorization 只删指定的那一条，不能连坐。
// wildcard 和 apex 的授权落在同一个 TXT 名字上，但行是分开的。
func TestDeleteAuthorizationKeepsSiblings(t *testing.T) {
	s := openTestStore(t)

	for _, a := range []*Authorization{
		{CertName: "c", AuthzURL: "authz-1", Identifier: "example.com", TxtValue: "v1", Presented: true},
		{CertName: "c", AuthzURL: "authz-2", Identifier: "*.example.com", TxtValue: "v2", Presented: true},
	} {
		if err := s.PutAuthorization(a); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.DeleteAuthorization("c", "authz-1"); err != nil {
		t.Fatalf("DeleteAuthorization 失败: %v", err)
	}

	got, err := s.ListAuthorizations("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("应只剩 1 条授权，得到 %d 条", len(got))
	}
	if got[0].AuthzURL != "authz-2" || got[0].TxtValue != "v2" {
		t.Errorf("删错了行: %+v", got[0])
	}

	// 删除不存在的行不应报错（幂等）。
	if err := s.DeleteAuthorization("c", "authz-1"); err != nil {
		t.Errorf("重复删除应当幂等: %v", err)
	}
}
