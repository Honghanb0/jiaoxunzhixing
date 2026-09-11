package scanner

import (
	"regexp"
	"testing"
)

func TestDeriveSampleRules(t *testing.T) {
	kw, re := DeriveSampleRules([]string{
		"admin@cuz.edu.cn",   // 邮箱 -> 字面量 + @域名
		"330106199001011234", // 纯数字 18 位 -> 泛化正则
		"CUZ20240001",        // 字母数字混合 -> 泛化正则
		"abc",                // 过短 -> 仅字面量
		"  ",                 // 空白 -> 忽略
		"admin@cuz.edu.cn",   // 重复 -> 去重
	})

	has := func(list []string, want string) bool {
		for _, v := range list {
			if v == want {
				return true
			}
		}
		return false
	}

	// 1) 字面量关键词
	for _, want := range []string{"admin@cuz.edu.cn", "330106199001011234", "CUZ20240001", "abc"} {
		if !has(kw, want) {
			t.Errorf("关键词缺少字面量 %q，实际: %v", want, kw)
		}
	}

	// 2) 邮箱派生 @域名
	if !has(kw, "@cuz.edu.cn") {
		t.Errorf("邮箱样例未派生出 @域名 关键词，实际: %v", kw)
	}

	// 3) 去重：admin@cuz.edu.cn 只应出现一次
	n := 0
	for _, v := range kw {
		if v == "admin@cuz.edu.cn" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("重复样例未去重，出现 %d 次", n)
	}

	// 4) 纯数字泛化：前 4 位 + \d{12} + 后 2 位
	wantNum := `\b3301\d{12}34\b`
	if !has(re, wantNum) {
		t.Errorf("纯数字样例未派生出 %q，实际: %v", wantNum, re)
	}

	// 5) 字母数字混合泛化：前 3 位 + [0-9A-Za-z]{6} + 后 2 位
	wantAlnum := `\bCUZ[0-9A-Za-z]{6}01\b`
	if !has(re, wantAlnum) {
		t.Errorf("混合样例未派生出 %q，实际: %v", wantAlnum, re)
	}

	// 6) 过短样例不应产生正则（否则误报会爆）
	for _, v := range re {
		if regexp.MustCompile(v).MatchString("abc") {
			t.Errorf("过短样例派生出的正则 %q 命中了 abc，泛化过宽", v)
		}
	}

	// 7) 空白样例不应产生任何规则
	k2, r2 := DeriveSampleRules([]string{"   ", ""})
	if len(k2) != 0 || len(r2) != 0 {
		t.Errorf("空白样例应被忽略，实际 kw=%v re=%v", k2, r2)
	}
}

func TestDeriveSampleRulesMatchRealisticContent(t *testing.T) {
	kw, re := DeriveSampleRules([]string{"330106199001011234", "admin@cuz.edu.cn"})

	content := `联系人邮箱 admin@cuz.edu.cn ，另一账号 teacher@cuz.edu.cn ；` +
		`个人证件号 330106199002022334 疑似泄露。`

	hit := 0
	for _, k := range kw {
		if regexp.MustCompile(regexp.QuoteMeta(k)).MatchString(content) {
			hit++
		}
	}
	for _, p := range re {
		if regexp.MustCompile(p).MatchString(content) {
			hit++
		}
	}
	if hit < 3 {
		t.Fatalf("样例规则未能命中内容（命中 %d 条），派生规则 kw=%v re=%v", hit, kw, re)
	}

	// 泛化正则不应把无关数字串误判为敏感
	benign := "服务器端口 8080，版本号 20240101"
	for _, p := range re {
		if regexp.MustCompile(p).MatchString(benign) {
			t.Errorf("泛化正则 %q 误命中了无关内容 %q", p, benign)
		}
	}
}
