package scanner

import (
	"fmt"
	"regexp"
	"strings"
)

// DeriveSampleRules 从「本单位敏感信息样例」派生可扫描的匹配规则。
//
// 命题要求敏感信息定义支持「关键词、正则、文件类型或样例」四种方式。样例的价值在于：
// 用户只需要粘贴几个本单位真实数据的样子（如一个工号、一个内部邮箱），
// 平台自动归纳出可扫描的规则，免去手写正则的门槛与出错风险。
//
// 派生策略遵循「字面量优先、泛化其次」——样例往往只有一两条，
// 泛化过猛会直接把误报率拉爆，因此所有泛化都保留首尾字面量做锚点：
//
//  1. 样例本身 → 高置信关键词（精确匹配、大小写不敏感），可命中同一条数据
//  2. 含 @ 的样例 → 追加 "@域名" 关键词，覆盖同域的其它账号
//  3. 纯数字且长度 >= 8（工号 / 身份证 / 手机号等）
//     → 保留前 4 位与后 2 位字面量，中间长度用 \d{n} 泛化
//  4. 字母数字混合且长度 >= 8（订单号 / 内部编码等）
//     → 前 3 位 + [0-9A-Za-z]{n} + 后 2 位
//
// 长度不足 6 的样例只保留字面量、不做泛化：过短的泛化几乎必然误报。
// 返回值均已去重，可直接并入 SensitiveConfig 的 Keywords / RegexPatterns。
func DeriveSampleRules(samples []string) (keywords []string, regexes []string) {
	seenKw := map[string]bool{}
	seenRe := map[string]bool{}

	addKw := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seenKw[s] {
			return
		}
		seenKw[s] = true
		keywords = append(keywords, s)
	}
	addRe := func(s string) {
		if s == "" || seenRe[s] {
			return
		}
		seenRe[s] = true
		regexes = append(regexes, s)
	}

	for _, raw := range samples {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}

		// 1) 字面量：最精确，先加上
		addKw(s)

		// 2) 邮箱：补一条 @域名，覆盖同域其它账号
		if at := strings.LastIndex(s, "@"); at > 0 && at < len(s)-1 {
			domain := s[at+1:]
			// 域名字符集校验，避免把 "a@b" 这类噪声当域名
			if strings.Contains(domain, ".") && !strings.ContainsAny(domain, " \t") {
				addKw("@" + domain)
			}
		}

		// 3)/4) 泛化：需要足够长度才有意义
		if len([]rune(s)) < 8 {
			continue
		}
		r := []rune(s)

		switch {
		case isAllDigits(r):
			prefix, suffix := string(r[:4]), string(r[len(r)-2:])
			middle := len(r) - 6
			if middle >= 2 {
				addRe(fmt.Sprintf(`\b%s\d{%d}%s\b`, regexp.QuoteMeta(prefix), middle, regexp.QuoteMeta(suffix)))
			}
		case isAlnum(r):
			prefix, suffix := string(r[:3]), string(r[len(r)-2:])
			middle := len(r) - 5
			if middle >= 2 {
				addRe(fmt.Sprintf(`\b%s[0-9A-Za-z]{%d}%s\b`, regexp.QuoteMeta(prefix), middle, regexp.QuoteMeta(suffix)))
			}
		}
	}

	return keywords, regexes
}

func isAllDigits(r []rune) bool {
	for _, c := range r {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(r) > 0
}

func isAlnum(r []rune) bool {
	for _, c := range r {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return len(r) > 0
}
