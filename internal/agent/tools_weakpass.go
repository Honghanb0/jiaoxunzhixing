package agent

import (
	"context"
	"fmt"
	"time"

	"security-agent/internal/weakpass"
)

// weakpassDict 是智能体共享的弱口令字典管理器（内置 users/passwords + 运行时可追加）。
var weakpassDict = weakpass.NewDictManager()

// registerWeakPassTools 注册弱口令相关工具：字典管理、弱口令扫描、单凭据验证。
// 这些工具让自主智能体具备对授权目标系统的弱口令探测与有效性验证能力，
// 命中结果可经既有 create_ticket / send_alert 工具回写为工单或告警，形成闭环。
func registerWeakPassTools(reg *ToolRegistry, d Deps) {
	reg.Register(toolFunc{
		name: "manage_password_dict",
		description: "弱口令字典管理：列出/追加/查看/重置/从文件加载口令字典（内置 users、passwords）。" +
			"用于为弱口令扫描准备或扩充字典。action=list 列出全部字典及词条数；action=show 查看某字典内容；" +
			"action=add 向某字典追加词条；action=reset 重置为内置值；action=load 从文件载入词条。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"action":      map[string]any{"type": "string", "description": "list / show / add / reset / load"},
			"dict":        map[string]any{"type": "string", "description": "字典名（users / passwords / 自定义名）"},
			"words":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "add 时追加的词条"},
			"source_file": map[string]any{"type": "string", "description": "load 时读取的字典文件路径"},
			"limit":       map[string]any{"type": "integer", "description": "show 时最多返回词条数（默认 200）"},
		}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			return weakpassDictHandle(args)
		},
	})

	reg.Register(toolFunc{
		name: "weak_password_scan",
		description: "对目标服务的弱口令探测：用「用户名×口令」字典发起并发登录尝试，命中即记录有效凭据并默认二次复验。" +
			"需显式提供 target（host 或 host:port）与 service（ssh/ftp/pop3/smtp/redis/http）。" +
			"未提供 usernames/passwords 时自动使用内置 users/passwords 字典；可用 use_dict 指定单一字典名。" +
			"注意：仅可在授权范围内对目标发起探测，禁止对未授权目标扫描。命中结果建议经 create_ticket / send_alert 回写。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"target":        map[string]any{"type": "string", "description": "目标 host 或 host:port，如 10.0.0.5 或 10.0.0.5:22"},
			"service":       map[string]any{"type": "string", "description": "服务类型：ssh/ftp/pop3/smtp/redis/http（http=Basic Auth）"},
			"usernames":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可选：显式用户名列表（缺省用内置 users 字典）"},
			"passwords":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可选：显式口令列表（缺省用内置 passwords 字典）"},
			"use_dict":      map[string]any{"type": "string", "description": "可选：指定单一字典名同时作为用户名与口令来源（覆盖默认 users/passwords）"},
			"concurrency":   map[string]any{"type": "integer", "description": "并发数（1~50，默认 10）"},
			"timeout_sec":   map[string]any{"type": "integer", "description": "单条尝试超时秒数（1~30，默认 5）"},
			"stop_on_first": map[string]any{"type": "boolean", "description": "命中即停止（默认 false）"},
			"verify":        map[string]any{"type": "boolean", "description": "对命中凭据二次复验（默认 true）"},
		}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			return weakPasswordScan(ctx, args)
		},
	})

	reg.Register(toolFunc{
		name: "verify_credentials",
		description: "对单条「用户名+口令」做有效性验证（确认该凭据能否登录目标服务）。" +
			"用于复验弱口令扫描的命中项，或人工指定凭据的即时判定。返回 authenticated 布尔与所用 service/target/username。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"target":      map[string]any{"type": "string", "description": "目标 host 或 host:port"},
			"service":     map[string]any{"type": "string", "description": "服务类型：ssh/ftp/pop3/smtp/redis/http"},
			"username":    map[string]any{"type": "string"},
			"password":    map[string]any{"type": "string"},
			"timeout_sec": map[string]any{"type": "integer", "description": "超时秒数（1~30，默认 5）"},
		}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			return verifyCreds(ctx, args)
		},
	})
}

// weakpassDictHandle 实现 manage_password_dict 工具。
func weakpassDictHandle(args map[string]any) (string, error) {
	action := getString(args, "action")
	if action == "" {
		action = "list"
	}
	switch action {
	case "list":
		return toJSON(map[string]any{"dicts": weakpassDict.List()}), nil
	case "show":
		name := dictNameArg(args)
		if name == "" {
			return "", fmt.Errorf("action=show 需提供 dict")
		}
		limit := getInt(args, "limit", 200)
		words := weakpassDict.Get(name)
		if words == nil {
			return "", fmt.Errorf("字典不存在: %s", name)
		}
		if limit > 0 && len(words) > limit {
			words = words[:limit]
		}
		return toJSON(map[string]any{"dict": name, "count": len(weakpassDict.Get(name)), "words": words}), nil
	case "add":
		name := dictNameArg(args)
		if name == "" {
			return "", fmt.Errorf("action=add 需提供 dict")
		}
		words := getStringSlice(args, "words")
		if len(words) == 0 {
			return "", fmt.Errorf("action=add 需提供 words（词条数组）")
		}
		n := weakpassDict.Add(name, words)
		return toJSON(map[string]any{"dict": name, "added": n, "total": len(weakpassDict.Get(name))}), nil
	case "reset":
		name := dictNameArg(args)
		if name == "" {
			return "", fmt.Errorf("action=reset 需提供 dict")
		}
		ok := weakpassDict.Reset(name)
		return toJSON(map[string]any{"dict": name, "reset": ok, "total": len(weakpassDict.Get(name))}), nil
	case "load":
		name := dictNameArg(args)
		if name == "" {
			return "", fmt.Errorf("action=load 需提供 dict")
		}
		src := getString(args, "source_file")
		if src == "" {
			return "", fmt.Errorf("action=load 需提供 source_file")
		}
		n, err := weakpassDict.LoadFile(name, src)
		if err != nil {
			return "", err
		}
		return toJSON(map[string]any{"dict": name, "loaded": n, "total": len(weakpassDict.Get(name)), "source": src}), nil
	default:
		return "", fmt.Errorf("未知 action: %s（支持 list/show/add/reset/load）", action)
	}
}

func dictNameArg(args map[string]any) string {
	return getString(args, "dict")
}

// weakPasswordScan 实现 weak_password_scan 工具。
func weakPasswordScan(ctx context.Context, args map[string]any) (string, error) {
	target := getString(args, "target")
	service := getString(args, "service")
	if target == "" {
		return "", fmt.Errorf("缺少参数 target")
	}
	if service == "" {
		return "", fmt.Errorf("缺少参数 service（支持: ssh/ftp/pop3/smtp/redis/http）")
	}

	// 解析用户名 / 口令来源
	users := resolveDictArg(args, "usernames", "users")
	passwords := resolveDictArg(args, "passwords", "passwords")
	if len(users) == 0 || len(passwords) == 0 {
		return "", fmt.Errorf("无法解析用户名或口令字典（请显式提供 usernames/passwords，或确保内置字典可用）")
	}

	concurrency := getInt(args, "concurrency", weakpass.DefaultConcurrency)
	timeoutSec := getInt(args, "timeout_sec", int(weakpass.DefaultTimeout.Seconds()))
	opts := weakpass.ScanOptions{
		Target:      target,
		Service:     service,
		Users:       users,
		Passwords:   passwords,
		Concurrency: concurrency,
		Timeout:     time.Duration(timeoutSec) * time.Second,
		StopOnFirst: boolArg(args, "stop_on_first", false),
		Verify:      boolArg(args, "verify", true),
	}
	res, err := weakpass.Scan(ctx, opts)
	if err != nil {
		return "", err
	}
	// 精简输出：found 凭据全量返回（通常很少），errors 已在上限内截断
	out := map[string]any{
		"target":           res.Target,
		"service":          res.Service,
		"attempts":         res.Attempts,
		"found":            res.Found,
		"found_count":      len(res.Found),
		"errors_sample":    res.Errors,
		"elapsed_sec":      res.ElapsedSec,
		"stopped_on_first": res.StoppedOnFirst,
	}
	return toJSON(out), nil
}

// resolveDictArg 解析字典参数：显式列表 > use_dict 单一字典 > 默认字典名。
func resolveDictArg(args map[string]any, key, defaultDict string) []string {
	if list := getStringSlice(args, key); len(list) > 0 {
		return list
	}
	if name := getString(args, "use_dict"); name != "" {
		return weakpassDict.Get(name)
	}
	return weakpassDict.Get(defaultDict)
}

// verifyCreds 实现 verify_credentials 工具。
func verifyCreds(ctx context.Context, args map[string]any) (string, error) {
	target := getString(args, "target")
	service := getString(args, "service")
	user := getString(args, "username")
	pass := getString(args, "password")
	if target == "" || service == "" || user == "" {
		return "", fmt.Errorf("缺少参数 target / service / username")
	}
	timeoutSec := getInt(args, "timeout_sec", int(weakpass.DefaultTimeout.Seconds()))
	authed, err := weakpass.Check(ctx, service, target, user, pass, time.Duration(timeoutSec)*time.Second)
	if err != nil {
		return toJSON(map[string]any{
			"target": target, "service": service, "username": user,
			"authenticated": false, "error": err.Error(),
		}), nil
	}
	return toJSON(map[string]any{
		"target": target, "service": service, "username": user,
		"authenticated": authed,
	}), nil
}
