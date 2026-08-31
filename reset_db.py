#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
交巡智星 —— Neo4j 数据库重置脚本（独立工具，默认不会执行任何删除）

⚠️ 警告：本脚本会清空整个 Neo4j 图数据库中的所有节点与关系（含用户、域名、
漏洞、工单、巡检记录等全部数据），且不可恢复。请仅在测试/重置环境使用，
并务必确认连接的是正确的数据库实例。

用法：
    # 1) 查看将要执行的操作（dry-run，不做任何修改）
    python reset_db.py --dry-run

    # 2) 真正执行清空（必须显式传 --confirm）
    python reset_db.py --confirm

    # 3) 自定义连接（也可使用环境变量 NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD）
    python reset_db.py --confirm \
        --uri bolt://localhost:7687 \
        --user neo4j --password your_password \
        --database neo4j

连接参数优先级：命令行参数 > 环境变量 > 脚本内置默认值。

依赖：
    pip install neo4j          # 官方 Neo4j Python 驱动
    （可选）pip install pyyaml # 若需从 config.yaml 读取连接信息
"""

import argparse
import os
import sys

# ---------------------------------------------------------------------------
# 默认连接（可被环境变量/命令行覆盖）
# ---------------------------------------------------------------------------
DEFAULT_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
DEFAULT_USER = os.environ.get("NEO4J_USER", "neo4j")
DEFAULT_PASSWORD = os.environ.get("NEO4J_PASSWORD", "your_password")
DEFAULT_DATABASE = os.environ.get("NEO4J_DATABASE", "neo4j")


def load_from_config_yaml():
    """如果项目根目录存在 config.yaml 且已安装 pyyaml，则读取连接信息。"""
    try:
        import yaml  # type: ignore
    except ImportError:
        return {}
    cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
    if not os.path.exists(cfg_path):
        return {}
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        neo = (cfg.get("database") or {}).get("neo4j") or {}
        out = {}
        if neo.get("uri"):
            out["uri"] = neo["uri"]
        if neo.get("username"):
            out["user"] = neo["username"]
        if neo.get("password"):
            out["password"] = neo["password"]
        if neo.get("database"):
            out["database"] = neo["database"]
        return out
    except Exception as e:  # noqa: BLE001
        print(f"[warn] 读取 config.yaml 失败，使用默认值：{e}")
        return {}


def main():
    parser = argparse.ArgumentParser(
        description="交巡智星 Neo4j 数据库重置工具（清空全部节点与关系）"
    )
    parser.add_argument("--uri", default=None, help="Neo4j bolt 地址")
    parser.add_argument("--user", default=None, help="Neo4j 用户名")
    parser.add_argument("--password", default=None, help="Neo4j 密码")
    parser.add_argument("--database", default=None, help="Neo4j 数据库名")
    parser.add_argument("--confirm", action="store_true",
                        help="必须显式指定才会真正执行删除（否则仅 dry-run）")
    parser.add_argument("--dry-run", action="store_true",
                        help="只打印将要执行的操作，不做任何修改")
    args = parser.parse_args()

    # 合并参数：命令行 > 环境变量/默认值，并优先用 config.yaml 补充缺失项
    cfg = load_from_config_yaml()
    uri = args.uri or cfg.get("uri") or DEFAULT_URI
    user = args.user or cfg.get("user") or DEFAULT_USER
    password = args.password or cfg.get("password") or DEFAULT_PASSWORD
    database = args.database or cfg.get("database") or DEFAULT_DATABASE

    print("=" * 60)
    print("交巡智星 - Neo4j 数据库重置")
    print("=" * 60)
    print(f"  目标 URI   : {uri}")
    print(f"  用户名     : {user}")
    print(f"  数据库     : {database}")
    print(f"  模式       : {'DRY-RUN（不修改）' if (args.dry_run or not args.confirm) else 'CONFIRM（将清空全部数据!）'}")
    print("=" * 60)

    if args.dry_run or not args.confirm:
        print("[dry-run] 未提供 --confirm，不会执行任何删除操作。")
        print("[dry-run] 若确实要清空，请重新运行并附加 --confirm 参数。")
        sys.exit(0)

    try:
        from neo4j import GraphDatabase
    except ImportError:
        print("[error] 未安装 neo4j 驱动，请先执行: pip install neo4j")
        sys.exit(2)

    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        # 连接健康检查
        driver.verify_connectivity()
        print("[ok] 已连接到 Neo4j。")

        with driver.session(database=database) as session:
            # 删除前统计
            before = session.run("MATCH (n) RETURN count(n) AS c").single()["c"]
            rel_before = session.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
            print(f"[统计] 删除前：节点 {before} 个，关系 {rel_before} 条。")

            # 真正清空：DETACH DELETE 会同时删除关联的关系
            session.run("MATCH (n) DETACH DELETE n")

            after = session.run("MATCH (n) RETURN count(n) AS c").single()["c"]
            rel_after = session.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
            print(f"[完成] 删除后：节点 {after} 个，关系 {rel_after} 条。")
            print("[提示] 重启服务后，若数据库无用户，平台会自动重建默认管理员账号。")

    except Exception as e:  # noqa: BLE001
        print(f"[error] 操作失败：{e}")
        sys.exit(1)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
