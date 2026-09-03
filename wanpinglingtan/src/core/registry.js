'use strict';

/**
 * Provider 注册中心：自动发现 src/providers 下所有 provider 模块，
 * 收集元数据，按分类/优先级/启用状态/密钥可用性对外提供实例。
 *
 * 设计目标：
 *  - 低耦合：新增数据源 = 在 providers/<分类>/ 下放一个继承 BaseProvider 的文件
 *  - 可扩展：引擎只依赖 registry.getProviders(category)，不感知具体实现
 *  - 安全：requiresKey 的 provider 在无密钥时自动停用（宁缺毋滥）
 */

const fs = require('fs');
const path = require('path');
const { BaseProvider } = require('./base');

const PROVIDERS_DIR = path.join(__dirname, '..', 'providers');

class Registry {
  constructor() {
    this.providers = []; // { Class, meta }
    this.config = {
      keys: {}, // name -> value
      enabled: {}, // id -> bool (覆盖默认)
      concurrency: 24,
      timeout: 20000,
    };
    this._discover();
  }

  _isProviderClass(mod) {
    if (!mod) return [];
    // 模块可能直接导出类（函数），或 { default: Class }，或 { SomeProvider: Class }
    const candidates = [];
    if (typeof mod === 'function' && mod.prototype instanceof BaseProvider) candidates.push(mod);
    if (typeof mod === 'object') {
      for (const key of Object.keys(mod)) {
        const v = mod[key];
        if (typeof v === 'function' && v.prototype instanceof BaseProvider) candidates.push(v);
      }
    }
    return candidates;
  }

  _discover() {
    if (!fs.existsSync(PROVIDERS_DIR)) return;
    const walk = (dir) => {
      let entries = [];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch (_) {
        return;
      }
      for (const ent of entries) {
        if (ent.name.startsWith('.') || ent.name === 'node_modules') continue;
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) {
          walk(full);
        } else if (ent.isFile() && ent.name.endsWith('.js')) {
          try {
            const mod = require(full);
            const classes = this._isProviderClass(mod);
            for (const Cls of classes) {
              this.providers.push({
                Class: Cls,
                meta: {
                  id: Cls.id,
                  category: Cls.category,
                  label: Cls.label,
                  description: Cls.description || '',
                  requiresKey: !!Cls.requiresKey,
                  keyEnv: Cls.keyEnv || null,
                  priority: Cls.priority || 50,
                  defaultEnabled: Cls.defaultEnabled !== false,
                },
              });
            }
          } catch (e) {
            // 单个模块加载失败不应中断整个注册
            console.error(`[registry] 加载 provider 失败 ${full}: ${e.message}`);
          }
        }
      }
    };
    walk(PROVIDERS_DIR);
  }

  setConfig(config = {}) {
    if (config.keys) Object.assign(this.config.keys, config.keys);
    if (config.enabled) Object.assign(this.config.enabled, config.enabled);
    if (config.concurrency) this.config.concurrency = config.concurrency;
    if (config.timeout) this.config.timeout = config.timeout;
  }

  list() {
    return this.providers.map((p) => p.meta);
  }

  /** 该 provider 当前是否可用（启用 + 密钥满足） */
  _isAvailable(meta) {
    if (meta.id in this.config.enabled) {
      if (!this.config.enabled[meta.id]) return false;
    } else if (!meta.defaultEnabled) {
      return false;
    }
    if (meta.requiresKey) {
      const keyVal = meta.keyEnv ? process.env[meta.keyEnv] : null;
      const cfgKey = this.config.keys[meta.id] || this.config.keys[meta.keyEnv || ''];
      if (!keyVal && !cfgKey) return false;
    }
    return true;
  }

  /** 取得某分类下、当前可用且按优先级排序的 provider 类列表 */
  getProviders(category) {
    return this.providers
      .filter((p) => p.meta.category === category && this._isAvailable(p.meta))
      .sort((a, b) => (a.meta.priority || 50) - (b.meta.priority || 50))
      .map((p) => p.Class);
  }

  /** 所有可用 provider 元信息（用于 UI 展示能力清单） */
  availableList() {
    return this.providers
      .map((p) => ({ ...p.meta, available: this._isAvailable(p.meta) }))
      .sort((a, b) => a.category.localeCompare(b.category) || (a.priority || 50) - (b.priority || 50));
  }

  /** 实例化一个 provider，注入运行上下文 */
  instantiate(Class, ctx) {
    return new Class(ctx);
  }
}

let _singleton = null;
function getRegistry() {
  if (!_singleton) _singleton = new Registry();
  return _singleton;
}

module.exports = { Registry, getRegistry };
