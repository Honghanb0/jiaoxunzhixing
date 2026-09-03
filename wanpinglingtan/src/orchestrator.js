'use strict';

/**
 * 采集协调器（v3）。
 * 改为「薄封装」：构建统一的 job，交给 Provider 引擎编排执行。
 * 所有阶段流水线、并发控制、去重、错误隔离、结构化输出均位于 core/engine。
 *
 * 设计原则：宁可返回空结果，也不收集不可靠/疑似虚假资产。
 */

const { createEngine } = require('./core/engine');

async function runCollection(form, emitter) {
  const engine = createEngine();
  return engine.run(form || {}, emitter);
}

module.exports = { runCollection };
