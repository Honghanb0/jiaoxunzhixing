'use strict';

/**
 * 并发信号量：限制同时进行的异步任务数量，避免打爆网络或被封。
 * 用法：
 *   const pool = new Pool(20);
 *   await Promise.all(tasks.map(t => pool.run(() => doWork(t))));
 */
class Pool {
  constructor(max = 20) {
    this.max = Math.max(1, max | 0);
    this.active = 0;
    this.queue = [];
  }

  run(fn) {
    return new Promise((resolve, reject) => {
      const task = { fn, resolve, reject };
      if (this.active < this.max) {
        this._exec(task);
      } else {
        this.queue.push(task);
      }
    });
  }

  _exec(task) {
    this.active++;
    Promise.resolve()
      .then(() => task.fn())
      .then(
        (val) => {
          task.resolve(val);
        },
        (err) => {
          task.reject(err);
        }
      )
      .finally(() => {
        this.active--;
        if (this.queue.length > 0) {
          const next = this.queue.shift();
          this._exec(next);
        }
      });
  }

  /** 批量并发执行，返回结果数组（顺序与输入一致），单个失败返回 {error} */
  async map(items, fn, onItem) {
    return Promise.all(
      items.map((item, idx) =>
        this.run(async () => {
          try {
            const r = await fn(item, idx);
            if (onItem) onItem(r, idx);
            return r;
          } catch (e) {
            return { __error: e.message || String(e) };
          }
        })
      )
    );
  }
}

module.exports = { Pool };
