// 登录链路验证：直接加载 web/index.html 中真实的 <script>，用最小 DOM stub 运行，
// 调用真实的 apiRequest，验证各条成功与失败路径的提示文案与地址回退行为。
// 用法: node tools/verify_login.js
const fs = require('fs');
const path = require('path');

const htmlPath = path.join(__dirname, '..', 'web', 'index.html');
const html = fs.readFileSync(htmlPath, 'utf8');
const m = html.match(/<script[^>]*>([\s\S]*?)<\/script>/);
if (!m) { console.error('未找到 script 块'); process.exit(1); }
const pageScript = m[1];

function makeElement() {
    return {
        style: {}, value: '', textContent: '', innerHTML: '', disabled: false,
        classList: { add() {}, remove() {}, contains() { return false; } },
        appendChild() {}, addEventListener() {}, reset() {}, dataset: {},
    };
}

// 运行页面脚本，返回可调用的测试上下文。
// elements 按 id 持久化，使得输入框的 value 能跨调用保留（模拟真实 DOM）。
function runPage(origin, sharedStore) {
    // sharedStore 用于跨"页面实例"共享 localStorage，模拟同一浏览器多次打开页面
    const store = sharedStore || new Map();
    const elements = new Map();

    const getEl = (id) => {
        if (!elements.has(id)) elements.set(id, makeElement());
        return elements.get(id);
    };

    const sandbox = {
        location: { protocol: 'http:', origin, href: origin + '/' },
        setInterval, clearInterval,
        localStorage: {
            getItem: (k) => (store.has(k) ? store.get(k) : null),
            setItem: (k, v) => store.set(k, String(v)),
            removeItem: (k) => store.delete(k),
        },
        document: {
            addEventListener() {},
            getElementById: getEl,
            querySelector: () => makeElement(),
            querySelectorAll: () => [],
            createElement: () => makeElement(),
            body: { appendChild() {} },
        },
        console,
        fetch: (...a) => fetch(...a),
        AbortController,
        setTimeout,
        clearTimeout,
        Error, JSON, Math, String, Number,
    };

    const keys = Object.keys(sandbox);
    const fn = new Function(...keys, pageScript + `
        ;return {
            get API_BASE(){return API_BASE},
            get API_HOST(){return API_HOST},
            API_HOSTS, initAPIHost, probeHost, apiRequest, APIError, httpErrorText,
            get currentToken(){return authToken},
            // 登录表单状态相关
            loginFormState, logout, readLoginForm, restoreLoginForm,
            onLoginFieldInput, onLoginFieldBlur, onLoginFieldFocus,
            prefillLoginUsername, clearLoginPassword,
            startAutoRefresh, stopAutoRefresh,
            get autoRefreshTimer(){return autoRefreshTimer},
            // 测试钩子：替换候选地址列表，用于构造"所有地址都不通"的场景
            setAPIHosts(hosts){
                API_HOSTS.length = 0;
                hosts.forEach(h => API_HOSTS.push(h));
                activeHostIndex = 0;
                API_BASE = getAPIBase();
                API_HOST = getAPIHost();
            }
        };
    `);

    const ctx = fn(...keys.map((k) => sandbox[k]));
    ctx.elements = elements;
    ctx.getEl = getEl;
    ctx.browserStore = store;
    return ctx;
}

// 模拟真实输入：先写 DOM 值，再触发 oninput 处理器
function type(ctx, field, value) {
    const id = field === 'username' ? 'loginUsername' : 'loginPassword';
    ctx.getEl(id).value = value;
    ctx.onLoginFieldInput(field, value);
}

const BACKEND = 'http://localhost:8080';
const ALT_BACKEND = 'http://127.0.0.1:8080';
const PREVIEW = 'http://127.0.0.1:58815';   // 模拟 IDE 预览面板：托管页面但无 /api
const DEAD = 'http://127.0.0.1:59999';      // 必然不可达

let failures = 0;
function check(name, cond, detail) {
    if (!cond) failures++;
    console.log(`  [${cond ? 'PASS' : 'FAIL'}] ${name}${detail ? ' -> ' + detail : ''}`);
}
function section(title) {
    console.log();
    console.log('='.repeat(66));
    console.log(title);
    console.log('='.repeat(66));
}

(async () => {
    section('场景一：页面由后端自身托管（' + BACKEND + '）');
    {
        const ctx = runPage(BACKEND);
        await ctx.initAPIHost();
        check('选中后端地址', ctx.API_HOST === BACKEND, ctx.API_HOST);
        const data = await ctx.apiRequest('/auth/login', {
            method: 'POST', body: { username: 'admin', password: 'Admin@123' }, skipAuth: true,
        });
        check('正确凭据登录成功', !!(data && data.token), 'role_level=' + (data.user || {}).role_level);
    }
    {
        const ctx = runPage(BACKEND);
        await ctx.initAPIHost();
        try {
            await ctx.apiRequest('/auth/login', { method: 'POST', body: { username: 'admin', password: 'bad' }, skipAuth: true });
            check('错误密码应报错', false, '居然成功了');
        } catch (e) {
            check('错误密码返回中文提示', /[一-龥]/.test(e.message) && e.status === 401, `"${e.message}"`);
        }
    }

    section('场景二：页面跑在预览面板（' + PREVIEW + '，无 /api）→ 应自动回退');
    {
        const ctx = runPage(PREVIEW);
        console.log('  候选地址:', ctx.API_HOSTS.join(' | '));
        const found = await ctx.initAPIHost();
        check('探测到可用后端', found === true, '选中 ' + ctx.API_HOST);
        check('已回退到 8080 端口', /:8080$/.test(ctx.API_HOST), ctx.API_HOST);
        const data = await ctx.apiRequest('/auth/login', {
            method: 'POST', body: { username: 'admin', password: 'Admin@123' }, skipAuth: true,
        });
        check('回退后登录成功', !!(data && data.token), 'user=' + (data.user || {}).username);
    }

    section('场景三：后端完全不可达 —— 复现 "Failed to fetch"');
    {
        const ctx = runPage(DEAD);
        // 把所有候选都换成死地址，模拟服务确实没启动
        ctx.setAPIHosts(['http://127.0.0.1:59998', 'http://127.0.0.1:59999']);
        try {
            await ctx.apiRequest('/auth/login', {
                method: 'POST', body: { username: 'admin', password: 'Admin@123' }, skipAuth: true, timeout: 6000,
            });
            check('后端不可达应报错', false, '居然成功了');
        } catch (e) {
            const hasEnglish = /Failed to fetch|NetworkError|TypeError/i.test(e.message);
            check('不再抛出英文 "Failed to fetch"', !hasEnglish, 'kind=' + e.kind);
            check('给出中文可读提示', /[一-龥]/.test(e.message), `"${e.message}"`);
            check('提示中列出排查方向', /启动服务|监听|尝试/.test(e.message), '');
            check('提示列出已尝试的地址', /59998/.test(e.message) && /59999/.test(e.message), '');
        }
    }

    section('场景三-B：页面来源是死地址，但后端在 8080 → 应自动救回');
    {
        const ctx = runPage(DEAD);
        const data = await ctx.apiRequest('/auth/login', {
            method: 'POST', body: { username: 'admin', password: 'Admin@123' }, skipAuth: true, timeout: 8000,
        });
        check('自动回退后登录成功', !!(data && data.token), '实际使用 ' + ctx.API_HOST);
    }

    section('场景四：HTTP 状态码中文映射');
    {
        const ctx = runPage(BACKEND);
        const map = { 400: '请求参数有误', 401: '登录', 403: '权限', 404: '不存在', 500: '服务器', 503: '服务' };
        for (const [code, kw] of Object.entries(map)) {
            const text = ctx.httpErrorText(Number(code), '');
            check(`HTTP ${code} -> 中文`, /[一-龥]/.test(text) && text.includes(kw), `"${text}"`);
        }
    }

    section('场景五：地址可切换（localStorage 记忆上次可用地址）');
    {
        const ctx = runPage(PREVIEW);
        await ctx.initAPIHost();
        check('记住可用地址', /:8080$/.test(ctx.API_HOST), ctx.API_HOST);
        // 二次运行：即使页面仍在预览面板，也应直接用记住的地址
        const first = ctx.API_HOST;
        check('候选列表以记住的地址开头或已定位', ctx.API_HOSTS.includes(first), first);
    }

    section('场景六：登录表单状态保持（回归：切换输入框时账号被清空）');
    {
        const ctx = runPage(BACKEND);
        const uEl = ctx.getEl('loginUsername');
        const pEl = ctx.getEl('loginPassword');

        // 1. 输入账号
        type(ctx, 'username', 'admin');
        check('输入账号后 DOM 有值', uEl.value === 'admin', uEl.value);

        // 2. 焦点切换到密码框（触发 blur）
        ctx.onLoginFieldBlur('username');
        check('切换到密码框后账号仍在', uEl.value === 'admin', `账号="${uEl.value}"`);

        // 3. 输入密码
        type(ctx, 'password', 'Admin@123');
        check('密码已写入', pEl.value === 'Admin@123', '');
        check('输入密码后账号仍未被清空', uEl.value === 'admin', `账号="${uEl.value}"`);

        // 4. 关键回归：程序性 logout（401 触发）不得清空输入框
        ctx.logout();
        check('程序性登出后账号保留', uEl.value === 'admin', `账号="${uEl.value}"`);
        check('程序性登出后密码保留', pEl.value === 'Admin@123', '');

        // 5. 提交时应能取到完整凭据
        const form = ctx.readLoginForm();
        check('提交取值完整', form.username === 'admin' && form.password === 'Admin@123',
              `${form.username} / ${form.password}`);

        // 6. 用户主动退出：清密码、留账号
        ctx.logout({ userInitiated: true });
        check('主动退出后密码已清空', pEl.value === '', '');
        check('主动退出后账号保留', uEl.value === 'admin', `账号="${uEl.value}"`);

        // 7. 外部把 DOM 清空后，聚焦应能从 state 恢复
        uEl.value = '';
        ctx.onLoginFieldFocus('username');
        check('DOM 被清空后可从 state 恢复', uEl.value === 'admin', `账号="${uEl.value}"`);

        // 8. 账号已持久化，新页面（共享 localStorage）可带出
        const ctx2 = runPage(BACKEND, ctx.browserStore);
        ctx2.prefillLoginUsername();
        check('新页面自动带出记住的账号', ctx2.getEl('loginUsername').value === 'admin',
              ctx2.getEl('loginUsername').value);
    }

    section('场景七：未登录时不得启动后台轮询（根因防护）');
    {
        const ctx = runPage(BACKEND);
        check('页面加载后轮询未启动', ctx.autoRefreshTimer === null, String(ctx.autoRefreshTimer));

        // 手动启动后再登出，应被停止
        ctx.startAutoRefresh();
        check('可手动启动轮询', ctx.autoRefreshTimer !== null, '');
        ctx.stopAutoRefresh();
        check('登出/停止后轮询被清理', ctx.autoRefreshTimer === null, '');

        // 程序性登出也应顺带停掉轮询
        ctx.startAutoRefresh();
        ctx.logout();
        check('logout 会停止轮询', ctx.autoRefreshTimer === null, '');
    }

    console.log();
    console.log('='.repeat(66));
    console.log(failures === 0 ? '全部通过 ✔' : `${failures} 项失败 ✘`);
    console.log('='.repeat(66));
    process.exit(failures === 0 ? 0 : 1);
})();
