"""证书生命周期图的中英对照表。

**中文是唯一的事实来源。** `docs/certificate-lifecycle.html` 用手写中文维护，
英文版由 `scripts/build-diagram-langs.py` 拿这张表逐条替换生成。这样：

- 编辑只维护一份文件，不会出现两份 HTML 各自漂移
- 生成脚本在还有中文残留时**直接报错**，所以不可能悄悄漏译

键是去掉了首尾空白的完整中文串。改中文而忘了改这里，构建会以
"这条没有英文对照"的形式失败 —— 而不是安静地留下一块中文。
"""

# ── 图内标签（foreignObject 与 <text>）────────────────────────────────────────
LABELS = {
    "人 / CI / 上游系统": "Human / CI / upstream",
    "_wecert.* TXT 声明": "_wecert.* TXT declarations",
    "唯一的授权动作": "the one explicit authorisation",
    "CLB 七层规则": "CLB layer-7 rules",
    "守卫 1 · 必需": "guard 1 · required",
    "A / AAAA 记录": "A / AAAA records",
    "守卫 2 · 可选": "guard 2 · optional",
    "一次性进程 · timer": "one-shot · systemd timer",
    "1 · 枚举 _wecert 声明": "1 · enumerate _wecert declarations",
    "2 · 解析 + CLB 守卫过滤": "2 · parse + apply the CLB guard",
    "3 · 按 PSL 注册域分组": "3 · group by PSL registered domain",
    "4 · 通配符优先覆盖": "4 · wildcard-first coverage",
    "5 · 五条熔断门禁": "5 · the five safety gates",
    "6 · 原子写出文档": "6 · write the document atomically",
    "report.json": "report.json",
    "逐名字的理由": "per-name reasons",
    "期望状态文档": "desired-state document",
    "revision 指纹": "revision fingerprint",
    "原子 rename": "atomic rename",
    "可 git diff": "git-diffable",
    "守护进程 / oneshot": "daemon / one-shot",
    "1 · 读期望状态（只读）": "1 · read the desired state (read-only)",
    "2 · 逐张决策：签发/重签/续期": "2 · decide per certificate: issue / reissue / renew",
    "3 · 订单状态机（ACME）": "3 · the order state machine (ACME)",
    "4 · DNS-01 挑战编排": "4 · DNS-01 challenge orchestration",
    "5 · 部署到腾讯云": "5 · deploy to Tencent Cloud",
    "6 · ARI 协调续期": "6 · ARI-coordinated renewal",
    "腾讯云 SSL": "Tencent Cloud SSL",
    "上传 / 一键更新": "upload / update instances",
    "同一个 DNS zone 既放声明（输入）也放 _acme-challenge 挑战记录（机制）—— 谁能写这个 zone，谁本来就能为其中任何名字做 DNS-01 验证，把声明放这里没有引入新的信任边界。":
        "One DNS zone holds both the declarations (input) and the <code>_acme-challenge</code> records (mechanism) — anyone who can write this zone could already pass DNS-01 for any name in it, so putting the declarations here introduces no new trust boundary.",
    "挑战回环的时序见 图 ⑤": "the challenge round-trip is diagram ⑤",
    "另外，每一轮都会拨一个真实的 TLS 连接读回对端实际出示的证书，比对\"在服务的\"和\"部署的\" —— 这是唯一不信任云控制面的证据，因为换绑是异步的、SNI 上也可能有另一张证书在赢。wecert-probe":
        "Separately, every pass dials a real TLS connection and reads back the certificate actually served, comparing “what is live” against “what was deployed” — the only evidence that does not trust the cloud control plane, because the rebind is asynchronous and another certificate can be winning SNI. <code>wecert-probe</code>",
    "① 枚举声明": "① enumerate declarations",
    "_wecert.* 全部 zone": "_wecert.* across all zones",
    "② 解析 + 过滤": "② parse + filter",
    "未知键报错": "unknown keys rejected",
    "CLB 守卫 1": "CLB guard 1",
    "③ 分组 + 覆盖": "③ group + cover",
    "PSL 注册域分组": "group by PSL registered domain",
    "通配符优先": "wildcard-first",
    "算出最小 SAN 集": "compute the minimal SAN set",
    "④ 门禁": "④ gates",
    "骤变 >30%": "abrupt drop >30%",
    "删除宽限 24h": "24h removal grace",
    "配额 25 次/7d": "quota 25 changes / 7d",
    "空集合拒绝": "empty set refused",
    "⑤ 组装文档": "⑤ assemble the document",
    "证书名 ← 分组键": "name ← grouping key",
    "⑥ 原子写盘": "⑥ atomic write",
    "再写 report / state": "then report / state",
    "冻结 · 保持上一版": "frozen · previous revision kept",
    "文档一个字不改，wecert 继续按上一版续期":
        "the document is untouched; wecert keeps renewing from the last revision",
    "冻结期间没有任何东西会坏": "nothing breaks while frozen",
    "退出码 2 → 接进监控": "exit code 2 → wire it into monitoring",
    "局部失败不会冻结整轮 —— 一个手误不该让所有证书停止更新":
        "a local failure does not freeze the whole run — one typo must not stop every certificate from updating",
    "② 单条声明无效 → 只排除该条，报告里留 reason · ③ 某组超 25 个 SAN → 只保留该组上一版 · ③ 某组跨注册域 → 契约层直接拒绝":
        "② a malformed declaration excludes just that one, with a reason in the report · ③ a group over 25 SANs keeps only its previous revision · ③ a group spanning registered domains is rejected by the contract",
    "每轮开始 · 按期望状态来源求值": "each pass starts by evaluating the desired-state source",
    "static = 配置里的 certificates | observe = 前者 + 影子对比 | enforce = 文档":
        "static = certificates in the config | observe = that plus a shadow diff | enforce = the document",
    "期望状态读到了吗？": "did the desired state load?",
    "否 → 整轮跳过": "no → skip the entire pass",
    "DesiredStateErrors++；绝不当作\"期望为空\"。跳过一轮只是这次没续上；把空当期望会让域名被摘掉。":
        "DesiredStateErrors++; never treat it as “the desired state is empty”. Skipping a pass only costs this renewal; treating empty as real strips names off the certificate.",
    "state.db 里没有这张证书？": "not in state.db yet?",
    "是 → 首次签发": "yes → first issuance",
    "建订单 → DNS-01 → finalize → 上传 → 需要人工在 CLB 绑一次 → deploy_confirmed=1":
        "create order → DNS-01 → finalize → upload → one manual CLB bind → deploy_confirmed=1",
    "SAN 集合与期望不一致？": "does the SAN set differ from the desired one?",
    "是 → 重签（CoverageDrift）": "yes → reissue (CoverageDrift)",
    "比较对顺序/大小写/重复不敏感，双向—— 少一个域名也算漂移。没有它，往 classic 证书加域名会静默等 60 天。":
        "the comparison ignores order, case and duplicates, and is bidirectional — a missing name counts too. Without it, adding a domain to a classic certificate would wait up to 60 days, silently.",
    "ARI 建议窗口到了？": "has the ARI window opened?",
    "是 → 续期，订单带 replaces": "yes → renew, with replaces on the order",
    "ARI 协调的续期豁免所有 Let's Encrypt 限速。这是唯一应该走的续期路径。":
        "ARI-coordinated renewals are exempt from every Let's Encrypt rate limit. This is the only renewal path worth taking.",
    "ARI 不可用 且 到 renewBefore？": "ARI unavailable and renewBefore reached?",
    "是 → 兜底续期": "yes → fallback renewal",
    "notAfter − renewBefore（classic 30d / tlsserver 15d / shortlived 48h），叠加确定性抖动避免多实例同时敲门。":
        "notAfter − renewBefore (classic 30d / tlsserver 15d / shortlived 48h), plus deterministic jitter so multiple instances do not knock at once.",
    "以上都不命中": "none of the above",
    "本轮不动": "do nothing this pass",
    "这是常态。只更新指标（notAfter、ARI 窗口、失败计数），不产生任何签发。":
        "This is the normal case. Only metrics are refreshed (notAfter, ARI window, failure count); nothing is issued.",
    "无单": "no order",
    "orders 表无行": "no row in orders",
    "已下单": "order created",
    "挑战已写入": "challenges written",
    "TXT 全写完": "every TXT written",
    "传播检查通过": "propagation confirmed",
    "授权有效": "authorizations valid",
    "全部 valid": "all valid",
    "已 finalize": "finalized",
    "CSR DER 提交到": "CSR (DER) posted to",
    "已签发": "issued",
    "已部署": "deployed",
    "任一步失败 → 退避，不重新下单": "any step fails → back off, never re-order",
    "consecutive_failures++ 且 next_attempt_at 退避。":
        "consecutive_failures++ and next_attempt_at is pushed out.",
    "撞了 5 authorization failures per identifier per hour 之后猛重试只会更糟，所以退避有上限并转人工。":
        "after 5 authorization failures per identifier per hour, retrying hard only makes it worse, so the backoff is capped and hand over to a human.",
    "旧证书 → 退役 → 从腾讯云删除": "old certificate → retired → deleted from Tencent Cloud",
    "换绑成功后旧 CertID 会落进 retired_certificates，":
        "once the rebind succeeds the old CertID lands in retired_certificates,",
    "ReapRetired 在 7 天保留期之后才真正删 —— 留出回滚窗口。":
        "and ReapRetired deletes it only after the 7-day retention window — leaving room to roll back.",
    "3 · 发现两个 identifier": "3 · two identifiers turn out to",
    "指向同一个记录名": "share one record name",
    "5 · 传播检查（quorum）": "5 · propagation check (quorum)",
    "无可达 NS 否认 且 ≥1 确认": "no NS denial, ≥1 confirms",
    "多台权威时要求 ≥2 台": "multi-NS zones: ≥2 confirm",
    "证书有效区间": "certificate validity",
    "ARI 建议窗口": "ARI suggested window",
    "renewBefore 兜底窗口（仅当 ARI 不可用）": "renewBefore fallback (only when ARI is unavailable)",
    "上传 SSL + 人工绑一次 → deploy_confirmed=1":
        "upload to SSL + one manual bind → deploy_confirmed=1",
    "续期发生在这里 → 新证书生效": "renewal happens here → the new certificate goes live",
    "旧 CertID 进入 retired_certificates，保留 7 天后从腾讯云删除":
        "the old CertID goes to retired_certificates and is deleted from Tencent Cloud 7 days later",
    "到期告警应当基于 not_after，不是基于\"续期任务有没有报错\"—— 后者会在程序静默失效时保持沉默。":
        "Alert on not_after, not on “did the renewal job error” — the latter stays silent when the program is quietly broken.",
    "意图 · 人写": "intent · human-written",
    "推断 · 可丢弃": "inference · disposable",
    "契约 · 可 review": "contract · reviewable",
    "执行 · 必须稳": "execution · stable",
    "外部": "external",
    "枚举": "enumerate",
    "守卫": "guard",
    "原子写": "atomic write",
    "只读": "read-only",
    "部署": "deploy",
    "来源不可读": "source unreadable",
    "门禁命中": "gate tripped",
    "冻结写在报告里，不写文档": "a freeze goes into the report, never the document",
    "否": "no",
    "否则 ↓": "otherwise ↓",
    "写": "write",
    "验": "verify",
    "提": "submit",
    "绑": "bind",
    "ARI 窗口到 → 新订单带 replaces": "ARI window opens → new order carries replaces",
    "newOrder(identifiers, replaces = ARI 时的旧 certID)":
        "newOrder(identifiers, replaces = the old certID when ARI is in play)",
    "order + 每个 identifier 一个 authorization": "order + one authorization per identifier",
    "写入全部 TXT（不是逐条写逐条验）": "write every TXT (not one at a time)",
    "从多个 vantage point 读回 TXT": "read the TXT back from several vantage points",
    "authorizations: 全部 valid": "authorizations: all valid",
    "POST CSR（DER）到 finalize URL ← 不是 order URL":
        "POST the CSR (DER) to the finalize URL ← not the order URL",
    "order valid + certificate URL → 下载证书": "order valid + certificate URL → download it",
    "一起清理全部 TXT": "clean up every TXT together",
    "约 2/3 处，由 CA 决定": "around two-thirds in, decided by the CA",
    "day 0 · 首次签发": "day 0 · first issuance",
    "90 天": "90 days",

    # 图的 aria-label（给读屏用的，不显示在图上）
    "wecert 系统全景架构图": "wecert system map",
    "wecert-onboard 推断流水线": "the wecert-onboard inference pipeline",
    "wecert 每轮收敛的决策流程": "wecert's per-pass decision flow",
    "ACME 订单状态机": "the ACME order state machine",
    "证书生命周期时间线": "certificate lifetime timeline",
}


# ── 页面正文（块级元素，值为 innerHTML，所以可以保留 <b>/<code> 这类强调）──
PROSE: dict[str, str] = {
    '证书从"有人在 DNS 里加了一行"到"从云上删掉"':
        'From “somebody added a line to a DNS zone” to “deleted from the cloud”',
    '这套系统唯一的核心纪律是：wecert 永远不推断。 某个东西负责推断意图，并把结论写成一份可 diff 的文件；wecert 只读那份文件做收敛。 下面七张图从要解决的问题一路下钻到单个订单的状态机。':
        'The one rule everything else follows: <strong>wecert never infers.</strong>\n    Something else works out what should exist and writes it down; wecert only reads that document and converges.\n    The seven diagrams below go from the problem it solves down to the state machine of a single order.',
    '默认模式 static 迁移路径 static → observe → enforce 当前版本 v0.4.2 + 未发布改动 Go 1.26.6':
        '<span class="badge">default mode <b>static</b></span>\n    <span class="badge">migration <b>static → observe → enforce</b></span>\n    <span class="badge">version <b>v0.4.2 + unreleased changes</b></span>\n    <span class="badge">Go <b>1.26.6</b></span>',
    '图 ①系统全景：谁拥有什么，谁只读什么':
        '<span class="num">diagram ①</span>System map — who owns what, who only reads',
    '从左到右是权限的传递：意图（人写）→ 推断（可丢弃）→ 契约（机器写）→ 执行（必须稳）→ 外部。 每一层的失败模式都不一样，这正是它们被拆开的原因。':
        'Left to right is the transfer of authority: intent (written by a human) → inference (disposable) → contract (machine-written) → execution (must be stable) → external.\n    Each layer has a different failure mode, and that is exactly why they are separated.',
    '插一份文件之后，来源故障的后果变成"期望状态不更新"——保持现状，是安全的。 而且推断逻辑（加来源、调阈值、修边界）必然会反复改，证书生命周期必须稳， 两者绑在一起意味着改推断就是在动签发。':
        'With a document in between, a source failure becomes <strong>the desired state stops updating</strong> — and staying put is safe.\n    Inference logic (new sources, new thresholds, new edge cases) will keep changing; the certificate lifecycle must not.\n    Fusing the two would mean every change to inference is a change to issuance.',
    '图 ②意图 → 契约：推断侧流水线':
        '<span class="num">diagram ②</span>Intent → contract: the inference pipeline',
    'wecert-onboard 跑一轮的六个阶段。注意红色只挂在真正会冻结的地方—— 阶段 2、3 的失败是局部的，不冻结整轮。':
        'The six stages <code>wecert-onboard</code> runs in one pass. Note that red is only attached where a freeze actually happens — a failure in stage 2 or 3 is local and does not freeze the run.',
    '图 ③收敛决策：每轮对每张证书问什么':
        '<span class="num">diagram ③</span>Reconcile decisions — what each pass asks about a certificate',
    '判断是有序的。从上往下第一个命中的分支决定了这一轮做什么，全都不命中就是"本轮不动"—— 而那是绝大多数轮次的正常结果。':
        'The checks are <strong>ordered</strong>. The first branch that matches decides what this pass does, and if none match the answer is “do nothing” — which is what happens on the overwhelming majority of passes.',
    '图 ④订单状态机：崩溃之后从哪里接着跑':
        '<span class="num">diagram ④</span>Order state machine — where a restart picks up',
    '这个状态机的全部意义是让进程随时可以被杀掉。每个状态都在 state.db 里有对应字段， 重启之后靠它们决定"接着跑"还是"重新下单"。':
        'The entire point of this state machine is that <strong>the process can be killed at any moment</strong>. Every state has a column in <code>state.db</code>, and those columns decide, after a restart, whether to carry on or to place a new order.',
    '同一个道理也解释了为什么订单的 identifier 集合被单独存下来： 订单创建时它的 identifier 集合就固定了。如果这期间配置变了， 正确动作是丢弃并重建订单，而不是"遵守不重新下单"去推进一张 CSR 已经无法 finalize 的订单。':
        'The same reasoning explains why an order’s identifier set is stored separately: it is fixed when the order is created. If the configuration changes in the meantime, the correct action is to discard and rebuild the order, not to honour “never create a new order” and keep advancing one whose CSR can no longer finalize.',
    '图 ⑤DNS-01 时序：通配符和顶点共用一个 TXT 名字':
        '<span class="num">diagram ⑤</span>DNS-01 — a wildcard and its apex share one TXT name',
    '这是最容易写错、后果最隐蔽的一段。example.com 和 *.example.com 的挑战记录都叫 _acme-challenge.example.com——同一个名字、两个值。':
        'This is the easiest part to get wrong and the hardest to notice. <code>example.com</code> and <code>*.example.com</code> both put their challenge at <code>_acme-challenge.example.com</code> — one name, two values.',
    '传播检查用 quorum 而不是"全部权威 NS 可达"：实测里 9 个权威 NS 总有 1 个不可达（实测 确认 8 / 否认 0 / 不可达 1）。 要求全部可达会让验证永远通不过；判据是没有任何可达的 NS 否认，且至少一台确认—— 多台权威的 zone 还要求至少 2 台独立确认，只有一台权威的 zone 一台即可。':
        'Propagation checking uses a quorum rather than “every authoritative nameserver reachable”: in practice one of nine is routinely unreachable (measured: 8 confirm, 0 deny, 1 unreachable). Demanding all of them would never pass. The criterion is <strong>no reachable nameserver denies it, and at least one confirms</strong> — with multiple authorities at least <code>2</code> must confirm independently, and a zone with a single authority passes on one.',
    '图 ⑥一张证书的一生（以 classic / 90 天为例）':
        '<span class="num">diagram ⑥</span>The life of one certificate (classic, 90 days)',
    '时间轴按 classic profile 的 90 天画。真正决定续期时刻的是 ARI 的 suggestedWindow；下面的 renewBefore 只是 ARI 拿不到时的兜底。':
        'The axis is drawn for a <code>classic</code> 90-day certificate. What actually decides when renewal happens is ARI’s <code>suggestedWindow</code>; <code>renewBefore</code> below it is only the fallback for when ARI is unavailable.',
    '表 A数据所有权：谁写、谁读、丢了会怎样':
        '<span class="num">table A</span>Data ownership — who writes, who reads, and what losing it costs',
    '"丢了会怎样"这一列是这套系统里最值得记住的部分——它决定了每份状态该放在哪、该不该备份。':
        '“What losing it costs” is the column worth remembering: it decides where each piece of state belongs and whether it needs backing up.',
    '持久化状态的责任划分':
        'Responsibility for each piece of persistent state',
    '谁写':
        'Written by',
    '谁读':
        'Read by',
    '丢了会怎样':
        'If it is lost',
    '人 / CI':
        'a human / CI',
    '有事 宽限期（24h）后域名从证书移除':
        '<span class="pill warn">matters</span> after the 24h grace period the names leave the certificate',
    '安全 wecert 冻结在上一版并告警':
        '<span class="pill ok">safe</span> wecert freezes on the previous revision and alarms',
    '有事 宽限期归零 → 删除变激进':
        '<span class="pill warn">matters</span> the grace period resets, so deletion turns aggressive',
    '人':
        'a human',
    '无所谓 只影响排障':
        '<span class="pill ok">harmless</span> troubleshooting only',
    '灾难 order URL / ARI certID / CertID 全丢 → 重复下单撞 exact-set 限速':
        '<span class="pill stop">disaster</span> order URLs, ARI certIDs and CertIds all gone → orders re-placed into the exact-set limit',
    'ACME 账号私钥':
        'The ACME account key',
    '灾难 重建账号是有限资源（每 IP 每 3h 最多 10 个）':
        '<span class="pill stop">disaster</span> accounts are a limited resource (10 per IP per 3 hours)',
    '表 B失败语义：每一种"读不到"都有明确的反应':
        '<span class="num">table B</span>Failure semantics — every kind of “cannot read it” has a defined reaction',
    '这张表是整套设计的核心。没有一种情况会把"读不到"当成"没有了"。':
        'This table is the heart of the design. <strong>None of these treats “unreadable” as “gone”.</strong>',
    '故障 → 反应 → 理由':
        'Situation → reaction → why',
    '反应':
        'Reaction',
    '为什么':
        'Why',
    '声明来源读不到（DNS API 抖动 / 权限被改）':
        'Declaration source unreadable (DNS API hiccup, permissions changed)',
    '整轮冻结 文档一个字不改':
        '<span class="pill stop">freeze the whole run</span> the document is untouched',
    '空 ≠ 没了。照做会重签一张不含域名的证书':
        'Empty is not the same as gone; acting on it would reissue a certificate with no names',
    'CLB 守卫读不到':
        'CLB guard unreadable',
    '不做任何删除 且守卫视为"通过"':
        '<span class="pill warn">no deletions at all</span> and the guard counts as satisfied',
    '降级会让安全性随故障一起消失，而你恰好在那时最需要它':
        'Degrading makes safety disappear along with the dependency, exactly when you need it most',
    '文档读不到（运行期）':
        'Document unreadable (runtime)',
    '冻结在最后一版 继续按它续期':
        '<span class="pill warn">freeze on the last revision</span> and keep renewing from it',
    '续期不停，只是新域名进不来':
        'Renewals continue; only new names stop arriving',
    '文档读不到（启动期 · enforce）':
        'Document unreadable (startup · enforce)',
    '硬失败，不启动':
        '<span class="pill stop">hard failure, does not start</span>',
    '起不来是吵闹的；"起得来但什么都不续期"是无声的':
        'Failing to start is loud; “starts but renews nothing” is silent',
    '文档读不到（启动期 · observe）':
        'Document unreadable (startup · observe)',
    '降级为 static 并明确告警':
        '<span class="pill ok">falls back to static</span> with a clear warning',
    '观察期文档还没生成是正常状态，不该让进程起不来':
        'While observing, the document not existing yet is normal and must not stop the process',
    '算出来的期望状态是空的':
        'The desired state computes to empty',
    '拒绝写盘 -force 也不行':
        '<span class="pill stop">refuse to write</span> <code>-force</code> does not override',
    '"合法的空"和"生成失败的空"在文件里长得一模一样':
        'A legitimate empty state and a failed generation look identical in the file',
    '声明集合骤降 > 30%':
        'Declared set drops by more than 30%',
    '冻结 + 告警':
        '<span class="pill stop">freeze + alert</span>',
    '正常下线不会少三成；突然少三成几乎一定是上游塌了':
        'A normal decommission does not lose a third; losing a third means the upstream collapsed',
    '7 天内集合变更超 25 次':
        'More than 25 name-set changes in 7 days',
    'LE 只给 50 次/注册域/7 天，还跨账号共享':
        'Let’s Encrypt allows 50 per registered domain per 7 days, shared across accounts',
    '删除一个名字':
        'Removing a name',
    '三条件同时满足才删':
        '<span class="pill warn">only when all three hold</span>',
    '确认缺失 + 超过 24h + 没有 CLB 规则引用':
        'Confirmed absent + past 24h + unreferenced by any CLB rule',
    '某组超过 25 个 SAN':
        'A group exceeds 25 SANs',
    '保留该组上一版':
        '<span class="pill warn">keep that group’s previous revision</span>',
    '丢掉整组会让 wecert 看到一张证书凭空消失':
        'Dropping the group would show wecert a certificate that vanished',
    '单条声明写错（未知键）':
        'One declaration is malformed (unknown key)',
    '只排除该条 报告里留 reason':
        '<span class="pill ok">exclude just that one</span> with a reason in the report',
    '一个手误不该让所有证书停止更新':
        'A single typo must not stop every certificate from updating',
    '某张证书签发失败':
        'One certificate fails to issue',
    '不影响其它证书':
        '<span class="pill ok">does not affect the others</span>',
    '一张配错域名的证书拖住全部续期，是自动化里最危险的耦合':
        'One misconfigured certificate holding up every renewal is the most dangerous coupling in automation',
    '临近到期且反复签发失败（failureFallback 开启时）':
        'Near expiry and issuance keeps failing (<code>failureFallback</code> on)',
    '摘掉反复失败的名字先签':
        '<span class="pill warn">drop the names that keep failing</span> and sign the rest',
    '部分可用好过全挂。只摘有逐个授权失败证据的名字；记录老化后不再摘它，但全集要等到下一个续期窗口才重试':
        'Partial availability beats total failure. Only names with evidence of individual failure are dropped; once that record ages out the name is no longer dropped, but the full set is only retried at the next renewal window',
    '表 C限速算术：为什么"通配符优先"不是优化项':
        '<span class="num">table C</span>The rate-limit arithmetic — why wildcard-first is not an optimisation',
    '额度':
        'Allowance',
    '什么时候撞':
        'When you hit it',
    '怎么避':
        'How to avoid it',
    'New Orders / 账号':
        'New Orders / account',
    '300 / 3 小时':
        '300 / 3 hours',
    '反复下单':
        'Re-placing orders',
    'order URL 落盘，崩溃后复用':
        'Persist the order URL and reuse it after a crash',
    'New Certs / 注册域':
        'New Certs / registered domain',
    '50 / 7 天 · 跨账号共享':
        '50 / 7 days · <strong>shared across accounts</strong>',
    '域名集合频繁变化':
        'Frequent changes to the name set',
    '通配符优先 + 25 次/周预算':
        'Wildcard-first plus a 25-changes-per-week budget',
    'New Certs / 精确 identifier 集合':
        'New Certs / <strong>exact identifier set</strong>',
    '5 / 7 天 · 无 override':
        '5 / 7 days · <strong>no override</strong>',
    '同一组域名反复重签':
        'Reissuing the same name set repeatedly',
    '每证书最多一个在途订单':
        'At most one in-flight order per certificate',
    '5 / 小时':
        '5 / hour',
    'DNS 没配好还猛重试':
        'Retrying a name whose DNS is not configured',
    '退避 + 转人工':
        'Backoff, then hand over to a human',
    'Let\'s Encrypt 速率限制（与本系统相关的部分）':
        "Let's Encrypt rate limits (the ones this system runs into)",
    'ARI 协调的续期：豁免以上全部。 前提是订单必须带 replaces，且与被替换的证书至少共享一个 identifier——集合不变自然满足，完全不相交才失去豁免。':
        '<strong>ARI-coordinated renewals: exempt from all of the above.</strong>\n      The order must carry <code>replaces</code> and share <em>at least one identifier</em> with the certificate it replaces — an unchanged set trivially qualifies; only a wholly disjoint set loses the exemption.',
    '表 D实测踩过的坑':
        '<span class="num">table D</span>Field notes and pitfalls',
    '都是这套东西真跑起来之后才暴露的，按"如果不知道会浪费你多久"排序。':
        'All found by actually running this, ordered by how much time they would waste you.',
    '打印 / 存为 PDF 最后更新 2026-09-18 · 对应 v0.4.2 + 未发布改动':
        '<button class="print" type="button" onclick="window.print()">Print / save as PDF</button><br/>\n      <span style="font-size:12px">last updated 2026-09-18 · for v0.4.2 + unreleased changes</span>',
    '设计动机见 docs/desired-state-providers.md，操作手册见 docs/desired-state.md。 图 ① 的边语义：实线 = 同步，虚线 = 异步，点线 = 可选/兜底，粗线 = 关键路径。':
        'Design rationale in <code>docs/desired-state-providers.md</code>, operator guide in <code>docs/desired-state.md</code>.\n    Edge semantics in diagram ①: solid = synchronous, dashed = asynchronous, dotted = optional/fallback, thick = critical path.',
    'wecert · 证书生命周期架构图':
        'wecert · certificate lifecycle',
    'wecert · 架构 + 生命周期':
        'wecert · architecture + lifecycle',
    '默认模式 static':
        'default mode <b>static</b>',
    '迁移路径 static → observe → enforce':
        'migration <b>static → observe → enforce</b>',
    '当前版本 v0.4.2 + 未发布改动':
        'version <b>v0.4.2 + unreleased changes</b>',
    '① 系统全景':
        '① System map',
    '② 意图 → 契约':
        '② Intent → contract',
    '③ 收敛决策':
        '③ Reconcile decisions',
    '④ 订单状态机':
        '④ Order state machine',
    '⑤ DNS-01 时序':
        '⑤ DNS-01 sequence',
    '⑥ 一张证书的一生':
        '⑥ Life of a certificate',
    '数据所有权':
        'Data ownership',
    '失败语义':
        'Failure semantics',
    '限速算术':
        'Rate-limit arithmetic',
    '坑':
        'Pitfalls',
    '1 · 枚举 _wecert 声明 2 · 解析 + CLB 守卫过滤 3 · 按 PSL 注册域分组 4 · 通配符优先覆盖 5 · 五条熔断门禁 6 · 原子写出文档':
        '1 · enumerate _wecert declarations<br/>2 · parse + apply the CLB guard<br/>3 · group by PSL registered domain<br/>4 · wildcard-first coverage<br/>5 · the five safety gates<br/>6 · write the document atomically',
    'revision 指纹原子 rename可 git diff':
        'revision fingerprint<br/>atomic rename<br/>git-diffable',
    '1 · 读期望状态（只读） 2 · 逐张决策：签发/重签/续期 3 · 订单状态机（ACME） 4 · DNS-01 挑战编排 5 · 部署到腾讯云 6 · ARI 协调续期':
        '1 · read the desired state (read-only)<br/>2 · decide per certificate: issue / reissue / renew<br/>3 · the order state machine (ACME)<br/>4 · DNS-01 challenge orchestration<br/>5 · deploy to Tencent Cloud<br/>6 · ARI-coordinated renewal',
    '图 ⑤':
        'diagram ⑤',
    '人 / 上游 / 声明':
        'Human / upstream / declarations',
    'wecert 自有组件':
        'wecert-owned components',
    '契约（两者之间唯一的接口）':
        'the contract (the only interface between them)',
    '外部服务':
        'external services',
    '持久化状态':
        'persistent state',
    '同步':
        'synchronous',
    '异步':
        'asynchronous',
    '可选':
        'optional',
    '关键路径':
        'critical path',
    '为什么中间要插一份文件':
        'Why put a file in the middle',
    '如果让 wecert 自己去枚举 DNS 和 CLB，那它就在被动观察两个副作用去反推意图。 问题不在准确率，在失败模式：DNS 枚举接口抖一下返回空，wecert 会把它读成 "这些域名都没了"，接着重签一张不含域名的证书，线上立刻握手失败。':
        'If wecert enumerated DNS and CLB itself, it would be <strong>passively watching two side effects to infer intent</strong>. The problem is not accuracy, it is the failure mode: one DNS API hiccup returning empty gets read as “these names are gone”, and it reissues a certificate without them — the site stops handshaking.',
    '未知键报错CLB 守卫 1allowlist':
        'unknown keys rejected<br/>CLB guard 1<br/>allowlist',
    'PSL 注册域分组通配符优先算出最小 SAN 集':
        'group by PSL registered domain<br/>wildcard-first<br/>compute the minimal SAN set',
    '骤变 >30%删除宽限 24h配额 25 次/7d空集合拒绝':
        'abrupt drop &gt;30%<br/>24h removal grace<br/>quota 25 changes / 7d<br/>empty set refused',
    'revision = sha256证书名 ← 分组键':
        'revision = sha256<br/>name ← grouping key',
    'temp + fsync + rename再写 report / state':
        'temp + fsync + rename<br/>then report / state',
    '文档一个字不改，wecert 继续按上一版续期冻结期间没有任何东西会坏退出码 2 → 接进监控':
        'the document is untouched; wecert keeps renewing from the last revision<br/>nothing breaks while frozen<br/>exit code 2 → wire it into monitoring',
    '通配符优先：这里省下的是配额':
        'Wildcard-first: this is where the quota is saved',
    '声明了 *.example.com 之后的边际成本':
        'The marginal cost of declaring <code>*.example.com</code>',
    '动作':
        'Action',
    '没有通配符':
        'Without a wildcard',
    '已有 *.example.com':
        'With <code>*.example.com</code>',
    '加 foo.example.com':
        'Add <code>foo.example.com</code>',
    '1 次重签':
        '<span class="pill warn">1 re-issuance</span>',
    '0 次 SAN 集合不变':
        '<span class="pill ok">0</span> the SAN set does not change',
    '0 次':
        '<span class="pill ok">0</span>',
    '批量导入 50 个子域':
        'Import 50 subdomains',
    '50 次 = 撞满周配额':
        '<span class="pill stop">50 → the weekly allowance is gone</span>',
    '加 a.b.example.com':
        'Add <code>a.b.example.com</code>',
    '1 次 需要 *.b.example.com':
        '1 — needs <code>*.b.example.com</code>',
    '1 次':
        '1',
    '加 example.net':
        'Add <code>example.net</code>',
    '1 次 另一个注册域 = 另一张证书':
        '1 — a different registered domain is a different certificate',
    '通配符不会被凭空造出来。 声明 *.example.com 意味着这张证书能对任意子域完成握手——那是权限扩张， 必须是一个显式声明的动作，不能由分组逻辑替人决定。同理， *.example.com 不覆盖 example.com 本身， 两个都要显式声明。':
        '<strong>A wildcard is never invented.</strong> Declaring <code>*.example.com</code> means the certificate can complete a handshake for <em>any</em> subdomain — that is a privilege expansion, and it has to be an explicit declaration rather than something the grouping logic decides on your behalf. For the same reason <code>*.example.com</code> does <strong>not</strong> cover <code>example.com</code>; both need declaring.',
    '三条不变量决定了上面这个顺序。 ① 每张证书最多一个在途订单，且 order URL 先落盘再干活； ② 续期一律 ARI 优先并带 replaces； ③ 通配符与顶点共用同一个 _acme-challenge 名字，必须"全写 → 全验 → 一起清"。 违反任何一条都会直接撞上 5 certificates per exact set of identifiers / 7 days—— 而那条限速没有 override。':
        '<strong>Three invariants decide that order.</strong> (1) At most one in-flight order per certificate, and the order URL is on disk before anything else happens. (2) Renewals are ARI-first and carry <code>replaces</code>. (3) A wildcard and its apex share one <code>_acme-challenge</code> name, so the TXT records are written together, verified together and cleaned up together. Breaking any of them runs straight into <em>5 certificates per exact set of identifiers / 7 days</em> — and that limit has no override.',
    'TXT 全写完传播检查通过':
        'every TXT written<br/>propagation confirmed',
    'authorizations全部 valid':
        'authorizations<br/>all valid',
    'CSR DER 提交到finalize URL':
        'CSR (DER) posted to<br/>finalize URL',
    'consecutive_failures++ 且 next_attempt_at 退避。 撞了 5 authorization failures per identifier per hour 之后猛重试只会更糟，所以退避有上限并转人工。':
        'consecutive_failures++ and next_attempt_at is pushed out.<br/>After 5 authorization failures per identifier per hour, retrying hard only makes it worse, so the backoff is capped and hand over to a human.',
    '换绑成功后旧 CertID 会落进 retired_certificates， ReapRetired 在 7 天保留期之后才真正删 —— 留出回滚窗口。':
        'Once the rebind succeeds the old CertID lands in retired_certificates,<br/>and ReapRetired deletes it only after the 7-day retention window — leaving room to roll back.',
    'order URL 必须在 newOrder 返回之后立刻落盘，在任何别的事情之前。 这是崩溃安全的全部依赖：如果没有它，进程在 DNS 传播那几分钟里被杀掉， 重启后会再下一单，而那一单的 identifier 集合与前一单完全相同—— 直接撞上 exact-set 限速，且没有任何 override 可以申请。':
        '<strong>The order URL must be on disk immediately after <code>newOrder</code> returns, before anything else.</strong> That is the whole of the crash-safety story: without it, a process killed during the few minutes of DNS propagation would place a second order whose identifier set is identical to the first — straight into the exact-set limit, with <strong>no override available</strong>.',
    '为什么必须"全写 → 全验 → 一起清"':
        'Why it has to be “write all → verify all → clean up together”',
    '如果按 identifier 逐个处理——写一条、验一条、清一条——那么处理 *.example.com 时写入的值， 会在轮到 example.com 之前被清掉，或者被后写入的值覆盖。 DNSPod 允许同一个名字下有多条 TXT，但**清理必须一起做**，否则先验过的那个挑战会失效。':
        'Handling identifiers one at a time — write, verify, clean, next — means the value written for <code>*.example.com</code> gets removed or overwritten before <code>example.com</code> is reached. DNSPod allows several TXT records under one name, but the <strong>cleanup has to happen together</strong>, or a challenge that already verified becomes invalid again.',
    '换 profile 会改变什么':
        'What changing the profile changes',
    '三个 ACME profile 的差异':
        'The three ACME profiles',
    '有效期':
        'Validity',
    '默认 renewBefore':
        'Default <code>renewBefore</code>',
    'classic（默认）':
        '<code>classic</code> (default)',
    '30 天':
        '30 days',
    '45 天':
        '45 days',
    '15 天':
        '15 days',
    '160 小时':
        '160 hours',
    '48 小时':
        '48 hours',
    'CA/Browser Forum 已经排定 2027-03-15 起 ≤100 天、 2029-03-15 起 ≤47 天。所以"90 天 + 人工兜底"两年内就不是选项了。 期望状态生成器默认把单证书上限设成 25（与 tlsserver 对齐）， 就是为了将来切 profile 时不用改架构。':
        'The CA/Browser Forum has scheduled <strong>≤100 days from 2027-03-15</strong> and <strong>≤47 days from 2029-03-15</strong>, so “90 days plus a manual fallback” stops being an option within two years. The desired-state generator caps a certificate at <strong>25</strong> names by default (aligned with <code>tlsserver</code>) so that switching profiles later needs no redesign.',
    '东西':
        'Thing',
    '情况':
        'Situation',
    '限制':
        'Limit',
    '这一条推出来的直接结论：与旧证书完全不相交的域名集合就是一张全新证书，拿不到 ARI 豁免， 要花掉"每注册域 50 张 / 7 天"的额度（增删域名只要还共享至少一个 identifier，豁免就还在）。 所以"加一个域名"的成本必须被压到接近零，而唯一能做到这件事的手段就是通配符。 这也是为什么期望状态生成器宁可把"加子域"解释成"已被通配符覆盖，0 次签发"， 也不肯为它动 SAN 集合。':
        'That last row is what makes wildcard-first more than an optimisation: <strong>a domain set wholly disjoint from the old certificate is a brand-new certificate</strong>, which forfeits the ARI exemption and spends “Certificates per Registered Domain (50 / 7 days)” instead (adding or removing a domain keeps the exemption as long as at least one identifier is shared). The cost of “add one domain” therefore has to be driven to nearly zero, and a wildcard is the only way to do that. It is also why the desired-state generator prefers to report “covered by the declared wildcard, 0 issuances” over touching the SAN set.',
    'CLB 开了 SNI 就静默忽略主证书字段':
        'Enabling SNI on a CLB silently ignores the primary certificate field',
    '必须写 multi_cert_info。而且只有 CertificateDeployInstanceEmpty 这个错误码才会暴露它——否则你看到的是一切正常。':
        'You must write <code>multi_cert_info</code>. And only the <code>CertificateDeployInstanceEmpty</code> error code exposes it — otherwise everything looks fine.',
    'DescribeListeners 不回读证书绑定':
        '<code>DescribeListeners</code> does not read certificate bindings back',
    '可靠的独立信号是 UpdateCertificateInstance 返回里的 UpdateSyncProgress.TotalCount 和 CreateCertificateBindResourceSyncTask（后者也是 wecert 每轮用来确认"人工绑上没绑上"的手段）。 TotalCount 为 0 意味着证书其实没绑上。':
        'The reliable independent signals are <code>UpdateSyncProgress.TotalCount</code> in the <code>UpdateCertificateInstance</code> response and <code>CreateCertificateBindResourceSyncTask</code> — the latter is also what wecert uses on every pass to confirm a hand-bound certificate. A <code>TotalCount</code> of 0 means the certificate was never actually bound.',
    '绑定成功 ≠ 已经生效':
        'Uploading is not binding',
    '重绑定是异步的，实测约 15 秒，而且不是原子的。 deploy_confirmed 要等确认换完才置位，否则首次上传就会让 deployed 指标报绿，到期告警以为一切正常。':
        'The rebind is asynchronous — measured at about 15 seconds — and <strong>not atomic</strong>. <code>deploy_confirmed</code> is only set once the switch is confirmed; otherwise the first upload would turn the <code>deployed</code> gauge green and the expiry alarm would think everything is fine.',
    '绑定状态里 1 才是完成':
        'In the binding status, 1 is “done”',
    'CreateCertificateBindResourceSyncTask 的 Status 语义很容易猜反 （0 = done 是错的）。猜反的表现是"永远等不到完成"。':
        'The <code>Status</code> semantics of <code>CreateCertificateBindResourceSyncTask</code> are easy to guess backwards (<code>0 = done</code> is wrong). Guessing backwards looks like “the task never completes”.',
    'CSR 必须是 DER，而且要发到 finalize URL':
        'The CSR must be DER, and posted to the finalize URL',
    "传 PEM 会得到 asn1 tags don't match；发到 order URL 会得到 POST-as-GET requests must have an empty payload。 lego 的参数名恰好叫 orderURL，很容易踩。":
        'Sending PEM gets you asn1 <code>tags don’t match</code>; posting to the order URL gets you <code>POST-as-GET requests must have an empty payload</code>. lego’s parameter happens to be called <code>orderURL</code>, which makes it easy to hit.',
    'Terraform 会把 wecert 绑的证书改回去':
        'Terraform will revert the certificate wecert bound',
    'IaC 和运行时都在写同一个字段。解法是在 CLB 资源上加 lifecycle { ignore_changes = [multi_cert_info, certificate_id] }—— 代价是 TF state 会一直是旧的。':
        'Both IaC and the runtime write the same field. The fix is a <code>lifecycle { ignore_changes = [multi_cert_info, certificate_id] }</code> on the CLB resource — at the cost of TF state staying stale.',
    'DNSPod 免费套餐 TTL 下限是 600':
        'DNSPod’s free tier has a TTL floor of 600',
    '写 60 会被 LimitExceeded.RecordTtlLimit 拒绝。所以默认值就是 600。':
        'Writing 60 is rejected with <code>LimitExceeded.RecordTtlLimit</code>, so 600 is the default.',
    '传播检查不能用"全部权威 NS 可达"':
        'Propagation checking cannot require “every authoritative NS reachable”',
    '实测 9 个 NS 里总有 1 个不可达。判据是 quorum：没有可达的 NS 否认，且至少一台确认； 多台权威的 zone 还要求至少 2 台独立确认，只有一台权威的 zone 一台即可。':
        'In practice one of nine nameservers is always unreachable. The criterion is a quorum: no reachable nameserver denies it, and at least one confirms; with multiple authorities at least 2 must confirm independently, and a zone with a single authority passes on one.',
    'CLB 健康检查的源地址不在 VPC CIDR 里':
        'CLB health-check source addresses are not in the VPC CIDR',
    '表象是 504，但 TLS 握手其实正常——非常容易误判成证书问题。放宽安全组即可。':
        'It shows up as a 504 while the TLS handshake is actually fine — very easy to misdiagnose as a certificate problem. Widening the security group fixes it.',
    '打印 / 存为 PDF':
        'Print / save as PDF',
    '最后更新 2026-09-18 · 对应 v0.4.2 + 未发布改动':
        'last updated 2026-09-18 · for v0.4.2 + unreleased changes',
    'wecert · 证书生命周期架构图 源码 github.com/susunola/wecert':
        '<strong>wecert</strong> · certificate lifecycle<br/>\n      source <code>github.com/susunola/wecert</code>',
    '图 ⓪':
        'diagram ⓐ',
    '浏览器 / 客户端':
        'Browser / client',
    '只跑业务 · 明文 HTTP':
        'business only · plain HTTP',
    '明文 HTTP':
        'plain HTTP',
    '50 / 7 天':
        '50 / 7 days',
    '5 / 7 天':
        '5 / 7 days',
    '精确 identifier 集合':
        'the exact identifier set',
    '前提是同名续期':
        'but only for a <b>same-name renewal</b>',
    '图 ②':
        'diagram ②',
    '⓪ 部署形态':
        'ⓐ Deployment',
    '图 ⓪部署形态：免费证书在 CLB 上自动轮转':
        '<span class="num">diagram ⓐ</span>Deployment shape: a free certificate rotating itself on the CLB',
    '最上面那条带子是这套系统要解决的场景：免费证书只有 90 天，必须自动轮转； 以及为什么选 Let\'s Encrypt 而不是腾讯云自带的免费 DV —— 后者是单域名证书，既不支持 SAN 也不支持通配符， 域名一多就得为每个域名单独维护一条轮转，而 Let\'s Encrypt 一张证书能装 100 个名字、 还支持通配符，多个域名可以合成一张、只轮转一条。 下面两条是它落到腾讯云上的形态——上面是请求路径，下面是这张证书是怎么来的。 关键的一层关系在中间： SNI 决定 CLB 用哪张证书，证书的 SAN 决定它能对哪些域名完成握手 —— 所以多个域名共用一张证书时，它们是生死与共的。':
        'The band on top is the scenario this system exists for: <b>a free certificate is valid for 90 days, so it has to rotate automatically</b> — and why the choice falls on Let’s Encrypt rather than Tencent Cloud’s own free DV: <b>those are single-domain certificates, supporting neither SAN nor wildcard</b>, so every extra domain means another rotation to maintain. One Let’s Encrypt certificate holds up to 100 names and does support wildcards, so several domains combine into one certificate and rotate as one. The two bands below are what that scenario looks like on Tencent Cloud — the request path on top, and where the certificate comes from underneath. The relationship in the middle is the one that matters: <b>SNI decides which certificate the CLB uses, and that certificate’s SAN decides which domains it can complete a handshake for</b> — so domains sharing one certificate share its fate.',
    '为什么用 Let\'s Encrypt，而不是腾讯云自带的免费 DV':
        'Why Let’s Encrypt rather than Tencent Cloud’s own free DV',
    '腾讯云免费 DV':
        'Tencent Cloud free DV',
    '单域名 · 不支持 SAN · 不支持通配符':
        'one domain only · no SAN · no wildcard',
    '3 个域名 = 3 张证书 = 3 条轮转要维护':
        '3 domains = 3 certificates = 3 rotations to look after',
    '一张证书最多 100 个 SAN · 支持通配符':
        'up to 100 SANs in one certificate · wildcards supported',
    '3 个域名（含 *.example.com）= 1 张证书 = 1 条轮转':
        '3 domains (incl. *.example.com) = 1 certificate = 1 rotation',
    '场景 · 免费证书（Let\'s Encrypt）+ 自动轮转':
        'The scenario · a free certificate (Let’s Encrypt), rotating automatically',
    'Let\'s Encrypt 不收费，代价是有效期只有 90 天 —— 一年至少要轮 4 次，靠人记着做迟早会漏。':
        'Let’s Encrypt costs nothing; the price is a 90-day validity — at least four rotations a year, and a human remembering each one will eventually miss.',
    '免费签发':
        'Issued for free',
    '不花钱，但只有 90 天':
        'no cost, but only 90 days',
    '自动换绑':
        'Rebound automatically',
    '上传到腾讯云 SSL':
        'uploaded to Tencent Cloud SSL',
    '再绑定到 CLB 监听器':
        'then bound to the CLB listener',
    '线上服务':
        'Serving traffic',
    'SNI 按域名选证书':
        'SNI picks the certificate',
    '这张证书只剩 90 天':
        'only 90 days left on it',
    '到期前自动再签':
        'Reissued before expiry',
    'ARI 给出建议窗口':
        'ARI suggests the window',
    '全程无人值守':
        'nobody has to be involved',
    '到期前自动回到第 1 步':
        'before expiry, back to step 1 automatically',
    '请求路径 · SNI 选证书，证书的 SAN 决定它能服务哪些域名':
        'Request path · SNI picks the certificate, the certificate’s SAN decides which domains it can serve',
    'CLB · 监听器 443 · SNI 开启':
        'CLB · listener 443 · <b>SNI on</b>',
    '它按客户端给的 SNI 去 multi_cert_info 里挑证书':
        'it picks the certificate out of multi_cert_info using the SNI the client sent',
    '挂载的那一张证书':
        'The one certificate that is bound',
    '三个域名生死与共：一起成功、一起失败、一起过期':
        'these domains share their fate: they succeed, fail and expire together',
    '七层规则按域名分流到后端':
        'Layer-7 rules route by domain to the backend',
    'a.example.com → RS 组 A b.example.com → RS 组 B':
        'a.example.com → RS group A\u3000\u3000b.example.com → RS group B',
    '后端 RS 池':
        'Backend RS pool',
    '机器上没有证书文件，也不需要':
        'no certificate file on these machines, and none is needed',
    '控制面 · 这张证书是怎么来的（wecert 跑在其中一台 CVM 上）':
        'Control plane · where this certificate comes from (wecert runs on one of the CVMs)',
    '守护进程 · 一台 CVM':
        'daemon · one CVM',
    '1 · 读期望状态（只读） 2 · 决策：签发 / 重签 / 续期 3 · 写 _acme-challenge 4 · finalize 并下载证书 5 · 上传并换绑到 CLB':
        '1 · read the desired state (read-only)<br/>2 · decide: issue / reissue / renew<br/>3 · write _acme-challenge<br/>4 · finalize and download<br/>5 · upload and rebind to the CLB',
    '_wecert.* 声明 —— 意图来源':
        '_wecert.* declarations — where the intent comes from',
    '_acme-challenge —— DNS-01 挑战':
        '_acme-challenge — the DNS-01 challenge',
    'ACME · 下单 / finalize / 下载':
        'ACME · order / finalize / download',
    'ARI · 协调续期（豁免限速）':
        'ARI · coordinated renewal (exempt from rate limits)',
    '腾讯云 SSL 证书服务':
        'Tencent Cloud SSL',
    '上传证书（wecert/ 前缀）':
        'upload the certificate (wecert/ prefix)',
    'UpdateCertificateInstance 一键换绑':
        'UpdateCertificateInstance rebinds it',
    '换绑是异步的（实测约 15 秒）而且不是原子的':
        'The rebind is asynchronous (measured ~15s) and not atomic',
    '所以每一轮还要拨 443 读回对端实际出示的证书， 确认线上服务的确实是这一张 —— 控制面说成功不等于已经生效':
        'so every pass also dials 443 and reads back the certificate <b>actually served</b>, confirming that what is live really is this one — the control plane saying “done” is not the same as it being in effect',
    '上传证书':
        'upload',
    '换绑到监听器':
        'rebind to the listener',
    '这个形态里有一条容易忽略的因果：后端 RS 完全不参与 TLS —— 解密发生在 CLB，所以证书是一份云端资源，不是几个文件。 把 certbot 装在每台 RS 上拿不到任何好处，而 cert-manager 那类假设 "证书最终写进一个 Secret" 的工具，在这里也没有落点。':
        'One easily missed consequence of this shape: <strong>the backend RSs take no part in TLS at all</strong> — decryption happens at the CLB, so the certificate is a <strong>cloud resource</strong>, not a few files. Putting certbot on every RS buys nothing, and tools that assume “the certificate ends up in a Secret” have nowhere to land here.',
    '另一条是共用一张证书的域名生死与共。SNI 只决定"用哪一张"， 真正决定"能不能服务这个域名"的是那张证书的 SAN —— 所以 a 和 b 被放进同一张证书之后， a 的 DNS 出问题会拖着 b 一起签不出来。这就是为什么 分组策略、通配符优先、以及"到期前降级"都是围绕这个约束做的 （见 图 ② 和 表 B）。':
        'The other is that <strong>domains sharing one certificate share its fate</strong>. SNI only decides <em>which</em> certificate is used; what decides whether a domain can actually be served is that certificate’s SAN. So once <code>a</code> and <code>b</code> are in the same certificate, a DNS problem on <code>a</code> drags <code>b</code> down with it. That is the constraint the grouping policy, wildcard-first and the failure fallback are all built around (see <a href="#intent">diagram ②</a> and <a href="#failure">table B</a>).',
    '表 B':
        'table B',

    # 只出现在 aria-label 属性里的键（正文压平查不到它们，别被剪枝误删）
    'wecert 系统全景架构图':
        'wecert system map',
    'wecert-onboard 推断流水线':
        'the wecert-onboard inference pipeline',
    'wecert 每轮收敛的决策流程':
        "wecert's per-pass decision flow",
    'ACME 订单状态机':
        'the ACME order state machine',
    'DNS-01 通配符与顶点共用 TXT 的时序图':
        'DNS-01 sequence: a wildcard and its apex sharing one TXT',
    '证书生命周期时间线':
        'certificate lifetime timeline',
    "wecert 的部署形态：免费证书由 Let's Encrypt 自动轮转（免费签发 → 自动换绑 → 服务 90 天 → 到期前自动再签）；选它而不是腾讯云自带的免费 DV，是因为后者单域名、不支持 SAN 也不支持通配符。客户端经 SNI 到 CLB，一张多 SAN 证书分流到后端 RS 池":
        "wecert's deployment shape: a free certificate rotated automatically by Let's Encrypt (issued for free → rebound automatically → serving for 90 days → reissued before expiry); Let's Encrypt is chosen over Tencent Cloud's own free DV because the latter is single-domain and supports neither SAN nor wildcard. Clients reach the CLB over SNI and one multi-SAN certificate routes to a backend RS pool",
}
