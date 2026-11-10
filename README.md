# GF2 单机服务端 · 战场问题修复记录与交接

本仓库记录一次针对 **NTRSimulator**（GF2 单机服务端）的排障过程：
从「进副本黑屏、返回 -1000001」一路做到「能进副本、能进战斗」，
并留下**卡住的最后一环**与完整证据，供原作者/后来者接手。

> 客户端文件全程未改动（仅用侧载 DLL 做过诊断，可随时删除）。

---

## 状态速览

| 项 | 状态 |
|---|---|
| 登录 / 大厅 / 各系统界面 | ✅ |
| 编队（6 槽位）与保存 | ✅ |
| 关卡解锁 | ✅ |
| **进副本** | ✅（关键修复见下） |
| 场景加载 / 敌方生成与行动 | ✅ |
| 部署面板列出人形 | ✅ |
| 点「作战开始」进入战斗 | ✅ |
| **己方单位出场** | ❌ 卡在这里 |
| 伤害数字 / 结算 | ⛔ 依赖上一项 |

---

## 三个关键修复（最值得合并）

### 1. 黑屏 `-1000001` — 回错了消息号

客户端 `CS_StageStart(10304)` 之后等的是 **`SC_StageStart(10305)`**，
里面带 `StageBattle stage = 2` 与 `StageOther other = 3`。

原实现回的是 `SC_StageReady(10316)`（只有一个 timestamp），
客户端拿不到战斗数据 → 本地初始化返回 `-1000001` → `ConnectClose` → 黑屏。

**实测**：回 10305、两个字段各给一个空子消息（payload `12 00 1A 00`）即可进副本。

### 2. 部署面板 `0/0`「暂无可选择人形」— handler 未实现

`CS_StageUsableGuns(10300) → SC_StageUsableGuns(10301)`

```protobuf
uint32 stage_id = 1;
repeated uint32 lineup = 2;           // 角色 id
map<uint32, Gun> lineup_guns = 3;     // 完整角色数据
```

必须用 `GunEntity.GunId`（配置角色 id）做 key；用数据库行号会导致全部匹配失败。

### 3. 点「作战开始」转圈 — handler 未实现

`CS_StageInto(10306) → SC_StageInto(10307)`，结构同 StageStart。

```protobuf
message CS_StageInto {
  map<uint32, uint32> guns = 2;    // key = 出生点 id, value = 角色 id
  repeated uint32 action_sequence = 5;
  ...
}
```

---

## 卡住的最后一环：己方单位不生成

已排除（均有实测）：

- `StageBattle` 只填 `formation_id / leader_id / predeployment_complated / need_sync_formation` → 我方不出现
- `camps` 只发玩家一侧（含 `Gun` / `sequence` / `uid=出生点 id` / 坐标字符串）→ 我方仍不出现
- `auto=false`、`stage_class`/`battle_type` 枚举 → 无变化
- `SC_StageStart` 里也带 camps → **敌方不再移动**（回归，已回滚）
- 「部署写回编队 + formation_id=1」→ 敌我都不动（回归，已回滚）

关键观测：

- 战斗为**纯客户端模拟**：`SC_StageInto` 后客户端只发 `10105 Sync` 心跳，无回合/操作包
- `camps` 非空时客户端似把它当「整个战场全部队伍」，只给一侧会破坏初始化
- `camps` 为空时客户端按 `StageConfigData.initial_enemies` 自行生成敌方（所以敌人能动）

建议验证方向：

1. `camps` 需**双方完整**：玩家 camp（`KGMEBGGOOAM=Player0` + `NFGCFGBGMCA`）
   ＋ 敌方 camp（`KGMEBGGOOAM=敌方阵营` + `FBDLKMOOECN(CFMHGIMNBNN)`）
   敌方数据来自 `StageConfigData.initial_enemies` / `enemy_groups` + `EnemyData`
2. `JPPLEFEAECH` 中 `OGEOEEBNDEP(2)` / `GCAABEBJHFL(3)` / `Type(20)` / `Other(21)` 含义待确认
3. 若有官方抓包，仓库根目录提到的 `PcapParser` 可直接对照 `SC_StageStart` / `SC_StageInto`

---

## 数据资料（对后来者最有用）

- `docs/数据摘录_10144.txt`：stage 10144（BH-1-4）的 StageData / StageConfigData /
  EnemyData / StageEnemyGroupData 实测数据
- `docs/修复记录_战斗与编队.txt`：33 轮完整实验记录（每轮都有实测结论）
- `docs/交接报告_战场修复_20261111.md`：完整技术报告
- `tools/`：侧载诊断 DLL 源码（抓解密 bundle / 全量内存快照 / 镜像 dump / 字符串搜索）

### 表文件格式（`Resources\Tables\*.bytes`）

```
[0..3]        4 字节 LE：header 长度 N
[4..4+N-1]    header（客户端懒加载索引）
[4+N..]       wrapper protobuf：field 1 重复行
```

### 关键 proto 片段

```protobuf
message StageBattle {
  int64 id=1; uint32 stc_stage_id=2; int64 random_seed=4; uint32 battle_level=5;
  FMMHAOHCKFN side=7; map<uint64,FMMHAOHCKFN> user_sides=8;
  repeated OPADLDPIIKL camps=9; BattleResult result=10; bool auto=11;
  bool predeployment_complated=16; uint32 leader_id=17;
  uint32 formation_id=21; bool need_sync_formation=22; bool is_pass=24;
}
message OPADLDPIIKL {
  FMMHAOHCKFN KGMEBGGOOAM=1;                 // 阵营
  repeated JPPLEFEAECH NFGCFGBGMCA=7;         // 上场单位
  repeated CFMHGIMNBNN FBDLKMOOECN=8;         // 疑似敌方单位
}
message JPPLEFEAECH {
  Gun JEKFJDDLGOO=1; uint32 OGEOEEBNDEP=2; string GCAABEBJHFL=3;
  uint32 sequence=24; uint64 uid=25; repeated uint32 buff_id=26;
}
```

---

## patches/

对上游仓库 6 个文件的 diff（**不含** `appsettings.json` 等本地配置）：

| 文件 | 内容 |
|---|---|
| `StageHandler.patch` | StageStart(10305) / StageInto(10307) / StageUsableGuns(10301) / StageRecord 全 type 应答 |
| `CustomFormationHandler.patch` | 6 编队默认 + `formations.json` 持久化 + 队伍查询辅助 |
| `Connection.patch` | 正常发送栈发任意包（协议诊断用）+ msgId 屏蔽开关 |
| `LobbyHandler.patch` / `AvgDuoHandler.patch` | 教学 / AVG 进度补齐 |
| `SDKController.patch` | SDK 资源反向代理修正（返回 byte[] 而非 Stream） |

应用方式：

```bash
git apply patches/StageHandler.patch
```

---

## 给原作者的话

主要收获就是一个「消息号错位」的坑：`SC_StageStart(10305)` 被误当成 `SC_StageReady(10316)`，
排查成本极高（回包内容怎么改都没用）。

最后一环（己方单位）我们没有打通，但把**能排除的都排除了**、把**数据结构都挖出来了**，
希望能帮你省掉重复试错。如果你手上有官方抓包，或者知道 `camps` 的完整构造方式，
前面几环的修复应该可以直接落地。
