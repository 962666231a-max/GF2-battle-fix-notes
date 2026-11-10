> 中文说明。**不完美**，但都是实测过的结论，先把最关键的"消息号错位"和几个缺失 handler 补上。

## 这个 PR 修了什么

### 1. 进副本黑屏（`-1000001`）——回错消息号 ★ 最关键

客户端 `CS_StageStart(10304)` 之后等的是 **`SC_StageStart(10305)`**：

```protobuf
message SC_StageStart { StageBattle stage = 2; StageOther other = 3; }
```

原实现回的是 `SC_StageReady(10316)`（只有 timestamp）。客户端拿不到战斗数据，在本地初始化处返回 `-1000001`（客户端错误码表 `IOJGLBFCNMO.CHIICDKCGPP = 1000001u` 取负），随后 `ReceiveError → ConnectClose` → 黑屏。

**实测**：回 10305、两个字段各给一个空子消息（payload `12 00 1A 00`）即可正常进入副本。

这个坑排查成本极高：之前一直尝试改 `SC_StageReady` 的字段（时间戳 / 0 / 空包 / 全字段置 0），现象完全一样。

### 2. 部署面板 `0/0`「暂无可选择人形」

`CS_StageUsableGuns(10300) → SC_StageUsableGuns(10301)` 未实现。

```protobuf
uint32 stage_id = 1;
repeated uint32 lineup = 2;           // 角色 id 列表
map<uint32, Gun> lineup_guns = 3;     // 完整角色数据
```

注意：必须用 `GunEntity.GunId`（配置角色 id）做 key，用数据库行号会导致全部匹配失败、lineup 为空（客户端会退化成显示全部角色）。

### 3. 点「作战开始」一直转圈

`CS_StageInto(10306) → SC_StageInto(10307)` 未实现（抛 `NotImplementedException`）。

```protobuf
message CS_StageInto {
  map<uint32, uint32> guns = 2;    // key = 出生点 id, value = 角色 id
  repeated uint32 action_sequence = 5;
  ...
}
```

### 4. `SC_StageRecord` 必须对所有 type 应答

客户端一次会话会按 24 个不同 type 询问关卡记录（11,12,13,14,20,21,22,26,31,32,33,36,41,50,54,59,61,63,64…）。原来只实现 11~14，其余无回包 → 客户端静默等待。现在未实现的 type 统一回空包。

### 5. 编队：槽位上限与持久化

- 客户端 UI 只支持 **6** 个编队槽位；下发超过 6 条会导致【编队】整页空白
- 编队原来只存内存，重启丢失（每次登录弹编队教程）→ 现在落盘 `formations.json`（Google.Protobuf JsonFormatter）
- 注意：`formations.json` 必须写成对象 `{ "1": { ... } }`，写成 JSON 字符串会在读回时报 `Expected an object`

### 6. 商店购买：`HandleStoreBuy` 实现

`CS_StoreBuy(10502) → SC_StoreBuy(10503)` 原来未实现。现在按 `StoreGoodData.reward`（形如 `"10:60;"`）发放道具/时装，并回 `SC_StoreBuy{code=Normal}`。

### 7. IndexHandler 重复 key 崩溃修复

拥有列表用 `Details.Add(...)` 写入，遇到重复时装会抛 `Key already exists in map` → 改用索引器赋值。

## 已知没解决的问题（本 PR 不包含）

- **真钱时装购买**：客户端点购买走内嵌支付 SDK（`POST /alipay/create_order_qr`），需要官方令牌，单机无法伪造回调；客户端商城界面也不会因服务端推送而刷新。要解决必须改客户端。
- **副本里己方单位不出场**：`SC_StageStart/Into` 的 `StageBattle.camps` 需要完整战场编制（我方 + 敌方），目前只填了基础字段；己方单位仍不生成（敌方会正常行动）。
- 本 PR 未包含任何本地调试代码 / GM 命令 / 支付探测逻辑。

## 验证情况

- 6 个文件，编译通过（`dotnet build NTRSimulator/NTRSimulator.csproj -c Release`）
- 进副本、部署面板、作战开始、编队保存、StageRecord 全 type 应答：均在 4.0.5136 客户端上实测
- 商店购买：服务端能按表发货（数据库验证），但客户端界面刷新问题未解决

## 相关记录

完整实验记录（37 轮，含每轮实测数据与失败结论）：
https://github.com/962666231a-max/GF2-battle-fix-notes
