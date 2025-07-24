# Burp Suite 漏洞扫描与指纹识别扩展

一个功能强大的 Burp Suite 扩展，集成了被动扫描、指纹识别、路径绕过等多种安全测试功能。

## 🚀 主要特性

- **被动扫描规则配置** - 支持自定义扫描规则，包括 GET/POST 请求模板
- **指纹识别系统** - 支持多种指纹识别方法（关键词、favicon hash等）
- **路径绕过检测** - 内置多种绕过技术和payload
- **多线程扫描** - 支持并发扫描，提高效率
- **速率限制** - 可配置的请求频率控制
- **实时监控** - 扫描进度和结果实时显示

## 📁 项目结构

```
src/main/java/
├── burp/                    # Burp Suite 核心扩展
├── fingerprint/             # 指纹识别模块
├── func/                    # 扫描功能实现
├── utils/                   # 工具类
└── yaml/                    # YAML 配置处理
```

## ⚙️ 配置文件说明

### 1. 被动扫描规则配置 (`Config_yaml.yaml`)

#### Load_List - 扫描规则配置

每个扫描规则包含以下字段：

```yaml
Load_List:
  - loaded: true              # 是否启用该规则
    re: test1                 # 规则标识符
    method: GET               # 请求方法 (GET/POST)
    name: test1               # 规则名称
    id: 1                     # 唯一ID
    state: "200"              # 期望的HTTP状态码
    type: default             # 规则类型
    body: ""                  # POST请求体（GET请求为空）
    url: /aaa                 # 目标路径
    info: test1               # 规则描述信息
```

**字段说明：**
- `loaded`: `true`启用规则，`false`禁用规则
- `method`: 支持 `GET` 和 `POST` 方法
- `state`: 匹配的HTTP状态码，如 "200", "404", "500"
- `body`: POST请求的JSON payload，支持复杂的认证数据

#### 路径绕过配置

```yaml
# 路径结尾绕过列表
Bypass_End_List: [;.js, .json, .js]

# URL编码绕过列表  
Bypass_List: ["%2f", "%2e"]

# 路径前缀绕过列表
Bypass_First_List: [css/..;/..;, ..;, js/..;/..;]
```

**绕过技术说明：**
- `Bypass_End_List`: 在路径末尾添加文件扩展名绕过
- `Bypass_List`: 使用URL编码字符绕过过滤
- `Bypass_First_List`: 使用目录遍历和路径混淆绕过

#### 指纹扫描路径

```yaml
Fingerprint_Paths: ["/", "/console"]
```

指定进行指纹识别的默认路径列表。

### 2. 指纹识别规则配置 (`finger.json`)

#### 指纹规则结构

```json
{
  "fingerprint": [
    {
      "cms": "test_title",           # CMS/应用名称
      "method": "keyword",           # 识别方法
      "location": "title",           # 匹配位置
      "keyword": ["网动统一通信平台"], # 关键词列表
      "status": 0                    # HTTP状态码（0表示任意）
    }
  ]
}
```

#### 支持的识别方法

1. **关键词匹配 (`keyword`)**
   ```json
   {
     "method": "keyword",
     "location": "body",           # body/title/header
     "keyword": ["Kibana"],
     "status": 0
   }
   ```

2. **Favicon Hash (`faviconhash`)**
   ```json
   {
     "method": "faviconhash", 
     "location": "body",
     "keyword": ["-386189083"],    # favicon的hash值
     "status": 0
   }
   ```

#### 匹配位置说明

- `title`: 匹配HTML页面标题
- `body`: 匹配响应体内容
- `header`: 匹配HTTP响应头

#### 状态码配置

- `0`: 接受任何HTTP状态码
- `200`: 仅匹配200状态码
- `404`: 仅匹配404状态码
- 其他: 匹配指定状态码

## 🔧 功能开关说明

### 扫描规则开关

在 `Config_yaml.yaml` 中通过 `loaded` 字段控制：

```yaml
# 启用规则
- loaded: true
  name: active_rule
  
# 禁用规则  
- loaded: false
  name: disabled_rule
```

**效果：**
- `loaded: true`: 规则参与扫描，会发送对应的HTTP请求
- `loaded: false`: 规则被跳过，不会执行该扫描项

### 速率限制控制

通过 `RateLimiter.java` 控制请求频率：

```java
// 启用速率限制
rateLimiter.setEnabled(true);

// 禁用速率限制  
rateLimiter.setEnabled(false);
```

**效果：**
- 启用：严格控制每秒请求数，避免目标服务器过载
- 禁用：不限制请求频率，最大化扫描速度

### 线程池配置

通过 `ThreadPoolManager.java` 控制并发：

```java
// 设置线程池大小
ThreadPoolManager.getInstance().setCorePoolSize(10);
ThreadPoolManager.getInstance().setMaxPoolSize(20);
```

**效果：**
- 较小值：降低并发，减少资源消耗
- 较大值：提高并发，加快扫描速度

## 📊 使用方法

### 1. 加载扫描规则

扩展会自动加载 `Config_yaml.yaml` 中的扫描规则。可以通过UI界面：
- 启用/禁用特定规则
- 修改规则参数
- 添加新的扫描规则

### 2. 配置指纹识别

指纹规则支持多种加载方式：
- 从 `finger.json` 文件加载
- 从在线源更新指纹库
- 手动添加自定义指纹

### 3. 执行扫描

- **被动扫描**: 自动对通过Burp的请求进行扫描
- **主动扫描**: 手动触发对特定目标的扫描
- **指纹识别**: 对目标进行CMS/框架识别

### 4. 查看结果

扫描结果会在Burp Suite的扩展标签页中显示：
- 漏洞发现列表
- 指纹识别结果
- 扫描进度和统计

## 🛠️ 高级配置

### 自定义绕过Payload

在 `Config_yaml.yaml` 中添加新的绕过技术：

```yaml
# 添加新的路径绕过方法
Bypass_First_List: 
  - "admin/..;/"
  - "api/../"
  - "static/../../"
```

### 扩展指纹库

在 `finger.json` 中添加新的指纹规则：

```json
{
  "cms": "Custom_App",
  "method": "keyword", 
  "location": "body",
  "keyword": ["custom-app-signature", "version-1.0"],
  "status": 200
}
```

## 📝 注意事项

1. **合规使用**: 仅在授权的测试环境中使用
2. **性能影响**: 大量并发请求可能影响目标系统性能
3. **误报处理**: 建议人工验证扫描结果
4. **配置备份**: 定期备份自定义的配置文件

## 🔍 故障排除

### 常见问题

1. **扫描规则不生效**
   - 检查 `loaded` 字段是否为 `true`
   - 验证YAML语法是否正确

2. **指纹识别失败**
   - 确认 `finger.json` 格式正确
   - 检查关键词是否准确

3. **请求频率过高**
   - 启用速率限制功能
   - 调整线程池大小

### 日志查看

扩展会在Burp Suite的输出面板显示详细日志：
- `[Fingerprint]`: 指纹识别相关日志
- `[Scanner]`: 扫描进程日志
- `[Error]`: 错误信息

---

**开发团队**: 安全研究团队  
**版本**: 1.0  
**更新时间**: 2024年