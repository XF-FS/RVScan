# Burp Suite 漏洞扫描与指纹识别扩展

一个功能强大的 Burp Suite 扩展，集成了被动扫描、指纹识别、路径绕过等多种安全测试功能。

原项目：https://github.com/F6JO/RouteVulScan

参考：https://github.com/EdgeSecurityTeam/EHole

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

如果需要手动管理配置文件，可以：

1. 查看当前配置路径
扩展启动时会在 Burp Suite 输出面板显示配置路径信息，默认位置同burpsuite_pro.jar文件同目录。

2. 复制配置文件
将项目根目录下的 `Config_yaml.yaml` 和 `finger.json` 复制到对应的配置目录。

## 功能介绍

### 指纹扫描功能

通过识别finger.json中的规则，对当前访问路径、和Fingerprint_Paths: ["/", "/console"]中的路径进行指纹识别，如果识别成功展示相关指纹信息

<img width="3200" height="1762" alt="PixPin_2025-07-24_14-40-07" src="https://github.com/user-attachments/assets/7d6f865f-dd6d-41ff-9ba5-b4ebd466cc40" />

### 被动敏感信息扫描
<img width="2952" height="884" alt="PixPin_2025-07-24_14-44-23" src="https://github.com/user-attachments/assets/feb9509b-265d-4331-b541-6fb3fcc2cdc4" />



### 1. 被动扫描规则配置 (`Config_yaml.yaml`)
<img width="3200" height="1764" alt="PixPin_2025-07-24_14-35-54" src="https://github.com/user-attachments/assets/0836a113-adee-4da6-abac-510a80cb105d" />


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

### 2. 路径配置说明
<img width="3200" height="1766" alt="PixPin_2025-07-24_14-37-19" src="https://github.com/user-attachments/assets/423e230d-cc89-4e1a-905a-3ad1cc9f8002" />


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

### 3. 指纹识别规则配置 (`finger.json`)
<img width="3200" height="1764" alt="PixPin_2025-07-24_14-35-15" src="https://github.com/user-attachments/assets/7d72a322-4c44-499b-a6f2-13b996a584b9" />


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
<img width="3200" height="1770" alt="PixPin_2025-07-24_14-45-26" src="https://github.com/user-attachments/assets/1f2801ab-96e9-4315-83ec-c418d592636e" />

扩展界面提供了9个主要功能开关，用于控制不同的扫描和检测功能：

### 1. 主扫描开关 (Stop/Start)
- **功能**: 控制整个扫描引擎的启停
- **状态**: 
  - `Stop` (绿色): 扫描引擎运行中，会对通过的HTTP请求进行被动扫描
  - `Start` (默认色): 扫描引擎已停止，不进行任何扫描
- **用途**: 临时暂停或启动所有扫描功能

### 2. 携带头部开关 (Head_On/Head_Off)
- **功能**: 控制是否在扫描请求中携带原始HTTP头部
- **状态**:
  - `Head_Off` (绿色): 启用，扫描请求会携带原始请求的头部信息
  - `Head_On` (默认色): 禁用，扫描请求使用默认头部
- **用途**: 绕过基于请求头的访问控制或身份验证

### 3. 域名扫描开关 (DomainScan_On/DomainScan_Off)
- **功能**: 控制是否对相同域名下的其他路径进行扫描
- **状态**:
  - `DomainScan_Off` (绿色): 启用域名扫描，会扫描同域名下的其他路径
  - `DomainScan_On` (默认色): 禁用域名扫描，只扫描当前路径
- **用途**: 扩大扫描范围，发现同域名下的其他漏洞点

### 4. 路径绕过开关 (Bypass_On/Bypass_Off)
- **功能**: 控制是否使用URL编码等技术绕过路径过滤
- **状态**:
  - `Bypass_Off` (绿色): 启用路径绕过，使用 `Bypass_List` 中的编码字符
  - `Bypass_On` (默认色): 禁用路径绕过
- **用途**: 绕过WAF或应用层的路径过滤机制

### 5. 前缀绕过开关 (Bypass_First_On/Bypass_First_Off)
- **功能**: 控制是否在路径前添加绕过前缀
- **状态**:
  - `Bypass_First_Off` (绿色): 启用前缀绕过，使用 `Bypass_First_List` 中的前缀
  - `Bypass_First_On` (默认色): 禁用前缀绕过
- **用途**: 使用目录遍历和路径混淆技术绕过访问控制

### 6. 后缀绕过开关 (Bypass_End_On/Bypass_End_Off)
- **功能**: 控制是否在路径后添加文件扩展名绕过
- **状态**:
  - `Bypass_End_Off` (绿色): 启用后缀绕过，使用 `Bypass_End_List` 中的扩展名
  - `Bypass_End_On` (默认色): 禁用后缀绕过
- **用途**: 通过添加文件扩展名绕过基于扩展名的过滤

### 7. EHole指纹扫描开关 (EHole_On/EHole_Off)
- **功能**: 控制指纹识别功能的启停
- **状态**:
  - `EHole_Off` (绿色): 启用指纹扫描，会对目标进行CMS/框架识别
  - `EHole_On` (默认色): 禁用指纹扫描
- **用途**: 识别目标使用的CMS、框架或应用类型
- **默认**: 初始状态为启用

### 8. 线程状态查看 (Thread Status)
- **功能**: 查看当前线程池和速率限制的状态信息
- **用途**: 
  - 显示活跃线程数、队列任务数
  - 显示速率限制配置和当前请求频率
  - 帮助调试性能问题

### 9. 速率限制开关 (RateLimit_On/RateLimit_Off)
- **功能**: 控制请求速率限制功能
- **状态**:
  - `RateLimit_On` (绿色): 启用速率限制，严格控制每秒请求数
  - `RateLimit_Off` (默认色): 禁用速率限制，最大化扫描速度
- **用途**: 避免对目标服务器造成过大压力，防止被WAF封禁
- **默认**: 初始状态为启用


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
