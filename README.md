# RVScan - Burp Suite 扩展插件

RVScan 是一个功能强大的 Burp Suite 扩展插件，专为自动化Web应用程序安全测试和漏洞扫描而设计。它提供全面的路径发现、绕过技术、EHole指纹识别和可定制的扫描规则。

## 项目概述

这是一个基于Java的Burp Suite扩展插件，自动化执行隐藏路径发现、绕过技术测试、Web应用程序指纹识别和漏洞扫描。该扩展与Burp Suite的被动和主动扫描功能无缝集成。

## 核心功能

### 🔍 **自动化路径发现**
- 基于可配置规则的智能路径枚举
- 多线程扫描提升性能
- 去重机制避免冗余请求

### 🛡️ **高级绕过技术**
- **路径绕过**: URL编码和路径操作 (`%2f`, `%2e`)
- **前缀路径绕过**: CSS/JS目录遍历 (`css/..;/..;`, `..;`, `js/..;/..;`)
- **后缀路径绕过**: 文件扩展名操作 (`;.js`, `.json`, `.js`)

### 🎯 **EHole指纹识别系统**
- **EHole兼容**: 完全兼容EHole官方指纹格式
- **智能识别**: 自动识别CMS、框架、中间件和应用程序
- **多种匹配方式**: 支持body、header、title、faviconhash四种匹配位置
- **高级匹配逻辑**: 支持AND(&&)、OR(||)、正则表达式和否定匹配
- **Favicon哈希**: 基于MurmurHash3算法的favicon指纹识别
- **编码自适应**: 自动检测和处理中文编码（UTF-8、GBK、GB2312）
- **缓存优化**: 避免重复扫描，提升性能
- **独立控制**: 指纹扫描与漏洞扫描独立开关控制

### ⚙️ **灵活配置**
- 基于YAML的规则配置
- 从GitHub仓库在线更新规则
- 自定义线程池管理
- 支持通配符的主机过滤

### 🔎 **智能扫描模式**
- **被动扫描**: 自动扫描拦截的请求
- **右键菜单集成**: 从任何Burp工具右键扫描
- **强制扫描**: 完整路径扫描，无去重
- **域名扫描**: 全面的子域名分析

## EHole指纹识别功能详解

### 🎯 **功能特性**

#### **多维度指纹识别**
- **响应体匹配**: 识别HTML、JavaScript、CSS等内容特征
- **响应头匹配**: 检测Server、X-Powered-By等服务器信息
- **标题匹配**: 分析HTML页面标题的特征关键词
- **Favicon哈希**: 基于网站图标的唯一哈希值识别

#### **高级匹配算法**
- **关键词组合**: 支持多关键词AND逻辑，所有关键词必须同时匹配
- **正则表达式**: 使用`regex:`前缀支持复杂模式匹配
- **否定匹配**: 使用`!`前缀排除特定内容
- **状态码过滤**: 根据HTTP响应状态码精确匹配

#### **智能扫描策略**
- **路径扫描**: 对当前访问路径、根路径和配置路径进行指纹识别
- **缓存机制**: 每个URL只扫描一次，避免重复请求
- **编码处理**: 自动检测响应编码，正确处理中文内容
- **性能优化**: 静态资源自动跳过，专注于动态页面

### 📁 **配置文件和目录结构**

#### **主要配置文件**
```
RouteVulScan_kiro/
├── finger.json              # EHole指纹库文件
├── Config_yaml.yaml         # 主配置文件
├── src/main/java/
│   ├── fingerprint/         # 指纹识别模块
│   │   ├── FingerPrint.java       # 指纹数据结构
│   │   ├── FingerprintMatcher.java # 指纹匹配引擎
│   │   ├── FingerprintScanner.java # 指纹扫描器
│   │   ├── FingerprintLoader.java  # 指纹库加载器
│   │   └── FingerprintConfig.java  # 指纹配置界面
│   └── burp/                # 主扩展模块
└── build/libs/              # 编译输出目录
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
