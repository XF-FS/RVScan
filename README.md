# RVScan - Burp Suite 漏洞扫描与指纹识别扩展

一个功能强大的 Burp Suite 扩展，集成了被动扫描、指纹识别、路径绕过等多种安全测试功能。

## 有啥需求，有啥想法都可以在Issues中提出，一起共创下

**原项目（扫描功能参考）**: [RouteVulScan](https://github.com/F6JO/RouteVulScan)  
**指纹识别参考**: [EHole](https://github.com/EdgeSecurityTeam/EHole)

## ✨ 核心功能

- **🔍 被动扫描** - 自动检测敏感路径和接口通过对访问接口递归对每一层路径进行路径探测，探测是否存在敏感信息漏洞接口
  
  > 💡 访问/admin/auth/api，递归探测会访问/\*、/admin/\*、/admin/auth/\*、/admin/auth/api/\*
  
  > 💡 一般可探测出如Swagger接口、登陆后台、漏洞路径、配置文件、spring env等泄露信息
- **🎯 指纹识别** - 支持关键词、favicon hash等多种识别方法
  > 💡 通过识别访问接口是否存在指定指纹，判断指纹信息，功能参考Ehole
- **🚀 路径绕过** - 内置多种绕过技术和payload
- **⚡ 多线程扫描** - 可配置并发数和速率限制
- **📊 实时监控** - 扫描进度和结果实时显示

## 功能截图

**🔍 被动扫描** 

<img width="3336" height="1760" alt="image" src="https://github.com/user-attachments/assets/c7e33abf-9918-4ebd-bb40-8f5c23f58155" />

**🎯 指纹识别**

<img width="3320" height="1782" alt="image" src="https://github.com/user-attachments/assets/04249625-8d8b-4973-9ccb-e8909271e29f" />

**⚙️ 规则配置**

<img width="3200" height="1764" alt="PixPin_2025-07-24_14-35-54" src="https://github.com/user-attachments/assets/0836a113-adee-4da6-abac-510a80cb105d" />


## 📁 项目结构

```
src/main/java/
├── burp/           # Burp Suite 核心扩展
├── fingerprint/    # 指纹识别模块
├── func/           # 扫描功能实现
├── utils/          # 工具类和线程池管理
├── yaml/           # YAML 配置处理
└── UI/             # 用户界面组件
```

## 🚀 快速开始

### 1. 安装扩展

1. 编译项目生成JAR文件
2. 在Burp Suite中加载扩展
3. 扩展会自动创建配置文件（与burpsuite_pro.jar同目录）

如果首次加载报错可将配置文件放到指定位置（Config_yaml.yaml、finger.json）

MacOS：/Applications/Burp Suite Professional.app/Contents/Resources/app/

<img width="3110" height="1336" alt="PixPin_2025-07-25_22-52-41" src="https://github.com/user-attachments/assets/d02f5408-f6bc-44c5-942a-e3e37520363b" />

Windows：（BURP安装位置即burpsuite_pro.jar同级目录）\BurpSuitePro/Config_yaml.yaml/finger.json

<img width="3084" height="1508" alt="PixPin_2025-07-25_23-13-40" src="https://github.com/user-attachments/assets/e21f3fb3-ec57-4568-9d59-48a65004c878" />


### 2. 配置文件

扩展使用两个主要配置文件：

- **Config_yaml.yaml** - 扫描规则和绕过配置
- **finger.json** - 指纹识别规则

## ⚙️ 配置说明

### 扫描规则配置 (Config_yaml.yaml)

<img width="3200" height="1764" alt="PixPin_2025-07-24_14-35-54" src="https://github.com/user-attachments/assets/0836a113-adee-4da6-abac-510a80cb105d" />

```yaml
Load_List:
  - loaded: true          # 是否启用
    name: "login_check"    # 规则名称
    method: GET            # 请求方法
    url: /login            # 目标路径
    state: "200"           # 期望状态码
    body: ""               # POST请求体
    info: "登录页面检测"    # 规则描述
```

### 路径绕过配置(Config_yaml.yaml)

<img width="3360" height="1868" alt="59ed3658084116c08a3c75248a202e96" src="https://github.com/user-attachments/assets/834206cc-5a86-4f72-8d03-3ba766f67bf8" />


```yaml
# URL编码绕过
Bypass_List: ["%2f", "%2e"]

# 前缀绕过（目录遍历）
Bypass_First_List: ["..;/", "css/..;/..;"]

# 后缀绕过（文件扩展名）
Bypass_End_List: [".js", ".json", ";.js"]

# 指纹识别路径
Fingerprint_Paths: ["/", "/console", "/admin"]

# 被动扫描结果过滤
Result_Filter_List: [认证失败, 访问失败, 权限不足, Access Denied, Authentication Failed, Unauthorized]
```

### 指纹识别配置 (finger.json)

<img width="3200" height="1764" alt="PixPin_2025-07-24_14-35-15" src="https://github.com/user-attachments/assets/7d72a322-4c44-499b-a6f2-13b996a584b9" />

```json
{
  "fingerprint": [
    {
      "cms": "WordPress",
      "method": "keyword",
      "location": "body",
      "keyword": ["wp-content", "wp-includes"],
      "status": 0
    },
    {
      "cms": "Apache",
      "method": "faviconhash",
      "location": "body", 
      "keyword": ["-386189083"],
      "status": 0
    }
  ]
}
```

## 🎛️ 功能控制面板

<img width="3200" height="1770" alt="PixPin_2025-07-24_14-45-26" src="https://github.com/user-attachments/assets/1f2801ab-96e9-4315-83ec-c418d592636e" />

扩展提供8个主要功能开关：

> 💡 **提示**: 绿色按钮表示功能已启用，默认颜色表示功能已禁用

| 开关 | 功能 | 启用状态 | 禁用状态 |
|------|------|----------|----------|
| **Stop/Start** | 主扫描开关 | Stop (绿色) | Start (默认) |
| **Head_On/Off** | 携带原始头部 | Head_Off (绿色) | Head_On (默认) |
| **DomainScan** | 域名扫描 | DomainScan_Off (绿色) | DomainScan_On (默认) |
| **Bypass** | URL编码绕过 | Bypass_Off (绿色) | Bypass_On (默认) |
| **Bypass_First** | 前缀绕过 | Bypass_First_Off (绿色) | Bypass_First_On (默认) |
| **Bypass_End** | 后缀绕过 | Bypass_End_Off (绿色) | Bypass_End_On (默认) |
| **EHole** | 指纹识别 | EHole_Off (绿色) | EHole_On (默认) |
| **Thread Status** | 查看线程状态 | - | - |



## 📊 使用方法

### 被动扫描
1. 启用主扫描开关 (Stop)
2. 配置线程数和速率限制
3. 设置主机过滤规则
4. 正常浏览目标网站，扩展会自动进行被动扫描

### 指纹识别
1. 确保EHole开关已启用 (EHole_Off)
2. 访问目标网站，扩展会自动识别CMS/框架
3. 在"指纹识别"标签页查看结果

### 主动扫描
1. 右键点击请求 → "Send To RVScan"
2. 选择是否携带自定义头部
3. 使用"Force Scan All Paths"进行强制扫描

## 🔧 高级功能

### 线程池管理
- 可配置线程数 (1-500)
- 实时监控线程状态

### 路径绕过技术
- **URL编码**: `%2f` → `/`, `%2e` → `.`
- **目录遍历**: `..;/`, `css/..;/..;`
- **文件扩展名**: `.js`, `.json`, `;.js`

### 指纹识别方法
- **关键词匹配**: 在title/body/header中搜索特征字符串
- **Favicon Hash**: 基于网站图标的哈希值识别
- **状态码匹配**: 结合HTTP状态码进行精确识别

## 🛠️ 开发构建

### 环境要求
- Java 8+
- Gradle 5.2+
- Burp Suite Professional

### 构建命令
```bash
# 编译项目
./gradlew build

# 生成Shadow JAR
./gradlew shadowJar
```

### 依赖库
- Burp Extender API 1.7.13
- SnakeYAML 1.28
- Jackson 2.13.0
- Apache Commons Collections 4.4

## 📝 注意事项

⚠️ **重要提醒**:
- 仅在授权的测试环境中使用
- 大量并发请求可能影响目标系统性能
- 建议人工验证扫描结果，避免误报
- 定期备份自定义配置文件

## 📄 许可证

本项目基于原项目进行开发和改进，请遵守相关开源协议。

## 开心值


[![Star History Chart](https://api.star-history.com/svg?repos=XF-FS/RVScan&type=Date)](https://star-history.com/?utm_source=bestxtools.com#XF-FS/RVScan&Date)

