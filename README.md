# Frida 动态分析工具

这是一个基于Frida的动态分析工具集，包含多种Hook脚本和批处理文件，用于Android应用程序的动态分析和逆向工程

## 📋 项目概述

本项目提供了完整的Frida动态分析解决方案，包括：
- TypeScript 编写的核心 Agent 脚本
- JavaScript Hook 脚本（Java 层和 Native 层）
- 批处理文件用于快速启动
- 完整的开发环境配置

## 🏗️ 项目结构

```
Frida/
├── agent/                # TypeScript 核心脚本
│   ├── index.ts          # 主入口文件
│   └── logger.ts         # 日志工具
├── js/                   # JavaScript Hook 脚本
│   ├── hook.js           # Java 层 Hook 脚本
│   └── hook_native.js    # Native 层 Hook 脚本
├── bat/                  # 批处理文件
│   ├── attach.bat        # 附加到运行中的应用
│   ├── spawn.bat         # 启动新应用实例
│   ├── attach_native.bat # 附加并 Hook Native 函数
│   └── spawn_native.bat  # 启动并 Hook Native 函数
├── _agent.js             # 编译后的 Agent 脚本
├── package.json          # 项目配置
└── tsconfig.json         # TypeScript 配置
```

## 🚀 快速开始

### 环境要求

- Node.js (推荐 v18+)
- Frida CLI 工具
- Android 设备或模拟器
- ADB 工具

## 📱 使用方法

### 1. Java 层 Hook

使用 `js/hook.js` 脚本 Hook Java 函数：

```
# 附加到运行中的应用
frida -D emulator-5554 -n ndkdemo -l js/hook.js

# 启动新应用实例
frida -D emulator-5554 -f com.example.ndkdemo -l js/hook.js
```

### 2. Native 层 Hook

使用 `js/hook_native.js` 脚本 Hook Native 函数：

```
# 附加到运行中的应用
frida -D emulator-5554 -n ndkdemo -l js/hook_native.js

# 启动新应用实例
frida -D emulator-5554 -f com.example.ndkdemo -l js/hook_native.js
```

### 3. 使用批处理文件

项目提供了批处理文件：

- `bat/attach.bat` - 附加到运行中的应用并执行 Java Hook
- `bat/spawn.bat` - 启动新应用实例并执行 Java Hook
- `bat/attach_native.bat` - 附加到运行中的应用并执行 Native Hook
- `bat/spawn_native.bat` - 启动新应用实例并执行 Native Hook

## 🔧 脚本说明

### Agent 脚本 (`agent/index.ts`)

核心 TypeScript 脚本，包含以下功能：
- 内存操作示例
- 模块导出函数枚举
- 系统调用 Hook（如 `open()` 函数）
- Java 虚拟机检测和操作

### Java Hook 脚本 (`js/hook.js`)

Hook Java 层函数的示例脚本：
- Hook `MainActivity.stringFromJNI()` 方法
- 打印输入参数和返回值
- 支持方法调用拦截

### Native Hook 脚本 (`js/hook_native.js`)

Hook Native 层函数的完整解决方案：
- 通过函数名查找导出函数
- 通过偏移量定位函数地址
- 完整的参数和返回值监控
- 支持多种定位方式

## 🛠️ 开发指南

### 添加新的Hook脚本

1. 在`js`目录下创建新的JavaScript文件
2. 参考现有脚本的结构
3. 使用`setImmediate()`确保脚本在Java环境准备好后执行

### 修改批处理文件

根据您的设备ID和包名修改`bat`目录下的批处理文件

```batch
# 修改设备ID和APP名称
frida -D YOUR_DEVICE_ID -n YOUR_APP_NAME -l ../js/hook.js

# 修改设备ID和包名
frida -D YOUR_DEVICE_ID -f YOUR_PACKAGE_NAME -l ../js/hook.js
```

## 🔍 故障排除

### 常见问题

1. **设备连接失败**
   - 确保 ADB 设备已连接
   - 检查设备 ID 是否正确

2. **应用未找到**
   - 确认应用包名正确
   - 确保应用已安装

3. **Hook 失败**
   - 检查函数名是否正确
   - 确认模块是否已加载

4. **webstorm控制台中文乱码**
   - 设置环境变量：PYTHONIOENCODING=UTF-8

### 调试技巧

- 使用 `console.log()` 输出调试信息
- 检查 Frida 控制台输出
- 验证函数地址是否正确

## 📄 许可证

本项目采用 Apache-2.0 许可证 - 详见 [LICENSE](LICENSE) 文件

## 🤝 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目！

---

**注意**: 请确保在使用本工具时遵守相关法律法规，仅用于合法的安全研究和学习目的。
