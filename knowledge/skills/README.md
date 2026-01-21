# 代码审查技能库 (Code Review Skills)

本目录包含按编程语言分类的代码审查技能，每个技能专注于特定的审查维度。

## 目录结构

```
knowledge/skills/
├── README.md                    # 本说明文档
├── common/                      # 通用技能（适用于所有语言）
│   ├── architecture-consistency/
│   ├── performance-review/
│   ├── secure-code-review/
│   ├── style-and-consistency/
│   └── test-coverage-review/
├── java/                        # Java特有技能
├── python/                      # Python特有技能
├── javascript/                  # JavaScript特有技能
├── go/                          # Go特有技能
├── rust/                        # Rust特有技能
└── cpp/                         # C++特有技能
```

## 技能分类体系

### 1. 通用技能 (Common Skills)
适用于所有编程语言的基础审查维度：
- **架构一致性**: 分层约束、模块边界、依赖倒置
- **性能审查**: N+1查询、缓存、IO、并发
- **安全审查**: 输入验证、认证授权、敏感信息
- **风格一致性**: 命名、接口契约、可读性
- **测试覆盖**: 单测/集成测试、边界条件

### 2. 语言特有技能 (Language-Specific Skills)
针对特定语言的深度审查规则：

#### Java Skills
- **JVM性能优化**: 内存管理、GC调优、并发模型
- **Spring最佳实践**: 依赖注入、事务管理、REST设计
- **Java安全**: 反序列化、JNDI注入、XXE防护
- **Maven/Gradle**: 依赖管理、版本冲突、构建优化

#### Python Skills
- **Pythonic代码**: 列表推导、生成器、上下文管理器
- **Django/Flask**: ORM使用、中间件、模板安全
- **性能优化**: GIL影响、异步IO、内存分析
- **包管理**: requirements.txt、虚拟环境、版本冲突

#### JavaScript Skills
- **ES6+特性**: async/await、解构、模块化
- **Node.js**: 事件循环、流处理、内存泄漏
- **前端安全**: XSS防护、CSRF、内容安全策略
- **框架特定**: React/Vue/Angular最佳实践

#### Go Skills
- **并发模式**: goroutine、channel、context使用
- **错误处理**: error包装、panic/recover模式
- **性能调优**: pprof、竞态检测、内存分配
- **模块管理**: go.mod、依赖版本、兼容性

#### Rust Skills
- **所有权系统**: 借用检查、生命周期管理
- **并发安全**: Send/Sync trait、无锁编程
- **错误处理**: Result类型、?运算符、自定义错误
- **性能优化**: 零成本抽象、内联、SIMD

#### C++ Skills
- **内存管理**: RAII、智能指针、内存泄漏
- **并发编程**: 线程安全、原子操作、锁策略
- **现代C++**: C++11/14/17/20特性使用
- **性能优化**: 移动语义、内联、缓存友好

## 使用指南

### 技能激活规则
1. **文件扩展名检测**: 根据代码文件扩展名自动激活对应语言的技能
2. **框架检测**: 通过项目配置文件识别框架并激活相关技能
3. **混合项目**: 支持多语言项目中激活多个技能集

### 技能优先级
1. 语言特有规则 > 通用规则
2. 框架特定规则 > 语言通用规则
3. 项目自定义规则 > 内置规则

### 扩展机制
- 支持自定义技能文件
- 支持技能继承和组合
- 支持项目特定规则覆盖

## 技能文件格式

每个技能目录包含：
```
skill-name/
├── SKILL.md          # 技能定义和检查清单
├── examples/         # 正反面示例
├── rules/            # 具体规则定义
└── tests/            # 测试用例
```

### SKILL.md模板
```yaml
---
name: skill-name
version: 1.0.0
description: 技能描述
language: java/python/javascript/go/rust/cpp/common
tags: [tag1, tag2, tag3]
frameworks: [spring, django, react]  # 可选
---

# Skill Name

## 重点检查项（Checklist）
- 检查项1
- 检查项2
- 检查项3

## 代码示例
### 正面示例
```java
// 好的示例代码
```

### 反面示例
```java
// 坏的示例代码
```

## 自动修复建议
- 建议1
- 建议2
