# eBPF-based Container Runtime Solution
 
## Introduction

This project aims to develop a high-performance and secure container runtime solution using eBPF. By leveraging the flexibility and performance of eBPF, it enhances container security and optimizes performance.

## Convention

### 🤝 Naming Rule

- **Function and Variable Names**: `snake_case`  
  (e.g., `int check_event()`)
- **Struct and Enum Names**: `PascalCase`  
  (e.g., `struct ProcInfo`, `enum EventType`)
- **Macro Constants**: `UPPER_SNAKE_CASE`  
  (e.g., `#define MAX_BUFFER_SIZE 1024`)
- **File Names**: `snake_case.c`, `snake_case.h`  
  (e.g., `main.c`, `proc_monitor.h`)
- **Folder Names**: `snake_case`  
  (e.g., `src/`, `include/`)
- **Parameter Names**: `snake_case`  
  (e.g., `int monitor_event(int event_type)`)
- **Event Handler Functions**: `handle_` + event name  
  (e.g., `void handle_open_event()`)

### 🤝 Branch Naming Convention

| Prefix    | Description                              |
|-----------|------------------------------------------|
| `main`    | Stable version for production deployment |
| `feat`    | Branch for new feature development (`feat/feature-name`) |
| `hotfix`  | Branch for urgent bug fixes (`hotfix/issue-name`) |

### 🤝 Commit Convention

| Prefix      | Description                                            |
|-------------|--------------------------------------------------------|
| `feat:`     | Add new features                                       |
| `fix:`      | Bug fixes and functionality improvements               |
| `refact:`   | Code refactoring                                       |
| `docs:`     | Documentation updates                                  |
| `style:`    | Code style changes (formatting, missing semicolons, etc.) |
| `test:`     | Add or modify test cases                               |
| `chore:`    | Miscellaneous tasks (e.g., build scripts, package settings) |