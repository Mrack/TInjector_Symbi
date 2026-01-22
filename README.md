
## TInjector_Symbi
这是一个 Android 进程注入工具，用于向指定应用程序Spawn模式注入共享库.


## 示例
劫持Zygote实现App启动前注入so
![1](img/1.gif)

## 命令行语法
```
tinjector_symbi <package_name> <so_file_path>
```
## Features
* Zygote spawn模式
* 自动注入子进程
* Arm64-v8a

## 参数说明
- `<package_name>`：目标应用程序的包名（例如：com.example.app）
- `<so_file_path>`：要注入的共享库文件完整路径

## 使用示例
```
./tinjector_symbi com.example.app /data/local/tmp/libhook.so
```

## TODO
* SO模块的隐藏