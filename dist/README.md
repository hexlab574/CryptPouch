# 分发包（发行分支）

这个分支只做一件事：把编译好的成品放进仓库，方便直接下载。代码与上一版一致（本分支从 `main` 的 `6b9cbb0` 拉出，未改动任何源码）。

| 产物 | 文件 | 体积 | 说明 |
| --- | --- | --- | --- |
| Windows 免安装包（最新） | `dist/windows/CryptPouch-2.13.0-win-x64-visual4.zip` | 96.04 MiB | 解压即用，自包含 .NET 9 运行时，不写注册表、不需要管理员权限；新增启动 β 公告（中英 + "不再提醒"），Android 端产物自动导出到 `Download/CryptPouch/` 的逻辑随包分发（桌面端不显示这两个入口） |
| Android APK（第 3 版） | `dist/android/CryptPouch-2.13.0-release-visual3.apk` | 38.37 MiB | 系统文件夹导入（SAF）+ "保存到手机"；SdkOnly 裁剪 + Profiled AOT，`arm64-v8a` + `x86_64` 双 ABI，同签名可覆盖安装 |

## 校验值

```
SHA256  CryptPouch-2.13.0-win-x64-visual4.zip
DAF501EB390C2C978B53943F744CECDF86608B9DECAC0AB3EDB0D76BFDF3CC19

SHA256  CryptPouch-2.13.0-release-visual3.apk
FD859636028953370299C38B09471E91C226AFB0F997A47FC95FB8295DD6B1F7
```

同一份清单也放在 `dist/SHA256SUMS.txt`，可直接 `sha256sum -c` / `Get-FileHash` 核对。

## Windows

解压 `CryptPouch-2.13.0-win-x64-visual4.zip` 后运行 `CryptPouch.App.exe`。首次启动会弹 β 公告，勾选"不再提醒"并点"知道了"后不再出现（写在应用的 `ui-state.json`）。
解压后的目录为 640 个文件 / 245.3 MiB，这里只提交压缩包，避免把 640 个文件塞进 Git 历史。

## Android

```
adb install -r dist/android/CryptPouch-2.13.0-release-visual3.apk
```

或直接把 APK 传到手机点击安装。签名证书：`CN=CryptPouch, OU=HexLab, O=HexLab, C=CN`，SHA-256 指纹
`d0d88d62 0be2b3ba 8f61967d 8fe0a6f5 f7fb59da 135bcdd6 6d2842d6 56cda5e4`，
与本仓库此前发布的 APK 同证书，可直接覆盖安装。

包信息：`com.hexlab.cryptpouch`、versionCode 21300、versionName 2.13.0、minSdk 24、targetSdk 35。

## 版本说明

- Windows 端是 `visual4`：相对 `visual3` 增加了启动 β 公告；输出路径填目录、分段控件等修复都在。
- Android 端选 `visual3`：`visual4` 的 APK 已在本地构建（38.38 MiB，含"自动导出 Download/CryptPouch"与 β 公告），但还没有真机验证，所以这次先发经过一轮真机交互反馈的 `visual3`。
- 更早的 `visual` / `visual2` / 初版产物都在发布者本地保留，没有覆盖任何旧文件。

## 许可

成品与源码同许可，见仓库根目录 `LICENSE`。
