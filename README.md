# singbox-x

基于 sing-box 1.13.12 的定制内核，加入 Cloudflare Tunnel 和 UU 两种跨网段出口。已有节点和路由继续使用 sing-box 配置。[上游文档](https://sing-box.sagernet.org)

需要网页配置、UU 扫码、选设备和网段分流时，用 sboxctl 管理本内核。[sboxctl](https://github.com/maxiloEmmmm/singbox-mini-panel)

## CF Mux

`cf` 出站把原始目标和逻辑流 ID 交给对端 daemon。一条 WSS 同时承载多条 TCP 流和 UDP 会话。单流窗口和总窗口限制排队数据，按字节调度让交互流能与大流共享链路。[对端 daemon](https://github.com/maxiloEmmmm/tmp-proxy)

```json
{
  "type": "cf",
  "tag": "home-cf",
  "kv_key": "cfp/demo",
  "detour": "edge-proxy"
}
```

- `kv_key` 使用对端发布的完整 Workers KV 键。内核从 CFP 配置的 `reporter` 读取 `account_id`、`namespace` 和凭据。配置路径依次取 `config_path`、`CFP_CONFIG`、`/etc/cfp/config.yaml` 或用户配置目录。
- `detour` 可选，指定 KV 查询和 WSS 经由哪个已配置的出站。示例中的 `edge-proxy` 需要按实际出站填写。
- 已有固定 WSS 地址时可用 `endpoint`。连通后可从 `CF-Ray` 获取接入位置，例如 `HKG`。

## UU

UU 的扫码认证、连接信令和端口映射参考了上游的 Linux 控制端与接收端，并在 singbox-x 中用 Go 实现。[VallierDev/uu-remote-linux v0.2.61](https://github.com/VallierDev/uu-remote-linux/releases/tag/v0.2.61)

`uu` 出站通过 UU 端口映射连接所选设备的 SOCKS5 或 mixed 入站。TCP 使用 SOCKS5 转发，UDP 通过 UoT 承载。出站在本机使用私有的回环监听，接收端只向配置指定的本机回环端口转发。

接收端以 `services` 中的一个 Go 服务运行，每个 sing-box 实例只启用一个。接收端可以独立扫码，也可以复用任意已登录的连接账号。多条 `uu` 出站可各自选择账号、设备和端口。

下面是 UU 相关的配置片段。本机和对端的 mixed 端口都用 `1080`，分别对应 `local_port` 和 `remote_port`。出站的 `device_id` 由扫码后选择的对端设备提供。

```json
{
  "outbounds": [
    {
      "type": "uu",
      "tag": "home-uu",
      "account": "default",
      "device_id": "<peer-device-id>",
      "remote_port": 1080
    }
  ],
  "services": [
    {
      "type": "uu",
      "tag": "uu-host",
      "local_port": 1080,
      "host_account": "default"
    }
  ]
}
```

`host_account` 留空时使用接收端独立登录。配置多个连接账号时，通过服务的 `accounts` 登记账号键，再在各出站的 `account` 选择。无 `HOME` 的 systemd 服务可通过 `SBOXCTL_UU_STATE_DIR` 指定持久凭据目录。

## 构建

使用 Go 1.24.7 或更新版本。默认构建包含 sboxctl 使用的 Clash API。

```bash
git clone https://github.com/maxiloEmmmm/singbox-x.git
cd singbox-x
make build
./sing-box version
```

将生成的 `sing-box` 放在 sboxctl 可执行文件旁，再重启服务。[sboxctl 安装说明](https://github.com/maxiloEmmmm/singbox-mini-panel#安装)

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```