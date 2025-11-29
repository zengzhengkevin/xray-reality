#!/usr/bin/env bash
# ============================================================
# Xray REALITY 一键脚本 V2
# 说明：
#   - 适用于 Debian 12（其他 systemd Linux 通常也可）
#   - 功能：一键安装 Xray + 开启 BBR + 配置单个 VLESS REALITY 节点
#   - 每次运行会覆盖旧节点，生成一个新的单节点配置
#   - 自动输出并保存：
#       * vless:// 链接（v2rayN / v2rayNG）
#       * sing-box 客户端配置 JSON
#       * Clash Meta 节点配置 YAML
#
# 生成文件：
#   /usr/local/etc/xray/config.json              # 服务器配置
#   /usr/local/etc/xray/reality-info.txt        # 人类可读的节点信息
#   /usr/local/etc/xray/vless-link.txt          # vless:// 链接（v2rayN / v2rayNG）
#   /usr/local/etc/xray/client-singbox.json     # sing-box 客户端配置
#   /usr/local/etc/xray/client-clashmeta.yaml   # Clash Meta 节点配置
#
# 卸载：
#   ./xray_reality_v2.sh uninstall
# ============================================================

CONFIG_FILE="/usr/local/etc/xray/config.json"
INFO_FILE="/usr/local/etc/xray/reality-info.txt"
VLESS_LINK_FILE="/usr/local/etc/xray/vless-link.txt"
SINGBOX_FILE="/usr/local/etc/xray/client-singbox.json"
CLASHMETA_FILE="/usr/local/etc/xray/client-clashmeta.yaml"

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
RESET="\e[0m"

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}请用 root 身份运行（sudo -i 或 sudo bash）。${RESET}"
        exit 1
    fi
}

system_check() {
    echo -e "${BLUE}[*] 检查系统环境...${RESET}"

    if ! grep -qi "debian" /etc/os-release; then
        echo -e "${YELLOW}[!] 当前系统不是 Debian，可能存在兼容问题。${RESET}"
        read -rp "仍然继续？(y/N): " cont
        cont=${cont:-N}
        [[ \"$cont\" =~ ^[yY]$ ]] || exit 1
    fi

    IPV4=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -z \"$IPV4\" ]; then
        echo -e \"${RED}[x] 未检测到 IPv4 地址，请先检查网络。${RESET}\"
        exit 1
    else
        echo -e \"${GREEN}[✓] 本机 IPv4 地址: ${IPV4}${RESET}\"
    fi

    echo -e \"${BLUE}[*] 安装必要依赖: curl wget unzip openssl...${RESET}\"
    apt update -y >/dev/null 2>&1
    apt install -y curl wget unzip openssl >/dev/null 2>&1

    systemctl daemon-reload 2>/dev/null || true
}

install_xray() {
    if command -v xray >/dev/null 2>&1; then
        echo -e \"${GREEN}[✓] 已检测到 xray，跳过安装。${RESET}\"
        return 0
    fi

    echo -e \"${BLUE}[*] 安装 Xray ...${RESET}\"
    bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install
    if [ $? -ne 0 ]; then
        echo -e \"${RED}[x] Xray 安装失败，请检查网络后重试。${RESET}\"
        exit 1
    fi
    systemctl enable xray --now
    echo -e \"${GREEN}[✓] Xray 安装完成。${RESET}\"
}

enable_bbr() {
    echo -e \"${BLUE}[*] 开启 BBR 拥塞控制...${RESET}\"

    grep -q \"net.core.default_qdisc=fq\" /etc/sysctl.conf || echo \"net.core.default_qdisc=fq\" >> /etc/sysctl.conf
    grep -q \"net.ipv4.tcp_congestion_control=bbr\" /etc/sysctl.conf || echo \"net.ipv4.tcp_congestion_control=bbr\" >> /etc/sysctl.conf

    sysctl -p >/dev/null 2>&1
    algo=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
    echo -e \"${GREEN}[✓] 当前拥塞控制算法: ${algo}${RESET}\"
}

gen_short_id() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 8
    else
        tr -dc 'a-f0-9' </dev/urandom | head -c 16
    fi
}

# 生成 Reality 密钥：兼容新版（PrivateKey+Password）与旧版（Private/Public）
gen_reality_keys() {
    local out priv pub

    echo -e \"${BLUE}[*] 生成 REALITY 密钥对...${RESET}\"

    out=$(xray x25519 2>/dev/null)

    priv=$(printf \"%s\n\" \"$out\" | sed -n 's/^PrivateKey:[[:space:]]*//p;s/^[Pp]rivate[[:space:]]\\+key[[:space:]]*:[[:space:]]*//p' | head -n1)
    pub=$(printf \"%s\n\" \"$out\" | sed -n 's/^Password:[[:space:]]*//p;s/^[Pp]ublic[[:space:]]\\+key[[:space:]]*:[[:space:]]*//p' | head -n1)

    if [ -z \"$priv\" ]; then
        echo -e \"${RED}[x] 无法从 xray x25519 输出中解析 PrivateKey。${RESET}\"
        echo -e \"${YELLOW}请手动执行: xray x25519 查看输出格式。${RESET}\"
        return 1
    fi

    XRAY_PRIV_KEY=\"$priv\"
    XRAY_PUB_KEY=\"$pub\"

    echo -e \"  PrivateKey: ${GREEN}${XRAY_PRIV_KEY}${RESET}\"
    if [ -n \"$XRAY_PUB_KEY\" ]; then
        echo -e \"  PublicKey(pbk): ${GREEN}${XRAY_PUB_KEY}${RESET}\"
    else
        echo -e \"${YELLOW}[!] 未能解析到 PublicKey/Password，生成的 vless 链接中将不包含 pbk。${RESET}\"
    fi

    return 0
}

generate_config() {
    echo -e \"${BLUE}[*] 配置 VLESS REALITY...${RESET}\"

    read -rp \"监听端口（默认 51443）: \" PORT
    PORT=${PORT:-51443}

    read -rp \"伪装域名 SNI（默认 www.apple.com）: \" SNI
    SNI=${SNI:-www.apple.com}

    echo -e \"${BLUE}[*] 生成 UUID...${RESET}\"
    if xray uuid >/dev/null 2>&1; then
        UUID=$(xray uuid)
    else
        UUID=$(cat /proc/sys/kernel/random/uuid)
    fi
    echo -e \"  UUID: ${GREEN}${UUID}${RESET}\"

    if ! gen_reality_keys; then
        echo -e \"${RED}[x] 生成 REALITY 密钥失败，终止。${RESET}\"
        exit 1
    fi
    PRIVATE_KEY=\"$XRAY_PRIV_KEY\"
    PUBLIC_KEY=\"$XRAY_PUB_KEY\"

    SHORT_ID=$(gen_short_id)
    echo -e \"  ShortID: ${GREEN}${SHORT_ID}${RESET}\"

    mkdir -p /usr/local/etc/xray

    cat > \"$CONFIG_FILE\" <<EOF
{
  \"inbounds\": [
    {
      \"tag\": \"vless-reality-1\",
      \"listen\": \"0.0.0.0\",
      \"port\": ${PORT},
      \"protocol\": \"vless\",
      \"settings\": {
        \"clients\": [
          {
            \"id\": \"${UUID}\",
            \"flow\": \"xtls-rprx-vision\"
          }
        ],
        \"decryption\": \"none\"
      },
      \"streamSettings\": {
        \"network\": \"tcp\",
        \"security\": \"reality\",
        \"realitySettings\": {
          \"show\": false,
          \"dest\": \"${SNI}:443\",
          \"xver\": 0,
          \"serverNames\": [
            \"${SNI}\"
          ],
          \"privateKey\": \"${PRIVATE_KEY}\",
          \"shortIds\": [
            \"${SHORT_ID}\"
          ]
        }
      }
    }
  ],
  \"outbounds\": [
    {
      \"protocol\": \"freedom\"
    }
  ]
}
EOF

    echo -e \"${GREEN}[✓] 已写入配置到: ${CONFIG_FILE}${RESET}\"

    echo -e \"${BLUE}[*] 测试配置文件...${RESET}\"
    if ! xray run -test -c \"$CONFIG_FILE\"; then
        echo -e \"${RED}[x] 配置测试失败，请检查 ${CONFIG_FILE}。${RESET}\"
        exit 1
    fi

    systemctl restart xray
    sleep 1
    systemctl status xray --no-pager | sed -n '1,8p'

    SERVER_IP=$(
        curl -4s https://api64.ipify.org 2>/dev/null ||
        curl -4s https://ipv4.icanhazip.com 2>/dev/null ||
        curl -4s https://ifconfig.me 2>/dev/null ||
        hostname -I | awk '{print $1}'
    )

    local link=\"vless://${UUID}@${SERVER_IP}:${PORT}?security=reality&encryption=none&flow=xtls-rprx-vision&sni=${SNI}&fp=chrome\"
    if [ -n \"$PUBLIC_KEY\" ]; then
        link=\"${link}&pbk=${PUBLIC_KEY}\"
    fi
    link=\"${link}&sid=${SHORT_ID}&type=tcp#Xray-REALITY-${PORT}\"

    mkdir -p \"$(dirname \"$INFO_FILE\")\"
    echo \"$link\" > \"$VLESS_LINK_FILE\"

    cat > \"$SINGBOX_FILE\" <<EOF
{
  \"log\": {
    \"level\": \"info\"
  },
  \"dns\": {
    \"servers\": [
      {
        \"address\": \"https://1.1.1.1/dns-query\",
        \"detour\": \"direct\"
      }
    ]
  },
  \"outbounds\": [
    {
      \"type\": \"vless\",
      \"tag\": \"reality-out\",
      \"server\": \"${SERVER_IP}\",
      \"server_port\": ${PORT},
      \"uuid\": \"${UUID}\",
      \"flow\": \"xtls-rprx-vision\",
      \"packet_encoding\": \"xudp\",
      \"tls\": {
        \"enabled\": true,
        \"server_name\": \"${SNI}\",
        \"utls\": {
          \"enabled\": true,
          \"fingerprint\": \"chrome\"
        },
        \"reality\": {
          \"enabled\": true,
          \"public_key\": \"${PUBLIC_KEY}\",
          \"short_id\": \"${SHORT_ID}\"
        }
      }
    },
    {
      \"type\": \"direct\",
      \"tag\": \"direct\"
    },
    {
      \"type\": \"block\",
      \"tag\": \"block\"
    }
  ]
}
EOF

    cat > \"$CLASHMETA_FILE\" <<EOF
proxies:
  - name: \"reality_${SERVER_IP}_${PORT}\"
    type: vless
    server: ${SERVER_IP}
    port: ${PORT}
    uuid: \"${UUID}\"
    flow: xtls-rprx-vision
    udp: true
    network: tcp
    reality-opts:
      public-key: \"${PUBLIC_KEY}\"
      short-id: \"${SHORT_ID}\"
    servername: \"${SNI}\"
    client-fingerprint: \"chrome\"
    tls: true
EOF

    {
        echo \"=== Xray REALITY 节点信息 ===\"
        echo \"时间: $(date)\"
        echo \"服务器 IP: ${SERVER_IP}\"
        echo
        echo \"端口: ${PORT}\"
        echo \"UUID : ${UUID}\"
        echo \"SNI  : ${SNI}\"
        echo \"PrivateKey: ${PRIVATE_KEY}\"
        echo \"PublicKey : ${PUBLIC_KEY}\"
        echo \"ShortID   : ${SHORT_ID}\"
        echo
        echo \"VLESS 链接 (v2rayN / v2rayNG)：\"
        echo \"${link}\"
        echo
        echo \"vless 链接已保存到: ${VLESS_LINK_FILE}\"
        echo \"sing-box 客户端配置: ${SINGBOX_FILE}\"
        echo \"Clash Meta 节点配置: ${CLASHMETA_FILE}\"
    } > \"$INFO_FILE\"

    echo
    echo -e \"${GREEN}[✓] 已生成并保存所有配置文件：${RESET}\"
    echo \"  - 节点信息:        ${INFO_FILE}\"
    echo \"  - vless 链接:      ${VLESS_LINK_FILE}\"
    echo \"  - sing-box 配置:   ${SINGBOX_FILE}\"
    echo \"  - Clash Meta 配置: ${CLASHMETA_FILE}\"
    echo
    echo -e \"${YELLOW}下面是你的 VLESS REALITY 链接（可直接用于客户端导入 / 二维码）：${RESET}\"
    echo
    echo \"${link}\"
    echo
}

uninstall_xray() {
    echo -e \"${RED}[!] 即将卸载 Xray 并清理相关文件。${RESET}\"
    read -rp \"确认继续？(y/N): \" ans
    ans=${ans:-N}
    [[ \"$ans\" =~ ^[yY]$ ]] || { echo \"已取消。\"; exit 0; }

    systemctl stop xray 2>/dev/null
    systemctl disable xray 2>/dev/null

    bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) remove

    rm -f /usr/local/bin/xray
    rm -rf /usr/local/etc/xray
    rm -rf /usr/local/share/xray
    rm -f /etc/systemd/system/xray.service
    rm -f /etc/systemd/system/xray@.service
    rm -rf /etc/systemd/system/xray.service.d
    rm -rf /etc/systemd/system/xray@.service.d

    systemctl daemon-reload
    systemctl reset-failed

    echo -e \"${GREEN}[✓] Xray 及相关配置已删除。${RESET}\"
}

main() {
    check_root

    if [ \"$1\" = \"uninstall\" ]; then
        uninstall_xray
        exit 0
    fi

    system_check
    install_xray
    enable_bbr
    generate_config

    echo -e \"${GREEN}全部完成，可以用上面的链接在客户端导入/生成二维码。${RESET}\"
}

main \"$@\"
