#!/usr/bin/env bash
# ============================================================
# Xray REALITY 一键脚本 V3（多节点版）
#
# 特性：
#   - 每次运行脚本 = 添加一个新的 REALITY 节点（不会覆盖旧的）
#   - 支持多端口、多 UUID、多 SNI，多组 Reality 私钥/公钥
#   - 自动重建 config.json，包含所有节点的 inbounds
#   - 每次运行生成最新节点的：
#       * vless 链接（v2rayN / v2rayNG）
#       * sing-box 客户端配置 JSON
#       * Clash Meta 节点配置 YAML
#   - 维护一个节点数据库文件：/usr/local/etc/xray/reality-nodes.db
#
# 数据库存储格式（每行一个节点）：
#   PORT|UUID|SNI|PRIVATE_KEY|PUBLIC_KEY|SHORT_ID
#
# 生成文件：
#   /usr/local/etc/xray/config.json              # 服务器配置（包含所有节点）
#   /usr/local/etc/xray/reality-info.txt        # 所有节点的人类可读列表
#   /usr/local/etc/xray/vless-last.txt          # 最新节点 vless:// 链接
#   /usr/local/etc/xray/client-last-singbox.json     # 最新节点 sing-box 配置
#   /usr/local/etc/xray/client-last-clashmeta.yaml   # 最新节点 Clash Meta 节点
#   /usr/local/etc/xray/reality-nodes.db        # 节点数据库
#
# 卸载：
#   ./xray_reality_v3.sh uninstall
# ============================================================

CONFIG_FILE="/usr/local/etc/xray/config.json"
INFO_FILE="/usr/local/etc/xray/reality-info.txt"
DB_FILE="/usr/local/etc/xray/reality-nodes.db"
VLESS_LAST="/usr/local/etc/xray/vless-last.txt"
SINGBOX_LAST="/usr/local/etc/xray/client-last-singbox.json"
CLASHMETA_LAST="/usr/local/etc/xray/client-last-clashmeta.yaml"

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
RESET="\e[0m"

check_root() {
    if [ \"$(id -u)\" -ne 0 ]; then
        echo -e \"${RED}请用 root 身份运行（sudo -i 或 sudo bash）。${RESET}\"
        exit 1
    fi
}

system_check() {
    echo -e \"${BLUE}[*] 检查系统环境...${RESET}\"

    if ! grep -qi \"debian\" /etc/os-release; then
        echo -e \"${YELLOW}[!] 当前系统不是 Debian，可能存在兼容问题。${RESET}\"
        read -rp \"仍然继续？(y/N): \" cont
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

# 从 xray x25519 生成 Reality 私钥 & 公钥（新版用 Password 作为 pbk）
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

# 从 DB_FILE 重建 config.json 和 info 列表（多节点）
rebuild_config_and_info() {
    if [ ! -f \"$DB_FILE\" ] || [ ! -s \"$DB_FILE\" ]; then
        echo -e \"${RED}[x] 未找到任何节点记录（${DB_FILE} 空）。${RESET}\"
        return 1
    fi

    local inbounds_json=\"\"
    local idx=0
    local SERVER_IP
    SERVER_IP=$(
        curl -4s https://api64.ipify.org 2>/dev/null ||
        curl -4s https://ipv4.icanhazip.com 2>/dev/null ||
        curl -4s https://ifconfig.me 2>/dev/null ||
        hostname -I | awk '{print $1}'
    )

    local info_text=\"=== Xray REALITY 多节点信息 ===\n时间: $(date)\n服务器 IP: ${SERVER_IP}\n\n\"

    while IFS='|' read -r PORT UUID SNI PRIVATE_KEY PUBLIC_KEY SHORT_ID; do
        [ -z \"$PORT\" ] && continue
        idx=$((idx+1))

        local DEST TAG inbound link
        DEST=\"${SNI}:443\"
        TAG=\"vless-reality-${idx}\"

        inbound=$(cat <<EOF
{
  \"tag\": \"${TAG}\",
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
      \"dest\": \"${DEST}\",
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
EOF
)

        if [ -n \"$inbounds_json\" ]; then
            inbounds_json=\"${inbounds_json},
${inbound}\"
        else
            inbounds_json=\"${inbound}\"
        fi

        link=\"vless://${UUID}@${SERVER_IP}:${PORT}?security=reality&encryption=none&flow=xtls-rprx-vision&sni=${SNI}&fp=chrome\"
        if [ -n \"$PUBLIC_KEY\" ]; then
            link=\"${link}&pbk=${PUBLIC_KEY}\"
        fi
        link=\"${link}&sid=${SHORT_ID}&type=tcp#Xray-REALITY-${PORT}\"

        info_text+=\"节点 ${idx}:\n  端口: ${PORT}\n  UUID: ${UUID}\n  SNI : ${SNI}\n  ShortID: ${SHORT_ID}\n  PublicKey: ${PUBLIC_KEY}\n\n  链接: ${link}\n\n\"
    done < \"$DB_FILE\"

    mkdir -p /usr/local/etc/xray

    cat > \"$CONFIG_FILE\" <<EOF
{
  \"inbounds\": [
${inbounds_json}
  ],
  \"outbounds\": [
    {
      \"protocol\": \"freedom\"
    }
  ]
}
EOF

    printf \"%b\n\" \"$info_text\" > \"$INFO_FILE\"

    echo -e \"${BLUE}[*] 测试并重启 Xray...${RESET}\"
    if ! xray run -test -c \"$CONFIG_FILE\"; then
        echo -e \"${RED}[x] 配置测试失败，请检查 ${CONFIG_FILE}。${RESET}\"
        return 1
    fi

    systemctl restart xray
    sleep 1
    systemctl status xray --no-pager | sed -n '1,8p'

    echo -e \"${GREEN}[✓] 已重建 config.json 并重启 Xray，所有节点信息见: ${INFO_FILE}${RESET}\"
}

add_node() {
    echo -e \"${BLUE}[*] 添加新的 REALITY 节点...${RESET}\"

    read -rp \"监听端口（例如 443、51443 等，默认 51443）: \" PORT
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
    echo \"${PORT}|${UUID}|${SNI}|${PRIVATE_KEY}|${PUBLIC_KEY}|${SHORT_ID}\" >> \"$DB_FILE\"

    rebuild_config_and_info

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

    echo \"$link\" > \"$VLESS_LAST\"

    cat > \"$SINGBOX_LAST\" <<EOF
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

    cat > \"$CLASHMETA_LAST\" <<EOF
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

    echo
    echo -e \"${GREEN}[✓] 新节点已添加并启用。关键信息：${RESET}\"
    echo \"  - UUID        : ${UUID}\"
    echo \"  - 端口        : ${PORT}\"
    echo \"  - SNI         : ${SNI}\"
    echo \"  - ShortID     : ${SHORT_ID}\"
    echo \"  - PrivateKey  : ${PRIVATE_KEY}\"
    echo \"  - PublicKey   : ${PUBLIC_KEY}\"
    echo
    echo -e \"${YELLOW}最新节点的 VLESS 链接：${RESET}\"
    echo \"${link}\"
    echo
    echo \"已保存到:\"
    echo \"  - 所有节点信息:   ${INFO_FILE}\"
    echo \"  - 最新 vless 链接: ${VLESS_LAST}\"
    echo \"  - 最新 sing-box:   ${SINGBOX_LAST}\"
    echo \"  - 最新 ClashMeta:   ${CLASHMETA_LAST}\"
    echo
}

uninstall_xray() {
    echo -e \"${RED}[!] 即将卸载 Xray 并清理相关文件（包括所有节点配置）。${RESET}\"
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
    add_node

    echo -e \"${GREEN}本次操作已完成。以后再次运行本脚本，将继续添加新的 REALITY 节点。${RESET}\"
}

main \"$@\"
