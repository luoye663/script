#!/bin/sh
#
# *sshhole - OpenSSH 密码认证绕过漏洞检测
# 适用: Linux / Alpine / Debian / Ubuntu / RHEL / Rocky / OpenWrt
# 依赖: POSIX sh, awk, grep, sed, tr
#
# 只读检测，不修改系统，不发送网络请求，不尝试认证绕过。
#
# 退出码:
#   0 - 未发现当前漏洞的有效触发条件
#   1 - 高风险
#   2 - 无法排除风险，需要人工确认
#

export LC_ALL=C

RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
RESET='\033[0m'

if [ ! -t 1 ] || [ "${NO_COLOR:-}" ]; then
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    RESET=''
fi

info() { printf "${BLUE}[INFO]${RESET} %s\n" "$*"; }
ok()   { printf "${GREEN}[ OK ]${RESET} %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${RESET} %s\n" "$*"; }
risk() { printf "${RED}[RISK]${RESET} %s\n" "$*"; }

section() {
    printf '\n========== %s ==========\n' "$1"
}

UNKNOWN=0
BLOCKED=0
CONFIG_UNKNOWN=0

# ------------------------------------------
# 1. 操作系统
# ------------------------------------------
section "操作系统"

OS="unknown"

if [ -r /etc/os-release ]; then
    OS=$(awk -F= '
        /^PRETTY_NAME=/ {
            gsub(/"/, "", $2)
            print $2
            exit
        }
    ' /etc/os-release)
fi

UNAME=$(uname -s 2>/dev/null)

info "系统: ${OS:-unknown}"
info "内核: $(uname -r 2>/dev/null)"

if [ "$UNAME" != "Linux" ]; then
    ok "不是 Linux，不属于本次漏洞的影响范围"
    exit 0
fi

if [ "$(id -u)" != "0" ]; then
    warn "当前不是 root，部分检测可能不完整"
fi

# ------------------------------------------
# 2. 寻找 OpenSSH 服务端
# ------------------------------------------
section "OpenSSH 服务端"

SSHD=""

# 优先查找运行中的 sshd
if [ -d /proc ]; then
    for p in /proc/[0-9]*; do
        [ -r "$p/comm" ] || continue

        name=$(cat "$p/comm" 2>/dev/null)

        [ "$name" = "sshd" ] || continue

        if [ -e "$p/exe" ] && command -v readlink >/dev/null 2>&1; then
            candidate=$(readlink "$p/exe" 2>/dev/null)

            case "$candidate" in
                *" (deleted)"*)
                    warn "发现运行中的旧 sshd 可执行文件已被删除或替换"
                    warn "升级软件包后可能尚未重启 sshd"
                    ;;
            esac

            if [ -n "$candidate" ]; then
                SSHD="$candidate"
                SSHD_PID="${p##*/}"
                break
            fi
        fi
    done
fi

if [ -z "$SSHD" ]; then
    for candidate in \
        /usr/sbin/sshd \
        /usr/local/sbin/sshd \
        /sbin/sshd
    do
        if [ -x "$candidate" ]; then
            SSHD="$candidate"
            break
        fi
    done
fi

if [ -z "$SSHD" ] && command -v sshd >/dev/null 2>&1; then
    SSHD=$(command -v sshd)
fi

if [ -z "$SSHD" ]; then
    warn "没有发现 OpenSSH sshd"
    info "如果 SSH 服务位于容器内，请进入容器检测"
    exit 2
fi

info "sshd: $SSHD"

if [ -n "${SSHD_PID:-}" ]; then
    info "运行进程 PID: $SSHD_PID"
else
    warn "未确认正在运行的 sshd，使用磁盘上的程序检测"
    UNKNOWN=1
fi

VERSION=$("$SSHD" -V 2>&1 | head -n 1)

info "版本: ${VERSION:-unknown}"

# 仅当确认不低于官方修复版本时才视为上游已修复
PATCHED=unknown

case "$VERSION" in
    *OpenSSH_*)
        VER=$(printf '%s\n' "$VERSION" |
            sed -n 's/.*OpenSSH_\([0-9][0-9]*\)\.\([0-9][0-9]*\)\(p\([0-9][0-9]*\)\)\{0,1\}.*/\1 \2 \4/p')

        if [ -n "$VER" ]; then
            set -- $VER
            MAJOR=$1
            MINOR=$2
            PATCH=${3:-0}

            if [ "$MAJOR" -gt 10 ] ||
               { [ "$MAJOR" -eq 10 ] && [ "$MINOR" -gt 6 ]; } ||
               { [ "$MAJOR" -eq 10 ] && [ "$MINOR" -eq 6 ] && [ "$PATCH" -ge 2 ]; }; then
                PATCHED=yes
                ok "版本达到 OpenSSH 10.6p2 或更新"
            else
                PATCHED=unknown
                warn "版本低于 10.6p2，需检查发行版是否回移补丁"
            fi
        else
            warn "无法解析 OpenSSH 版本"
            UNKNOWN=1
        fi
        ;;
    *)
        warn "无法识别 OpenSSH 版本"
        UNKNOWN=1
        ;;
esac

# ------------------------------------------
# 3. 判断 sshd 使用的 libc
# ------------------------------------------
section "C 运行库"

LIBC=unknown

# 优先分析正在运行的 sshd 内存映射
if [ -n "${SSHD_PID:-}" ] && [ -r "/proc/$SSHD_PID/maps" ]; then
    if grep -Eiq 'musl|ld-musl' "/proc/$SSHD_PID/maps"; then
        LIBC=musl
    elif grep -Eq 'libc\.so\.6|ld-linux' "/proc/$SSHD_PID/maps"; then
        LIBC=glibc
    fi
fi

# ELF 动态解释器
if [ "$LIBC" = unknown ] && command -v readelf >/dev/null 2>&1; then
    INTERP=$(readelf -l "$SSHD" 2>/dev/null |
        grep 'Requesting program interpreter')

    case "$INTERP" in
        *musl*) LIBC=musl ;;
        *ld-linux*|*ld64.so*) LIBC=glibc ;;
    esac
fi

# ldd 补充判断（部分静态程序无法判断）
if [ "$LIBC" = unknown ] && command -v ldd >/dev/null 2>&1; then
    LIBOUT=$(ldd "$SSHD" 2>&1)

    case "$LIBOUT" in
        *musl*) LIBC=musl ;;
        *libc.so.6*|*ld-linux*) LIBC=glibc ;;
    esac
fi

# 最后使用系统 libc 信息作为线索
if [ "$LIBC" = unknown ]; then
    if ls /lib/ld-musl-*.so.1 >/dev/null 2>&1; then
        warn "系统存在 musl，但无法确定 sshd 是否使用它"
    fi
fi

case "$LIBC" in
    musl)
        risk "sshd 使用 musl libc"
        ;;
    glibc)
        ok "sshd 使用 glibc，不属于本次漏洞的典型受影响环境"
        BLOCKED=1
        ;;
    *)
        warn "无法确定 sshd 使用的 libc（可能静态链接）"
        UNKNOWN=1
        ;;
esac

# ------------------------------------------
# 4. 检测 SSH 有效配置
# ------------------------------------------
section "SSH 认证配置"

CONFIG=$("$SSHD" -T 2>/dev/null)

if [ -z "$CONFIG" ]; then
    warn "无法获取 sshd 有效配置"
    warn "可能需要 root 权限或检查 sshd 配置语法"
    UNKNOWN=1
    CONFIG_UNKNOWN=1
else
    get_config() {
        printf '%s\n' "$CONFIG" |
            awk -v key="$1" '
                tolower($1) == key {
                    print tolower($2)
                    exit
                }
            '
    }

    USEPAM=$(get_config usepam)
    PASSAUTH=$(get_config passwordauthentication)
    KBDAUTH=$(get_config kbdinteractiveauthentication)
    ROOTLOGIN=$(get_config permitrootlogin)

    info "UsePAM: ${USEPAM:-unknown}"
    info "PasswordAuthentication: ${PASSAUTH:-unknown}"
    info "KbdInteractiveAuthentication: ${KBDAUTH:-unknown}"
    info "PermitRootLogin: ${ROOTLOGIN:-unknown}"

    case "$USEPAM" in
        yes)
            ok "启用了 PAM"
            BLOCKED=1
            ;;
        no)
            warn "未启用 PAM"
            ;;
        *)
            warn "无法确定 PAM 状态"
            UNKNOWN=1
            ;;
    esac

    case "$PASSAUTH" in
        no)
            ok "密码认证已关闭"
            BLOCKED=1
            ;;
        yes)
            warn "密码认证已开启"
            ;;
        *)
            warn "无法确定密码认证状态"
            UNKNOWN=1
            ;;
    esac

    # sshd -T 不指定 -C 时不能完整覆盖 Match 规则
    if [ -r /etc/ssh/sshd_config ]; then
        if grep -Eiq '^[[:space:]]*Match[[:space:]]' \
            /etc/ssh/sshd_config; then
            warn "发现 Match 规则，需要按具体用户和来源地址另行检查"
            CONFIG_UNKNOWN=1
        fi
    fi

    if [ "$ROOTLOGIN" = "no" ]; then
        info "root 直接登录已禁用"
    elif [ "$ROOTLOGIN" = "prohibit-password" ]; then
        info "root 密码登录受到单独限制"
    fi
fi

# ------------------------------------------
# 5. 检查 /etc/shadow
# ------------------------------------------
section "账户密码字段"

STAR_COUNT=0
HASH_COUNT=0
SHADOW_UNKNOWN=0

if [ -r /etc/shadow ]; then
    # 只输出用户名和统计，不输出密码哈希
    STARS=$(awk -F: '$2 == "*" { print $1 }' /etc/shadow)

    STAR_COUNT=$(awk -F: '$2 == "*" { n++ } END { print n+0 }' \
        /etc/shadow)

    HASH_COUNT=$(awk -F: '$2 ~ /^\$/ { n++ } END { print n+0 }' \
        /etc/shadow)

    info "密码字段为 * 的账户: $STAR_COUNT"
    info "存在 $ 格式密码哈希的账户: $HASH_COUNT"

    if [ "$STAR_COUNT" -gt 0 ]; then
        warn "以下账户密码字段恰好为 *："
        printf '%s\n' "$STARS" |
            while IFS= read -r user; do
                [ -n "$user" ] && printf '    - %s\n' "$user"
            done
    else
        ok "未发现密码字段为 * 的本地账户"
    fi

    if [ "$HASH_COUNT" -eq 0 ]; then
        warn "未发现 $ 格式的本地密码哈希"
        warn "仍可能使用其他哈希格式或外部账户数据库"
    fi
else
    warn "无法读取 /etc/shadow"
    UNKNOWN=1
    SHADOW_UNKNOWN=1
fi

# ------------------------------------------
# 6. 风险分析
# ------------------------------------------
section "最终风险评估"

info "漏洞: *sshhole - OpenSSH / musl 密码认证绕过"
info "官方上游修复版本: OpenSSH 10.6p2"

if [ "$PATCHED" = yes ]; then
    ok "【低风险】当前检查到的 sshd 版本包含上游修复"
    exit 0
fi

if [ "$LIBC" = glibc ]; then
    ok "【低风险】sshd 使用 glibc，不满足 musl 利用条件"
    exit 0
fi

if [ "$BLOCKED" -eq 1 ] && [ "$CONFIG_UNKNOWN" -eq 0 ]; then
    ok "【低风险】当前认证配置不满足主要利用条件"
    exit 0
fi

if [ "$LIBC" = musl ] &&
   [ "${USEPAM:-}" = no ] &&
   [ "${PASSAUTH:-}" = yes ] &&
   [ "$STAR_COUNT" -gt 0 ] &&
   [ "$HASH_COUNT" -gt 0 ] &&
   [ "$SHADOW_UNKNOWN" -eq 0 ]; then

    risk "【高风险】符合此次漏洞公开的主要触发条件"
    risk "存在账户密码认证绕过风险"

    printf '\n建议立即执行：\n'
    printf '  1. 优先安装发行版 OpenSSH 安全更新\n'
    printf '  2. 暂时设置 PasswordAuthentication no\n'
    printf '  3. 检查 SSH 认证日志中的异常密码登录\n'
    printf '  4. 确认升级后的 sshd 进程已经重启\n'
    printf '  5. 检查 Match、PAM 和账户授权策略\n'

    warn "如已回移安全补丁，可能并不实际存在漏洞"
    exit 1
fi

warn "【无法排除风险】没有证实全部利用条件"

if [ "$LIBC" = musl ]; then
    warn "检测到 musl，需要特别关注"
fi

if [ "$CONFIG_UNKNOWN" -eq 1 ]; then
    warn "SSH 配置存在未覆盖的条件"
fi

if [ "$UNKNOWN" -eq 1 ]; then
    warn "部分环境信息无法可靠确定"
fi

info "建议核查发行版安全公告、补丁状态和实际认证路径"

exit 2
