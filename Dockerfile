FROM golang:1.21-alpine AS builder

# ===== 国内网络适配（部署到腾讯云时新增）=====
# proxy.golang.org 在国内不可达；Alpine 官方源 dl-cdn.alpinelinux.org 也很慢。
# 均可通过 --build-arg 覆盖，默认值只影响构建阶段，不写进最终镜像。
ARG GOPROXY=https://goproxy.cn,direct
ARG APK_MIRROR=mirrors.aliyun.com
ENV GOPROXY=${GOPROXY}
# ===========================================

WORKDIR /app

# 安装构建依赖（先切 Alpine 源，避免 apk 拉取超时）
RUN if [ -n "${APK_MIRROR}" ]; then \
        sed -i "s|dl-cdn.alpinelinux.org|${APK_MIRROR}|g" /etc/apk/repositories; \
    fi \
    && apk add --no-cache git

# 复制依赖清单（利用 Docker 构建缓存）
COPY go.mod go.sum ./
RUN go mod download

# 复制源码（配合 .dockerignore 排除本地二进制、日志与含密钥的 config.yaml）
COPY . .

# 构建：固定 GOOS=linux + CGO_ENABLED=0，产出静态二进制，
# 保证在 Alpine/musl 内可直接运行，不依赖 glibc，也不受宿主机是 Windows 还是 Linux 影响。
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o security-agent ./cmd/server

# 运行镜像
FROM alpine:latest

# ===== 国内网络适配（同上）=====
ARG APK_MIRROR=mirrors.aliyun.com
# ==============================

WORKDIR /app

# 安装运行时依赖（ca-certificates 供 HTTPS 调用大模型接口；tzdata 供时区解析）
RUN if [ -n "${APK_MIRROR}" ]; then \
        sed -i "s|dl-cdn.alpinelinux.org|${APK_MIRROR}|g" /etc/apk/repositories; \
    fi \
    && apk add --no-cache ca-certificates tzdata

# 复制二进制与前端静态资源。
# 关键修复：此前未复制 web/，导致 Linux 部署时首页与 /web/* 全部 404
# （容器内既无 ./web，也无法回退到 exe 同级 web 目录）。
COPY --from=builder /app/security-agent .
COPY --from=builder /app/web ./web
# 仅内置示例配置兜底；真实配置由 docker-compose 挂载或环境变量注入，
# 避免把含 API Key 的 config.yaml 打进镜像（.dockerignore 已排除）。
COPY --from=builder /app/config.yaml.example ./config.yaml

# 创建非root用户（Linux 安全基线：不以 root 运行网络服务）
RUN adduser -D -g '' appuser \
    && mkdir -p /app/logs \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

ENTRYPOINT ["./security-agent"]
