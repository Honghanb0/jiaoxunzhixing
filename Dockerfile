FROM golang:1.21-alpine AS builder

WORKDIR /app

# 安装构建依赖
RUN apk add --no-cache git

# 复制源码
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# 构建
RUN CGO_ENABLED=0 GOOS=linux go build -o security-agent ./cmd/server

# 运行镜像
FROM alpine:latest

WORKDIR /app

# 安装运行时依赖
RUN apk add --no-cache ca-certificates tzdata

# 复制二进制文件
COPY --from=builder /app/security-agent .
COPY --from=builder /app/config.yaml.example ./config.yaml

# 创建非root用户
RUN adduser -D -g '' appuser
USER appuser

EXPOSE 8080

ENTRYPOINT ["./security-agent"]
