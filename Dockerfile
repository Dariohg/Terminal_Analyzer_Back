# Build stage
FROM golang:1.21-alpine AS builder

# Instalar dependencias necesarias
RUN apk add --no-cache git

# Establecer directorio de trabajo
WORKDIR /app

# Copiar go mod y sum files
COPY go.mod go.sum ./

# Descargar dependencias
RUN go mod download

# Copiar código fuente
COPY . .

# Build de la aplicación
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/server

# Production stage
FROM alpine:latest

# Instalar ca-certificates para HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copiar el binario desde build stage
COPY --from=builder /app/main .

# Exponer puerto
EXPOSE 8080

# Comando para ejecutar
CMD ["./main"]