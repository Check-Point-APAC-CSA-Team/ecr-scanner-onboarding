
FROM alpine:3.16.9
RUN apk add --no-cache curl
CMD ["echo", "Hello from unique-ecs-task!"]
