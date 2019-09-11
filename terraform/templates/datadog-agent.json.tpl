{
  "family": "datadog",
  "networkMode": "awsvpc",
  "containerDefinitions": [
      {
          "name": "datadog-agent",
          "image": "${IMAGE}:${VERSION}",
          "essential": true,
          "command": ["bash", "-c", "'echo -en \"init_config:\ninstances:\n  - stats_url: ${STATS_URL}\n\" > /etc/datadog-agent/conf.d/envoy.d/conf.yaml && /init'"],
          "environment": [
              {
                  "name": "DD_API_KEY",
                  "value": "${DD_API_KEY}"
              },
              {
                  "name": "DD_APM_ENABLED",
                  "value": "true"
              },
              {
                  "name": "ECS_FARGATE",
                  "value": "true"
              }
          ]
      }
  ],
  "requiresCompatibilities": [
      "FARGATE"
  ],
  "cpu": "256",
  "memory": "512"
}
