[
    {
        "name": "datadog-agent",
        "image": "${IMAGE}:${VERSION}",
        "essential": true,
        "command": ["bash", "-c", "echo -en \"init_config:\\ninstances:\\n  - stats_url: ${STATS_URL}\\n\" > /etc/datadog-agent/conf.d/envoy.d/conf.yaml && /init"],
        "logConfiguration": { 
              "logDriver": "awslogs",
              "options": { 
                 "awslogs-group" : "roxprox",
                 "awslogs-region": "${AWS_REGION}",
                 "awslogs-stream-prefix": "datadog-agent"
              }
       },
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
]