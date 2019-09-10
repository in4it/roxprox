[
    {
      "essential": true,
      "image": "envoyproxy/envoy:${ENVOY_RELEASE}",
      "name": "envoy-proxy",
      "entryPoint": ["bash"],
      "command": ["-c", "echo 'IyEvYmluL2Jhc2gKcHJpbnRmICIlcyIgJEVOVk9ZX0NPTkZJRyB8YmFzZTY0IC0tZGVjb2RlID4gL2V0Yy9lbnZveS9lbnZveS55YW1sCmVudm95IC0tYmFzZS1pZCAxIC0tY29uZmlnLXBhdGggL2V0Yy9lbnZveS9lbnZveS55YW1sCg==' |base64 --decode |bash"],
      "logConfiguration": { 
              "logDriver": "awslogs",
              "options": { 
                 "awslogs-group" : "roxprox",
                 "awslogs-region": "${AWS_REGION}",
                 "awslogs-stream-prefix": "envoy-proxy"
              }
       },
           "secrets": [
         { 
           "name": "ENVOY_CONFIG", 
           "valueFrom": "${ENVOY_CONFIG}"
         }
       ],
       "portMappings": [ 
          { 
             "containerPort": 10000,
             "hostPort": 10000,
             "protocol": "tcp"
          },
          { 
             "containerPort": 10001,
             "hostPort": 10001,
             "protocol": "tcp"
          }
       ],
       "memory" : 512,
       "dependsOn": [{
        "containerName": "envoy",
        "condition": "HEALTHY"
      }${EXTRA_DEPENDENCY}]
    },
    {         
        "name" : "envoy",
        "image" : "111345817488.dkr.ecr.${AWS_REGION}.amazonaws.com/aws-appmesh-envoy:${APPMESH_ENVOY_RELEASE}",
        "essential" : true,
        "environment" : [
          {
              "name" : "APPMESH_VIRTUAL_NODE_NAME",
              "value" : "mesh/${APPMESH_NAME}/virtualNode/envoy-proxy"
          }
        ],
        "logConfiguration": { 
          "logDriver": "awslogs",
          "options": { 
             "awslogs-group" : "roxprox",
             "awslogs-region": "${AWS_REGION}",
             "awslogs-stream-prefix": "envoy-proxy-sidecar"
          }
        },
        "healthCheck" : {
          "command" : [
              "CMD-SHELL",
              "curl -s http://localhost:9901/server_info | grep state | grep -q LIVE"
          ],
          "interval" : 5,
          "retries" : 3,
          "startPeriod" : 10,
          "timeout" : 2
        },
        "memory" : 512,
        "user" : "1337"
    }${EXTRA_CONTAINERS}
  ]