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
         %{ for p in mtls ~}
          {
             "containerPort": ${p.port},
             "hostPort": ${p.port},
             "protocol": "tcp"
          },  
         %{ endfor ~} 
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
       "dependsOn": [${EXTRA_DEPENDENCY}]
    }${EXTRA_CONTAINERS}
  ]