set(src
  token_conf.c
  token.c)

FLB_PLUGIN(out_token "${src}" "EnnMonitorSecurityGatewayClient -lprotobuf -lgrpc++ -lgrpc")
