set(src
  logformat_log.c
  logformat_conf.c
  logformat_meta.c
  logformat_regex.c
  logformat_test.c
  logformat.c
  )

FLB_PLUGIN(filter_logformat "${src}" "")
