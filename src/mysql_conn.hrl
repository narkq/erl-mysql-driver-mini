-record(connect, {
	  socket,
	  seqnum = 0,
	  mysql_version,
	  log_fun,
	  reader,
	  buf = <<>>,
	  recv_timeout = 600000,
	  query_started = 0,
	  wait_time = 0
	 }).


