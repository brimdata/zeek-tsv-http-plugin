module LogTsvHttp;

event bro_init() &priority=-10
	{
	if ( url == "" )
		return;

	for ( stream_id in Log::active_streams )
		{
		if ( stream_id in exclude_logs ||
		     (|send_logs| > 0 && stream_id !in send_logs) )
			next;

		local filter: Log::Filter = [$name = "default-http",
		                             $writer = Log::WRITER_TSVHTTP];
		Log::add_filter(stream_id, filter);
		}
	}
