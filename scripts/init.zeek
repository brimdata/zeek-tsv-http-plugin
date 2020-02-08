module LogTsvHttp;

export {
       # The endpoint to POST logs to, for example http://my.server.com:8080/zeek
       const url = "" &redef;

       # Optionally ignore any :zeek:type:`Log::ID` from being sent
       const exclude_logs: set[Log::ID] &redef;

       # If you want to explicitly only send certain :zeek:type:`Log::ID`
       # streams, add them to this set.  If the set remains empty, all will
       # be sent.  The :zeek:id:`LogTsvHttp::exclude_logs` option
       # will remain in effect as well.
       const send_logs: set[Log::ID] &redef;
}

