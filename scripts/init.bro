module LogTsvHttp;

export {
       # The endpoint to POST logs to, for example http://my.server.com:8080/zeek
       const url = "" &redef;

       # Optionally ignore any :bro:type:`Log::ID` from being sent
       const exclude_logs: set[Log::ID] &redef;

       # If you want to explicitly only send certain :bro:type:`Log::ID`
       # streams, add them to this set.  If the set remains empty, all will
       # be sent.  The :bro:id:`LogTsvHttp::exclude_logs` option
       # will remain in effect as well.
       const send_logs: set[Log::ID] &redef;
}

