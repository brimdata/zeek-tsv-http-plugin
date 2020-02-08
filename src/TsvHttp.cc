// See the file "COPYING" in the main distribution directory for copyright.

#include <string>
#include <errno.h>
#include <unistd.h>

#include "threading/SerialTypes.h"

#include <curl/curl.h>
#include <curl/easy.h>

#include "Plugin.h"
#include "TsvHttp.h"
#include "tsvhttp.bif.h"

using namespace logging::writer;
using namespace threading;
using threading::Value;
using threading::Field;


size_t TsvHttp::InvokeReadCallback(char *buffer, size_t size, size_t nitems, void *userdata) {

    return ((TsvHttp*)userdata)->CurlReadCallback(buffer, size, nitems);
}


TsvHttp::TsvHttp(WriterFrontend* frontend) : WriterBackend(frontend)
{
    databuf1.Clear();
    databuf2.Clear();
    headerbuf.Clear();
    connstate = CLOSED;
    InitConfigOptions();
    InitFilterOptions();
}

void TsvHttp::InitConfigOptions()
{
    endpoint = BifConst::LogTsvHttp::url->AsString()->CheckString();
}

void TsvHttp::InitFilterOptions()
{
	const WriterInfo& info = Info();

	for ( WriterInfo::config_map::const_iterator i = info.config.begin(); i != info.config.end(); ++i ) {
            if ( strcmp(i->first, "url") == 0 ) {
                endpoint = i->second;
            }
        }
}

bool TsvHttp::InitFormatter()
{

    formatter = 0;
    delete formatter;

    // Use the default "Zeek logs" format.
    databuf1.EnableEscaping();
    databuf1.AddEscapeSequence(separator);
    databuf2.EnableEscaping();
    databuf2.AddEscapeSequence(separator);
    headerbuf.EnableEscaping();
    headerbuf.AddEscapeSequence(separator);

    formatter::Ascii::SeparatorInfo sep_info(separator, set_separator, unset_field, empty_field);
    formatter = new formatter::Ascii(this, sep_info);

    return true;
}

TsvHttp::~TsvHttp()
{
    delete formatter;
}

void TsvHttp::WriteHeaderField(const string& key, const string& val)
{
    string str = meta_prefix + key + separator + val + "\n";
    headerbuf.AddRaw(str);
}




bool TsvHttp::CurlConnect()
{
    if ( curl ) {
        CURLMcode mres = curl_multi_remove_handle(mcurl, curl);
        if (mres != CURLM_OK) {
            Error(Fmt("curl_multi_add_handle() failed: %s", curl_multi_strerror(mres)));
            return false;
        }
        curl_easy_cleanup(curl);
    }

    curl = curl_easy_init();
    if ( ! curl ) {
        Error("curl_easy_init() failed");
        return false;
    }

    CurlSetopts();

    CURLMcode mres = curl_multi_add_handle(mcurl, curl);
    if ( mres != CURLM_OK) {
        Error(Fmt("curl_multi_add_handle() failed: %s", curl_multi_strerror(mres)));
        return false;
    }

    connstate=SENDING_HEADER;
    if (!CurlSendHeader()) {
        connstate=WAITING;
        return false;
    }
    connstate=SENDING_DATA;
    return true;
}

void TsvHttp::CurlSetopts()
{


    PLUGIN_DBG_LOG(plugin::Zeek_TsvHttp::plugin, "Endpoint: %s", endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());

    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, TsvHttp::InvokeReadCallback);
    curl_easy_setopt(curl, CURLOPT_READDATA, this);
    // curl_easy_setopt(curl, CURLOPT_UPLOAD_BUFFERSIZE, 16384L); commented pending selecting min version in cmakelists
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, http_headers);

    // will probably want to set these too (like ES plugin)
    // curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1);
    // curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, transfer_timeout);
    // curl_easy_setopt(handle, CURLOPT_TIMEOUT, transfer_timeout);
    // curl_easy_setopt(handle, CURLOPT_DNS_CACHE_TIMEOUT, 60*60);

}


size_t TsvHttp::CurlReadCallback(char *dest, size_t size, size_t nitems)
{
    size_t n_read = 0;
    size_t max_read = size * nitems;
    cb_done = true;

    if (connstate == FINISHING) {
        return 0;
    }

    if (!read_sizeleft) {
        Error(Fmt("CurlReadCallback called with read_sizeleft=0"));
        return 0;
    }

    /* copy as much as possible from the source to the destination */
    n_read = read_sizeleft;
    if(n_read > max_read)
        n_read = max_read;
    memcpy(dest, read_ptr, n_read);

    read_ptr += n_read;
    read_sizeleft -= n_read;
    PLUGIN_DBG_LOG(plugin::Zeek_TsvHttp::plugin, "TsvHttp::CurlReadCallback read %zu bytes, %d bytes left", n_read, read_sizeleft);
    return n_read;
}

void TsvHttp::SwitchBuffers()
{
    ODesc* tmp = read_buffer;
    read_buffer = write_buffer;
    write_buffer = tmp;

    read_sizeleft = read_buffer->Len();
    read_ptr = read_buffer->Bytes();
}

bool TsvHttp::DoInit(const WriterInfo& info, int num_fields, const Field* const * fields)
{

    InitFormatter();

    read_buffer = &databuf1;
    write_buffer = &databuf2;
    read_sizeleft = 0;

    // xxx not thread safe
    CURLcode res = curl_global_init(CURL_GLOBAL_NOTHING); // will likely want to init SSL here at some point

    if(res != CURLE_OK) {
        PLUGIN_DBG_LOG(plugin::Zeek_TsvHttp::plugin, "curl_global_init() failed: %s", curl_easy_strerror(res));
        return false;
    }

    http_headers = curl_slist_append(NULL, "Transfer-Encoding: chunked");
    if (http_headers == NULL) {
        Error("curl_slist_append() failed, TsvHttp plugin not starting");
        return false;
    }

    // Add an empty Expect header to prevent libcurl from
    // automatically adding "Expect: 100-continue", as it does with
    // chunked transfers
    http_headers = curl_slist_append(http_headers, "Expect:");
    if (http_headers == NULL) {
        Error("curl_slist_append() failed, TsvHttp plugin not starting");
        return false;
    }

    mcurl = curl_multi_init();
    if ( ! mcurl ) {
        Error("curl_multi_init() failed");
        return false;
    }

    path = info.path;
    WriteHeader(path);

    CurlConnect();

    Info(Fmt("running version %d.%d", version_major, version_minor));
    return true;
}

bool TsvHttp::CurlSendData() {
    int running_handles=-1;

    if (connstate != SENDING_DATA) {
        Error(Fmt("Unexpected connstate %d when sending data", connstate));
        return false;
    }

    while (read_sizeleft) {
        // Each invocation of curl_multi_perform leads to a read
        // callback, as long as the underlying HTTP connection is
        // available.  We repeat the loop until our read buffer
        // drains, unless we don't get a callback, indicating that the
        // underlying connection is unavailable, in which case we drop
        // the current buffer and return.
        // (It might be unavailable because we are still connecting,
        // or because the underlying socket write buffer is full).
        cb_done=false;
        CURLMcode mres = curl_multi_perform(mcurl, &running_handles);
        PLUGIN_DBG_LOG(plugin::Zeek_TsvHttp::plugin, "curl_multi_perform done, running handles %d", running_handles);
        if(mres != CURLM_OK) {
            Error(Fmt("curl_multi_perform() failed: %s", curl_multi_strerror(mres)));
            return false;
        }

        if (running_handles == 0) {
            if (read_sizeleft)
                Warning(Fmt("dropping %d bytes due to transfer interruption\n", read_sizeleft));

            read_sizeleft = 0;
            read_buffer->Clear();
            connstate=CLOSED;
            return true;
        }

        if (!cb_done) {
            Warning(Fmt("dropping %d bytes due to write buffer full\n", read_sizeleft));
            read_sizeleft=0;
            read_buffer->Clear();
            return true;
        }

    }

    PLUGIN_DBG_LOG(plugin::Zeek_TsvHttp::plugin, "Read buffer drained");
    read_buffer->Clear();

    return true;
}

bool TsvHttp::CurlSendHeader() {
    int running_handles=-1;
    read_sizeleft = headerbuf.Len();
    read_ptr = headerbuf.Bytes();

    // TODO: We should probably do a curl_multi_wait before this loop, to
    // avoid busy-looping during connection setup.
    while (read_sizeleft) {
        CURLMcode mres = curl_multi_perform(mcurl, &running_handles);
        PLUGIN_DBG_LOG(plugin::Zeek_TsvHttp::plugin, "curl_multi_perform done, running handles %d", running_handles);
        if(mres != CURLM_OK) {
            Error(Fmt("curl_multi_perform() failed: %s", curl_multi_strerror(mres)));
            read_sizeleft = 0;
            return false;
        }

        if (running_handles == 0) {
            Info(Fmt("No connection or transfer interrupted while sending header. Will try to reconnect later."));
            read_sizeleft = 0;
            return false;
        }
    }
    read_sizeleft = 0;
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        Warning(Fmt("response code %ld\n", response_code));

    return true;
}

void TsvHttp::WriteHeader(const string& path)
{

    string names;
    string types;

    for ( int i = 0; i < NumFields(); ++i )
        {
            if ( i > 0 )
                {
                    names += separator;
                    types += separator;
                }

            names += string(Fields()[i]->name);
            types += Fields()[i]->TypeName().c_str();
        }

    string str = meta_prefix
        + "separator " // Always use space as separator here.
        + get_escaped_string(separator, false)
        + "\n";

    headerbuf.AddRaw(str);

    WriteHeaderField("set_separator", get_escaped_string(set_separator, false));
    WriteHeaderField("empty_field", get_escaped_string(empty_field, false));
    WriteHeaderField("unset_field", get_escaped_string(unset_field, false));
    WriteHeaderField("path", get_escaped_string(path, false));
    WriteHeaderField("open", Timestamp(0));

    WriteHeaderField("fields", names);
    WriteHeaderField("types", types);
}

/**
 * Writer-specific method implementing flushing of its output.	A writer
 * implementation must override this method but it can just
 * ignore calls if flushing doesn't align with its semantics.
 */
bool TsvHttp::DoFlush(double network_time)
{
    if (connstate == SENDING_DATA) {
        SwitchBuffers();
        CurlSendData();
    }
    return true;
}

/**
 * Writer-specific method called just before the threading system is
 * going to shutdown. It is assumed that once this messages returns,
 * the thread can be safely terminated.
 */
bool TsvHttp::DoFinish(double network_time)
{
    int running_handles=-1;
    Info("DoFinish");
    DoFlush(network_time);
    connstate = FINISHING;
    // callback will return 0, signaling curl library to send final zero-length chunk.
    CURLMcode mres = curl_multi_perform(mcurl, &running_handles);
    curl_slist_free_all(http_headers);

    // cleanup order as per https://curl.haxx.se/libcurl/c/curl_multi_cleanup.html
    curl_multi_remove_handle(mcurl, curl);
    curl_easy_cleanup(curl);
    curl_multi_cleanup(mcurl);

    return true;
}

/**
 * Writer-specific output method implementing recording of one log
 * entry.
 */
bool TsvHttp::DoWrite(int num_fields, const Field* const * fields,
                         Value** vals)
{
    PLUGIN_DBG_LOG(plugin::Zeek_TsvHttp::plugin, "TsvHttp::DoWrite()");

    if (connstate == SENDING_HEADER || connstate == FINISHING) {
        Error(Fmt("Unexpected connstate %d in DoWrite", connstate));
        return false;
    }
    if (connstate == CLOSED) {
        if (!CurlConnect()) {
            return true;
        }
    }

    // connstate is either WAITING or SENDING_DATA at this point.
    if (write_buffer->Len() > (1 << 12)) {
        if (read_sizeleft) {
            Warning(Fmt("dropping data in DoWrite(): write buffer full (size %d) before read buffer drained (size %d, still %d left)",
                        write_buffer->Len(), read_buffer->Len(), read_sizeleft));
            return true;
        }
        if (connstate == WAITING) {
            // don't log anything here because we would log too much when disconnected (once per event)
            return true;
        }

        PLUGIN_DBG_LOG(plugin::Zeek_TsvHttp::plugin, "TsvHttp::DoWrite() write buffer reached limit, sending");

        SwitchBuffers();

        // if this fails and we return false, the plugin is disabled (and will be eventually discarded).
        if (!CurlSendData())
            return false;
    }

    if ( ! formatter->Describe(write_buffer, num_fields, fields, vals) )
        return false;
    write_buffer->AddRaw("\n", 1);

    return true;
}

/**
 * Writer-specific method implementing log rotation.	Most directly
 * this only applies to writers writing into files, which should then
 * close the current file and open a new one.	However, a writer may
 * also trigger other apppropiate actions if semantics are similar.
 * Once rotation has finished, the implementation *must* call
 * FinishedRotation() to signal the log manager that potential
 * postprocessors can now run.
 */
bool TsvHttp::DoRotate(const char* rotated_path, double open, double close, bool terminating)
{
    // this is no-op as we're not a file writer
    return FinishedRotation();
}

/**
 * Writer-specific method implementing a change of fthe buffering
 * state.	If buffering is disabled, the writer should attempt to
 * write out information as quickly as possible even if doing so may
 * have a performance impact. If enabled (which is the default), it
 * may buffer data as helpful and write it out later in a way
 * optimized for performance. The current buffering state can be
 * queried via IsBuf().
 */
bool TsvHttp::DoSetBuf(bool enabled)
{
    // Nothing to do.
    return true;
}

/**
 * Triggered by regular heartbeat messages from the main thread.
 */
bool TsvHttp::DoHeartbeat(double network_time, double current_time)
{
    if (connstate == WAITING) {
        connstate = CLOSED;
    } else if (connstate == SENDING_DATA) {
        SwitchBuffers();
        CurlSendData();
    }
    return true;
}


string TsvHttp::Timestamp(double t)
{
    time_t teatime = time_t(t);

    if ( ! teatime )
        {
            // Use wall clock.
            struct timeval tv;
            if ( gettimeofday(&tv, 0) < 0 )
                Error("gettimeofday failed");
            else
                teatime = tv.tv_sec;
        }

    struct tm tmbuf;
    struct tm* tm = localtime_r(&teatime, &tmbuf);

    char tmp[128];
    const char* const date_fmt = "%Y-%m-%d-%H-%M-%S";
    strftime(tmp, sizeof(tmp), date_fmt, tm);

    return tmp;
}


