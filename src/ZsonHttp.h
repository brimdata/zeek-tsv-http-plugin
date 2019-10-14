// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ZEEK_PLUGIN_ZSONHTTP_H
#define ZEEK_PLUGIN_ZSONHTTP_H

#include <curl/curl.h>

#include "logging/WriterBackend.h"
#include "threading/formatters/Ascii.h"
#include "zlib.h"

const int version_major=0;
const int version_minor=3;

namespace logging { namespace writer {

        class ZsonHttp : public WriterBackend {
        public:
            explicit ZsonHttp(WriterFrontend* frontend);
            ~ZsonHttp() override;

            static WriterBackend* Instantiate(WriterFrontend* frontend)
            { return new ZsonHttp(frontend); }

        protected:
            bool DoInit(const WriterInfo& info, int num_fields,
                        const threading::Field* const* fields) override;
            bool DoWrite(int num_fields, const threading::Field* const* fields,
                         threading::Value** vals) override;
            bool DoSetBuf(bool enabled) override;
            bool DoRotate(const char* rotated_path, double open,
                          double close, bool terminating) override;
            bool DoFlush(double network_time) override;
            bool DoFinish(double network_time) override;
            bool DoHeartbeat(double network_time, double current_time) override;

        private:
            enum ConnectionState {
                           CLOSED = 0,
                           WAITING = 1,
                           SENDING_HEADER = 2,
                           SENDING_DATA = 3,
                           FINISHING = 4
            };
            int connstate;

            void InitConfigOptions();
            void InitFilterOptions();

            void WriteHeader(const string& path);
            void WriteHeaderField(const string& key, const string& value);
            string Timestamp(double t); // Uses current time if t is zero.
            bool InitFormatter();

            void CurlSetopts();
            bool CurlConnect();
            bool CurlSendData();
            bool CurlSendHeader();
            static size_t InvokeReadCallback(char *buffer, size_t size, size_t nitems, void *userdata);
            size_t CurlReadCallback(char *buffer, size_t size, size_t nitems);
            void SwitchBuffers();

            ODesc databuf1, databuf2, headerbuf;
            ODesc* write_buffer, *read_buffer;
            const u_char* read_ptr;
            unsigned int read_sizeleft;
            bool cb_done;

            CURLM* mcurl = NULL;
            CURL* curl = NULL;
            struct curl_slist *http_headers;

            // hardcoded defaults from Ascii logwriter
            const string separator = "\t";
            const string set_separator = ",";
            const string empty_field = "(empty)";
            const string unset_field = "-";
            const string meta_prefix = "#";

            string endpoint;
            string path;

            threading::formatter::Formatter* formatter;
        };
    }
}


#endif
