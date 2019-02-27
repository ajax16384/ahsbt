/*
 * Copyright (C) 2019 Andrei Kurushin
 * For conditions of distribution and use, see copyright notice in LICENSE
 */

#include <iostream>
#include <chrono>
#include <thread>
#include <iomanip>
#include <vector>
#include <list>
#include <string>
#include <mutex>
#include <cstdint>
#include <atomic>

#include <curl/curl.h>

#if LIBCURL_VERSION_NUM < 0x073a00
#error "upgrade your libcurl to no less than 7.58.0"
#endif

using duration_seconds = std::chrono::duration<double>;
using time_provider = std::chrono::high_resolution_clock;

struct SCURLConnectionData {
  CURL *easyHandle{ nullptr };
  bool sent{ false };
  time_provider::time_point startMoment;
};

struct SThreadData {
  std::size_t totalRequestsCount{ 0 };
  std::size_t transferErrorRequestsCount{ 0 };
  std::size_t responseErrorRequestsCount{ 0 };

  duration_seconds totalRequestsDuration{ 0 };
  duration_seconds minRequestDuration{ 0 };
  duration_seconds maxRequestDuration{ 0 };

  void UpdateDuration(const duration_seconds &duration) {
    if (minRequestDuration > duration) {
      minRequestDuration = duration;
    }
    if (maxRequestDuration < duration) {
      maxRequestDuration = duration;
    }
    totalRequestsDuration += duration;
  }

  void Add(const SThreadData &val) {
    totalRequestsCount += val.totalRequestsCount;
    transferErrorRequestsCount += val.transferErrorRequestsCount;
    responseErrorRequestsCount += val.responseErrorRequestsCount;
    totalRequestsDuration += val.totalRequestsDuration;

    if (minRequestDuration > val.minRequestDuration) {
      minRequestDuration = val.minRequestDuration;
    }
    if (maxRequestDuration < val.maxRequestDuration) {
      maxRequestDuration = val.maxRequestDuration;
    }
  }
};

std::mutex printMutex;
std::string selfName;

const std::size_t defaultOptRequestsCount = 2;
const std::size_t defaultOptConnectionsCount = 2;
const std::size_t defaultOptThreadsCount = 2;
std::atomic_intptr_t globalRequestsLeft;

void PrintCURLCode(const char *context, CURLcode code) {
  std::lock_guard<std::mutex> lock(printMutex);
  if (nullptr != context) {
    std::cerr << context;
  }
  std::cerr << "CURL code=" << code;
  const char *str = curl_easy_strerror(code);
  if (nullptr != str) {
    std::cerr << " str=" << str;
  }
  std::cerr << "\n";
}

void PrintCURLMcode(const char *context, CURLMcode code) {
  std::lock_guard<std::mutex> lock(printMutex);
  if (nullptr != context) {
    std::cerr << context;
  }
  std::cerr << "CURLM code=" << code;
  const char *str = curl_multi_strerror(code);
  if (nullptr != str) {
    std::cerr << " str=" << str;
  }
  std::cerr << "\n";
}

void PrintUsage() {
  std::lock_guard<std::mutex> lock(printMutex);
  std::cout << "Usage: " << selfName << " [option...] url\n";
  std::cout << "Options:\n";
  std::cout << "  --requests       overall requests count (default: " << defaultOptRequestsCount << ")\n";
  std::cout << "  --connections    concurrent connections count per single thread (default: " << defaultOptConnectionsCount << ")\n";
  std::cout << "  --threads        concurrent threads count (default: " << defaultOptThreadsCount << ")\n";
  std::cout << "  --noreuse        forbid reuse connection (default: false)\n";
  std::cout << "  --insecure       disable SSL peer and host verification (default: false)\n";
  std::cout << "  --fastopen       enable TCP Fast Open (default: false)\n";
  std::cout << "  --tcpnagle       enable TCP Nagle (default: false)\n";
  std::cout << "  --verbose        verbose information will be sent to stderr (default: false)\n";  
  std::cout << "  --http           enforce http version (default: none)\n";
  std::cout << "                   1      - HTTP 1.0\n";
  std::cout << "                   1.1    - HTTP 1.1\n";
  std::cout << "                   2      - HTTP 2\n";
  std::cout << "                   2tls   - HTTP 2 for HTTPS, HTTP 1.1 for HTTP\n";
  std::cout << "                   2prior - HTTP 2 without HTTP/1.1 Upgrade\n";
  std::cout << "\n";
  std::cout << "Examples:\n";
  std::cout << "  " << selfName << " --threads=4 --requests=10000 http://example.com/\n";
}

static size_t EmptyWriteFunction(void *ptr, size_t size, size_t nmemb, void *data) {
  return size * nmemb;
}

void ThreadMethod(SThreadData *data,
  const char  *url,
  std::size_t connectionsCount,
  std::size_t requestsCount,
  bool noReuse,
  bool insecure,
  bool TCPFastOpen,
  bool TCPNagle,
  bool verbose,
  long httpVersion
) {

  CURLM *multiCurlHandle;
  multiCurlHandle = curl_multi_init();
  if (nullptr == multiCurlHandle) {
    abort();
  }


  std::vector<SCURLConnectionData> connections;
  connections.resize(connectionsCount);
  for (auto &connection : connections) {
    connection.easyHandle = nullptr;
    connection.sent = false;
  }

  int stillRunning;
  int numFDs;
  int msgLeft;
  CURLMcode mcode;
  CURLcode code;


  // try HTTP/1 pipelining and HTTP/2 multiplexing
  mcode = curl_multi_setopt(multiCurlHandle, CURLMOPT_PIPELINING, (CURLPIPE_HTTP1 | CURLPIPE_MULTIPLEX));
  if (CURLM_OK != mcode) {
    PrintCURLMcode("curl_multi_setopt CURLMOPT_PIPELINING", mcode);
    abort();
  }

  struct curl_slist *httpHeaderList = nullptr;
  if (noReuse) {
      httpHeaderList = curl_slist_append(httpHeaderList, "Connection: close");
  }

  for (;;) {
    std::size_t drainedConnectionsCount = 0;
    for (auto &connection : connections) {
      if (connection.sent) {
        continue;
      }

      auto requestsLeft = globalRequestsLeft.fetch_sub(1);
      if (0 >= requestsLeft) {
        drainedConnectionsCount++;
        continue;
      }

      if (nullptr == connection.easyHandle) {
        connection.easyHandle = curl_easy_init();
        if (nullptr == connection.easyHandle) {
          abort();
        }

        // since we are multi-thread: https://curl.haxx.se/libcurl/c/threadsafe.html
        code = curl_easy_setopt(connection.easyHandle, CURLOPT_NOSIGNAL, 1L);
        if (CURLE_OK != code) {
          PrintCURLCode("curl_easy_setopt CURLOPT_NOSIGNAL", code);
          abort();
        }

        code = curl_easy_setopt(connection.easyHandle, CURLOPT_HTTP_VERSION, httpVersion);
        if (CURLE_OK != code) {
          PrintCURLCode("curl_easy_setopt CURLOPT_HTTP_VERSION", code);
          abort();
        }

        code = curl_easy_setopt(connection.easyHandle, CURLOPT_NOPROXY, "*");
        if (CURLE_OK != code) {
          PrintCURLCode("curl_easy_setopt CURLOPT_NOPROXY", code);
          abort();
        }

        if (TCPFastOpen) {
          code = curl_easy_setopt(connection.easyHandle, CURLOPT_TCP_FASTOPEN, 1L);
          if (CURLE_OK != code) {
            PrintCURLCode("curl_easy_setopt CURLOPT_TCP_FASTOPEN", code);
            abort();
          }
        }

        if (TCPNagle) {
          code = curl_easy_setopt(connection.easyHandle, CURLOPT_TCP_NODELAY, 0L);
          if (CURLE_OK != code) {
            PrintCURLCode("curl_easy_setopt CURLOPT_TCP_NODELAY", code);
            abort();
          }
        }

        if (verbose) {
          code = curl_easy_setopt(connection.easyHandle, CURLOPT_VERBOSE, 1L);
          if (CURLE_OK != code) {
            PrintCURLCode("curl_easy_setopt CURLOPT_VERBOSE", code);
            abort();
          }
        }

        if (noReuse) {
          code = curl_easy_setopt(connection.easyHandle, CURLOPT_FORBID_REUSE, 1L);
          if (CURLE_OK != code) {
            PrintCURLCode("curl_easy_setopt CURLOPT_FORBID_REUSE", code);
            abort();
          }
        }

        if (nullptr != httpHeaderList) {
          code = curl_easy_setopt(connection.easyHandle, CURLOPT_HTTPHEADER, httpHeaderList);
          if (CURLE_OK != code) {
            PrintCURLCode("curl_easy_setopt CURLOPT_HTTPHEADER", code);
            abort();
          }
        }

        if (insecure) {
          code = curl_easy_setopt(connection.easyHandle, CURLOPT_SSL_VERIFYPEER, 0L);
          if (CURLE_OK != code) {
            PrintCURLCode("curl_easy_setopt CURLOPT_SSL_VERIFYPEER", code);
            abort();
          }
          code = curl_easy_setopt(connection.easyHandle, CURLOPT_SSL_VERIFYHOST, 0L);
          if (CURLE_OK != code) {
            PrintCURLCode("curl_easy_setopt CURLOPT_SSL_VERIFYHOST", code);
            abort();
          }
        }

        code = curl_easy_setopt(connection.easyHandle, CURLOPT_PRIVATE, &connection);
        if (CURLE_OK != code) {
          PrintCURLCode("curl_easy_setopt CURLOPT_PRIVATE", code);
          abort();
        }

        code = curl_easy_setopt(connection.easyHandle, CURLOPT_WRITEFUNCTION, EmptyWriteFunction);
        if (CURLE_OK != code) {
          PrintCURLCode("curl_easy_setopt CURLOPT_WRITEFUNCTION", code);
          abort();
        }

        code = curl_easy_setopt(connection.easyHandle, CURLOPT_URL, url);
        if (CURLE_OK != code) {
          PrintCURLCode("curl_easy_setopt CURLOPT_URL", code);
          abort();
        }
      }

      mcode = curl_multi_add_handle(multiCurlHandle, connection.easyHandle);
      if (CURLM_OK != mcode) {
        PrintCURLMcode("curl_multi_add_handle", mcode);
        abort();
      }

      connection.sent = true;
      connection.startMoment = time_provider::now();
    }

    if (drainedConnectionsCount == connectionsCount) {
      break;
    }

    mcode = curl_multi_wait(multiCurlHandle, NULL, 0, 1000, &numFDs);
    if (CURLM_OK != mcode) {
      PrintCURLMcode("curl_multi_wait", mcode);
      break;
    }

    do {
      mcode = curl_multi_perform(multiCurlHandle, &stillRunning);
    } while (CURLM_CALL_MULTI_PERFORM == mcode);

    if (CURLM_OK != mcode) {
      PrintCURLMcode("curl_multi_perform", mcode);
      break;
    }

    CURLMsg *msg = nullptr;
    while ((msg = curl_multi_info_read(multiCurlHandle, &msgLeft))) {
      if (CURLMSG_DONE == msg->msg) {
        CURL *handle = msg->easy_handle;

        SCURLConnectionData *connection;
        code = curl_easy_getinfo(handle, CURLINFO_PRIVATE, &connection);
        if (CURLE_OK != code) {
          PrintCURLCode("curl_easy_getinfo CURLINFO_PRIVATE", code);
          abort();
        }
        data->totalRequestsCount++;

        time_provider::time_point finishMoment = time_provider::now();
        duration_seconds duration = finishMoment - connection->startMoment;
        data->UpdateDuration(duration);

        if (msg->data.result == CURLE_OK) {
          long responseStatus;
          code = curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &responseStatus);
          if (CURLE_OK != code) {
            PrintCURLCode("curl_easy_getinfo CURLINFO_RESPONSE_CODE", code);
            abort();
          }
          if (responseStatus != 200) {
            data->responseErrorRequestsCount++;
          }
        }
        else {
          data->transferErrorRequestsCount++;
        }

        mcode = curl_multi_remove_handle(multiCurlHandle, connection->easyHandle);
        if (mcode != CURLM_OK) {
          PrintCURLMcode("curl_multi_remove_handle", mcode);
          abort();
        }
        connection->sent = false;
        /*
        curl_easy_cleanup(connection->easyHandle);
        connection->easyHandle = nullptr;
        */
      }
    }
  }


  for (auto connection : connections) {
    if (nullptr != connection.easyHandle) {
      curl_easy_cleanup(connection.easyHandle);
    }
  }

  if (nullptr != httpHeaderList) {
    curl_slist_free_all(httpHeaderList);
  }
  curl_multi_cleanup(multiCurlHandle);
}

bool IfStartsWith(const std::string &sample, const std::string &value, std::string &result) {
  if (value.substr(0, sample.size()).compare(sample) == 0) {
    result = value.substr(sample.size());
    return true;
  }
  return false;
}

std::size_t optRequestsCount = defaultOptRequestsCount;
std::size_t optConnectionsCount = defaultOptConnectionsCount;
std::size_t optThreadsCount = defaultOptThreadsCount;
bool optNoReuse = false;
bool optInsecure = false;
bool optTCPFastOpen = false;
bool optTCPNagle = false;
bool optVerbose = false;
long optHttpVersion = CURL_HTTP_VERSION_NONE;
std::string optHttpVersionStr = "";
std::string commandUrl = "";

std::size_t GetPositiveValue(const std::string &value) {
  int intVal = std::stoi(value);
  if (intVal < 1) {
    throw std::invalid_argument("value < 1");
  }
  return static_cast<std::size_t>(intVal);
}

bool ParseCommandLine(int argc, char *argv[]) {
  std::list<std::string> commands;
  std::list<std::string> options;
  for (int i = 1; i < argc; ++i) {
    std::string currentArg;
    if (nullptr == argv[i]) {
      continue;
    }
    currentArg = argv[i];
    if (currentArg.empty()) {
      continue;
    }
    std::string option;
    if (IfStartsWith("--", currentArg, option)) {
      if (option.empty()) {
        continue;
      }
      options.push_back(option);
    }
    else {
      commands.push_back(currentArg);
    }
  }

  for (const auto &option : options) {
    std::string value;
    try {
      if (option.compare("noreuse") == 0) {
        optNoReuse = true;
      }
      else if (option.compare("insecure") == 0) {
        optInsecure = true;
      }
      else if (option.compare("fastopen") == 0) {
        optTCPFastOpen = true;
      }
      else if (option.compare("tcpnagle") == 0) {
        optTCPNagle = true;
      }
      else if (option.compare("verbose") == 0) {
        optVerbose = true;
      }
      else if (IfStartsWith("http=", option, optHttpVersionStr)) {
        if (optHttpVersionStr.compare("none") == 0) {
          optHttpVersion = CURL_HTTP_VERSION_NONE;
        }
        else if (optHttpVersionStr.compare("1") == 0) {
          optHttpVersion = CURL_HTTP_VERSION_1_0;
        }
        else if (optHttpVersionStr.compare("1.1") == 0) {
          optHttpVersion = CURL_HTTP_VERSION_1_1;
        }
        else if (optHttpVersionStr.compare("2") == 0) {
          optHttpVersion = CURL_HTTP_VERSION_2_0;
        }
        else if (optHttpVersionStr.compare("2tls") == 0) {
          optHttpVersion = CURL_HTTP_VERSION_2TLS;
        }
        else if (optHttpVersionStr.compare("2prior") == 0) {
          optHttpVersion = CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE;
        }
        else {
          throw std::invalid_argument("Unknown http value");
        }
      }
      else if (IfStartsWith("requests=", option, value)) {
        optRequestsCount = GetPositiveValue(value);
      }
      else if (IfStartsWith("connections=", option, value)) {
        optConnectionsCount = GetPositiveValue(value);
      }
      else if (IfStartsWith("threads=", option, value)) {
        optThreadsCount = GetPositiveValue(value);
      }
      else {
        throw std::invalid_argument("Unknown option");
      }
    }
    catch (const std::exception& e) {
      std::cerr << "Wrong option: " << option << "\n";
      std::cerr << "Exception: " << e.what() << "\n";
      return false;
    }
  }
  if (commands.size() != 1) {
    return false;
  }
  commandUrl = commands.front();
  return true;
}

int main(int argc, char *argv[], char *envp[])
{
  std::cout << "Another HTTP Server Benchmark Test 0.1\n";
  if (argc > 0) {
    selfName = argv[0];
  }

  if (!ParseCommandLine(argc, argv)) {
    PrintUsage();
    exit(1);
  }


  CURLcode code = curl_global_init(CURL_GLOBAL_ALL);
  if (CURLE_OK != code) {
    PrintCURLCode("curl_global_init", code);
    abort();
  }

  const char *curlVersionStr = curl_version();
  if (nullptr != curlVersionStr) {
    std::cout << "Using " << curlVersionStr << "\n";
  }

  std::vector<SThreadData> threadDatas;
  std::list<std::thread> threads;
  SThreadData allData;

  threadDatas.resize(optThreadsCount);

  int intPadSize;
  int floatPadSize;

  intPadSize = 8;
  floatPadSize = 6;

  std::cout << "\n" << std::setfill(' ');
  std::cout << "Url: " << commandUrl << "\n";
  if (optNoReuse) {
    std::cout << "No Reuse\n";
  }
  if (optInsecure) {
    std::cout << "Insecure\n";
  }
  if (optTCPFastOpen) {
    std::cout << "TCP Fast Open\n";
  }
  if (optTCPNagle) {
    std::cout << "TCP Nagle\n";
  }
  if (optVerbose) {
    std::cout << "Verbose\n";
  }
  if (!optHttpVersionStr.empty()) {
    std::cout << "Http: " << optHttpVersionStr << "\n";
  }
  std::cout << "Connections count:     " << std::setw(intPadSize) << optConnectionsCount << "\n";
  std::cout << "Requests count:        " << std::setw(intPadSize) << optRequestsCount << "\n";
  std::cout << "Threads count:         " << std::setw(intPadSize) << optThreadsCount << "\n";
  std::cout << "\nTesting ...\n";

  globalRequestsLeft = static_cast<std::intptr_t>(optRequestsCount);

  time_provider::time_point startMoment = time_provider::now();
  for (std::size_t i = 0; i < optThreadsCount; ++i) {
    threads.push_back(std::thread(&ThreadMethod, &threadDatas[i],
      commandUrl.c_str(),
      optConnectionsCount,
      optRequestsCount,
      optNoReuse,
      optInsecure,
      optTCPFastOpen,
      optTCPNagle,
      optVerbose,
      optHttpVersion
    ));
  }

  for (auto& thread : threads) {
    thread.join();
  }

  time_provider::time_point finishMoment = time_provider::now();
  duration_seconds totalDuration = finishMoment - startMoment;

  for (const auto& threadData : threadDatas) {
    allData.Add(threadData);
  }


  if (allData.totalRequestsCount != 0) {

    double transferErrorPercent = (static_cast<double>(allData.transferErrorRequestsCount) / static_cast<double>(allData.totalRequestsCount) * 100.0);
    double responseErrorPercent = (static_cast<double>(allData.responseErrorRequestsCount) / static_cast<double>(allData.totalRequestsCount) * 100.0);
    duration_seconds avgRequestDuration = allData.totalRequestsDuration / allData.totalRequestsCount;

    std::cout << "\n" << std::setfill(' ');
    std::cout << "Total requests count:  " << std::setw(intPadSize) << allData.totalRequestsCount << "\n";
    std::cout << "Transfer errors count: " << std::setw(intPadSize) << allData.transferErrorRequestsCount
      << " [ " << std::fixed << std::setw(floatPadSize) << std::setprecision(2) << transferErrorPercent << "% ]\n";
    std::cout << "Response errors count: " << std::setw(intPadSize) << allData.responseErrorRequestsCount
      << " [ " << std::fixed << std::setw(floatPadSize) << std::setprecision(2) << responseErrorPercent << "% ]\n";
    std::cout << "Min request time:      " << std::fixed << std::setw(intPadSize) << std::setprecision(2) << allData.minRequestDuration.count()
      << " sec\n";
    std::cout << "Avg request time:      " << std::fixed << std::setw(intPadSize) << std::setprecision(2) << avgRequestDuration.count()
      << " sec\n";
    std::cout << "Max request time:      " << std::fixed << std::setw(intPadSize) << std::setprecision(2) << allData.maxRequestDuration.count()
      << " sec\n";

    std::cout << "Measured total time:   " << std::fixed << std::setw(intPadSize) << std::setprecision(2) << totalDuration.count()
      << " sec\n";

    if (totalDuration.count() != 0) {
      double requestsPerSec = static_cast<double>(allData.totalRequestsCount) / totalDuration.count();
      std::cout << "Requests per second:   " << std::fixed << std::setw(intPadSize) << std::setprecision(2) << requestsPerSec << "\n";
    }
    
  }

  curl_global_cleanup();
  return 0;
}
