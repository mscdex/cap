#include <node.h>
#include <node_buffer.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
# define snprintf _snprintf
  // from: http://memset.wordpress.com/2010/10/09/inet_ntop-for-win32/
  const char* inet_ntop(int af, const void* src, char* dst, int cnt) {
    struct sockaddr_in srcaddr;
    memset(&srcaddr, 0, sizeof(struct sockaddr_in));
    memcpy(&(srcaddr.sin_addr), src, sizeof(srcaddr.sin_addr));
    srcaddr.sin_family = af;
    if (WSAAddressToString((struct sockaddr*) &srcaddr,
                           sizeof(struct sockaddr_in), 0, dst, (LPDWORD)
                           &cnt) != 0) {
      DWORD rv = WSAGetLastError();
      return NULL;
    }
    return dst;
  }
#else
# include <arpa/inet.h>
# include <sys/ioctl.h>
#endif

using namespace node;
using namespace v8;

static Persistent<FunctionTemplate> Pcap_constructor;
static Persistent<String> emit_symbol;
static Persistent<String> packet_symbol;
static Persistent<String> close_symbol;

void SetAddrStringHelper(const char* key, sockaddr *addr,
                         Local<Object> Address) {
  if (key && addr) {
    char dst_addr[INET6_ADDRSTRLEN + 1] = {0};
    char* src = 0;
    socklen_t size = 0;
    if (addr->sa_family == AF_INET) {
      struct sockaddr_in* saddr = (struct sockaddr_in*) addr;
      src = (char*) &(saddr->sin_addr);
      size = INET_ADDRSTRLEN;
    } else {
      struct sockaddr_in6* saddr6 = (struct sockaddr_in6*) addr;
      src = (char*) &(saddr6->sin6_addr);
      size = INET6_ADDRSTRLEN;
    }
    const char* address = inet_ntop(addr->sa_family, src, dst_addr, size);
    Address->Set(String::New(key), String::New(address));
  }
}

class Pcap : public ObjectWrap {
  public:
    Persistent<Function> Emit;

#ifdef _WIN32
    HANDLE wait;
    //uv_mutex_t mutex;
    uv_async_t async;
#else
    uv_poll_t poll_handle;
    int fd;
#endif
    pcap_t *pcap_handle;

    char *buffer_data;
    size_t buffer_length;

    Pcap() {
      pcap_handle = NULL;
      buffer_data = NULL;
      buffer_length = 0;
#ifdef _WIN32
      wait = NULL;
#endif
    }

    ~Pcap() {
      close();
      Emit.Dispose();
      Emit.Clear();
    }

    bool close() {
      if (pcap_handle) {
#ifdef _WIN32
        if (wait) {
          UnregisterWait(wait);
          wait = NULL;
        }
        //uv_mutex_destroy(&mutex);
        uv_close((uv_handle_t*)&async, cb_close);
#else
        uv_poll_stop(&poll_handle);
#endif
        pcap_close(pcap_handle);
        pcap_handle = NULL;
        buffer_data = NULL;
        buffer_length = 0;
        Unref();
        return true;
      }
      return false;
    }

    static void EmitPacket(u_char* user, const struct pcap_pkthdr* pkt_hdr,
                           const u_char* pkt_data) {
      HandleScope scope;
      Pcap *obj = (Pcap*) user;

      size_t copy_len = pkt_hdr->caplen;
      bool truncated = false;
      if (copy_len > obj->buffer_length) {
        copy_len = obj->buffer_length;
        truncated = true;
      }
      memcpy(obj->buffer_data, pkt_data, copy_len);

      TryCatch try_catch;
      Handle<Value> emit_argv[3] = {
        packet_symbol,
        Number::New(copy_len),
        Boolean::New(truncated)
      };
      obj->Emit->Call(obj->handle_, 3, emit_argv);
      if (try_catch.HasCaught())
        FatalException(try_catch);
    }

#ifdef _WIN32
    static void cb_packets(uv_async_t* handle, int status) {
      assert(status == 0);
      Pcap *obj = (Pcap*) handle->data;
      int packet_count;

      //uv_mutex_lock(&obj->mutex);
      do {
        packet_count = pcap_dispatch(obj->pcap_handle, 1, Pcap::EmitPacket,
                                     (u_char*)obj);
      } while (packet_count > 0);
      //uv_mutex_unlock(&obj->mutex);
    }
    static void CALLBACK OnPacket(void* data, BOOLEAN didTimeout) {
      assert(!didTimeout);
      uv_async_t* async = (uv_async_t*) data;
      int r = uv_async_send(async);
      assert(r == 0);
    }
    static void cb_close(uv_handle_t* handle) {
      /*HandleScope scope;
      Pcap *obj = (Pcap*) handle->data;
      TryCatch try_catch;
      Handle<Value> emit_argv[1] = { close_symbol };
      obj->Emit->Call(obj->handle_, 1, emit_argv);
      if (try_catch.HasCaught())
        FatalException(try_catch);
      */
    }
#else
    static void cb_packets(uv_poll_t* handle, int status, int events) {
      assert(status == 0);
      Pcap *obj = (Pcap*) handle->data;

      if (events & UV_READABLE) {
        int packet_count;
        do {
          packet_count = pcap_dispatch(obj->pcap_handle, 1, Pcap::EmitPacket,
                                       (u_char*)obj);
        } while (packet_count > 0);
      }
    }
#endif

    static Handle<Value> New(const Arguments& args) {
      HandleScope scope;

      if (!args.IsConstructCall()) {
        return ThrowException(Exception::TypeError(
          String::New("Use `new` to create instances of this object"))
        );
      }

      Pcap *obj = new Pcap();
      obj->Wrap(args.This());

      obj->Emit = Persistent<Function>::New(
                    Local<Function>::Cast(obj->handle_->Get(emit_symbol))
                  );

      return args.This();
    }

    static Handle<Value> Open(const Arguments& args) {
      HandleScope scope;
      Pcap *obj = ObjectWrap::Unwrap<Pcap>(args.This());

      if (obj->pcap_handle)
        obj->close();

      if (args.Length() >= 4) { 
        if (!args[0]->IsString()) {
          return ThrowException(
            Exception::TypeError(
              String::New("device must be a string")
            )
          );
        }
        if (!args[1]->IsString()) {
          return ThrowException(
            Exception::TypeError(
              String::New("filter must be a string")
            )
          );
        }
        if (!args[2]->IsUint32()) {
          return ThrowException(
            Exception::TypeError(
              String::New("bufSize must be a positive integer")
            )
          );
        }
        if (!Buffer::HasInstance(args[3])) {
          return ThrowException(
            Exception::TypeError(
              String::New("buffer must be a Buffer")
            )
          );
        }
      } else {
        return ThrowException(
          Exception::TypeError(
            String::New("Expecting 4 arguments")
          )
        );
      }
      String::Utf8Value device(args[0]->ToString());
      String::Utf8Value filter(args[1]->ToString());
      int buffer_size = args[2]->Int32Value();
#if NODE_MAJOR_VERSION == 0 && NODE_MINOR_VERSION < 10
      Local<Object> buffer_obj = args[3]->ToObject();
#else
      Local<Value> buffer_obj = args[3];
#endif
      struct bpf_program fp;
      bpf_u_int32 mask;
      bpf_u_int32 net;
      char errbuf[PCAP_ERRBUF_SIZE];

      obj->buffer_data = Buffer::Data(buffer_obj);
      obj->buffer_length = Buffer::Length(buffer_obj);

      if (pcap_lookupnet((char*)*device, &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
        fprintf(stderr, "Warning: %s - This may not actually work\n", errbuf);
      }

      obj->pcap_handle = pcap_create((char*)*device, errbuf);

      if (obj->pcap_handle == NULL)
        return ThrowException(Exception::Error(String::New(errbuf)));

      // 64KB is the max IPv4 packet size
      if (pcap_set_snaplen(obj->pcap_handle, 65535) != 0) {
        return ThrowException(
          Exception::Error(String::New("Unable to set snaplen"))
        );
      }

      // Always use promiscuous mode
      if (pcap_set_promisc(obj->pcap_handle, 1) != 0) {
        return ThrowException(
          Exception::Error(String::New("Unable to set promiscuous mode"))
        );
      }

      // Try to set buffer size. Sometimes the OS has a lower limit that it will
      // silently enforce.
      if (pcap_set_buffer_size(obj->pcap_handle, buffer_size) != 0) {
        return ThrowException(
          Exception::Error(String::New("Unable to set buffer size"))
        );
      }

      // Set "timeout" on read, even though we are also setting nonblock below.
      // On Linux this is required.
      if (pcap_set_timeout(obj->pcap_handle, 1000) != 0) {
        return ThrowException(
          Exception::Error(String::New("Unable to set read timeout"))
        );
      }

      if (pcap_activate(obj->pcap_handle) != 0) {
        return ThrowException(
          Exception::Error(String::New(pcap_geterr(obj->pcap_handle)))
        );
      }

      if (pcap_setnonblock(obj->pcap_handle, 1, errbuf) == -1)
        return ThrowException(Exception::Error(String::New(errbuf)));

      if (filter.length() != 0) {
        if (pcap_compile(obj->pcap_handle, &fp, (char*)*filter, 1, net) == -1) {
          return ThrowException(
            Exception::Error(String::New(pcap_geterr(obj->pcap_handle)))
          );
        }

        if (pcap_setfilter(obj->pcap_handle, &fp) == -1) {
          return ThrowException(
            Exception::Error(String::New(pcap_geterr(obj->pcap_handle)))
          );
        }

        pcap_freecode(&fp);
      }

#if defined(__APPLE_CC__) || defined(__APPLE__)
      // Work around buffering bug in BPF on OSX 10.6 as of May 19, 2010
      // This may result in dropped packets under load because it disables the
      // (broken) buffer
      // http://seclists.org/tcpdump/2010/q1/110
      #include <net/bpf.h>
      int fd = pcap_get_selectable_fd(obj->pcap_handle);
      int v = 1;
      ioctl(fd, BIOCIMMEDIATE, &v);
      // TODO - check return value
#endif

      int link_type = pcap_datalink(obj->pcap_handle);

      Local<Value> ret;
      switch (link_type) {
        case DLT_NULL:
          ret = String::New("NULL");
          break;
        case DLT_EN10MB: // most wifi interfaces pretend to be "ethernet"
          ret =  String::New("ETHERNET");
          break;
        case DLT_IEEE802_11_RADIO: // 802.11 "monitor mode"
          ret = String::New("IEEE802_11_RADIO");
          break;
        case DLT_LINUX_SLL: // "Linux cooked-mode capture"
          ret = String::New("LINKTYPE_LINUX_SLL");
          break;
        case DLT_RAW: // "raw IP"
          ret = String::New("RAW");
          break;
        default:
          snprintf(errbuf, PCAP_ERRBUF_SIZE, "Unknown linktype %d", link_type);
          ret = String::New(errbuf);
          break;
      }

      int r;
#ifdef _WIN32
      r = uv_async_init(uv_default_loop(), &obj->async, cb_packets);
      assert(r == 0);
      obj->async.data = obj;
      //r = uv_mutex_init(&obj->mutex);
      //assert(r == 0);
      r = RegisterWaitForSingleObject(
        &obj->wait,
        pcap_getevent(obj->pcap_handle),
        OnPacket,
        &obj->async,
        INFINITE,
        WT_EXECUTEINWAITTHREAD
      );
      if (!r) {
        char *errmsg = NULL;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
                      | FORMAT_MESSAGE_FROM_SYSTEM
                      | FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL,
                      GetLastError(),
                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      (LPTSTR)&errmsg,
                      0,
                      NULL);
        return ThrowException(Exception::Error(String::New(errmsg)));
      }
#else
      obj->fd = pcap_get_selectable_fd(obj->pcap_handle);
      r = uv_poll_init(uv_default_loop(), &obj->poll_handle, obj->fd);
      assert(r == 0);
      r = uv_poll_start(&obj->poll_handle, UV_READABLE, cb_packets);
      assert(r == 0);
      obj->poll_handle.data = obj;
#endif

      obj->Ref();
      return scope.Close(ret);
    }

#ifdef _WIN32
    static Handle<Value> WIN_SetMin(const Arguments& args) {
      HandleScope scope;
      Pcap *obj = ObjectWrap::Unwrap<Pcap>(args.This());

      if (args.Length() < 1) {
        return ThrowException(
          Exception::Error(String::New("missing min bytes value"))
        );
      }
      if (!args[0]->IsUint32()) {
        return ThrowException(
          Exception::TypeError(
            String::New("min bytes must be a positive number")
          )
        );
      }

      if (obj->pcap_handle == NULL) {
        return ThrowException(
          Exception::Error(String::New("Not currently capturing/open"))
        );
      }

      if (pcap_setmintocopy(obj->pcap_handle, args[0]->Uint32Value()) != 0) {
        return ThrowException(
          Exception::Error(String::New("Unable to set min bytes"))
        );
      }

      return Undefined();
    }
#endif

    static Handle<Value> Close(const Arguments& args) {
      HandleScope scope;
      Pcap *obj = ObjectWrap::Unwrap<Pcap>(args.This());

      return scope.Close(Boolean::New(obj->close()));
    }

    static void Initialize(Handle<Object> target) {
      HandleScope scope;

      Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
      Local<String> name = String::NewSymbol("Cap");

      Pcap_constructor = Persistent<FunctionTemplate>::New(tpl);
      Pcap_constructor->InstanceTemplate()->SetInternalFieldCount(1);
      Pcap_constructor->SetClassName(name);

      NODE_SET_PROTOTYPE_METHOD(Pcap_constructor, "open", Open);
      NODE_SET_PROTOTYPE_METHOD(Pcap_constructor, "close", Close);
#ifdef _WIN32
      NODE_SET_PROTOTYPE_METHOD(Pcap_constructor, "setMinBytes", WIN_SetMin);
#endif

      emit_symbol = NODE_PSYMBOL("emit");
      packet_symbol = NODE_PSYMBOL("packet");
      close_symbol = NODE_PSYMBOL("close");

      target->Set(name, Pcap_constructor->GetFunction());
    }
};

static Handle<Value> ListDevices(const Arguments& args) {
  HandleScope scope;

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs = NULL, *cur_dev;
  pcap_addr_t *cur_addr;
  int i, j, af;

  Local<Object> Dev;
  Local<Object> Address;
  Local<Array> DevsArray;
  Local<Array> AddrArray;

  if (pcap_findalldevs(&alldevs, errbuf) == -1)
    return ThrowException(Exception::Error(String::New(errbuf)));

  DevsArray = Array::New();

  for (i = 0, cur_dev = alldevs; cur_dev != NULL;
       cur_dev = cur_dev->next, ++i) {
    Dev = Object::New();
    AddrArray = Array::New();

    Dev->Set(String::New("name"), String::New(cur_dev->name));
    if (cur_dev->description != NULL) {
      Dev->Set(String::New("description"),
               String::New(cur_dev->description));
    }

    for (j = 0, cur_addr = cur_dev->addresses; cur_addr != NULL;
         cur_addr = cur_addr->next) {
      if (cur_addr->addr) {
        af = cur_addr->addr->sa_family;
        if (af == AF_INET || af == AF_INET6) {
          Address = Object::New();
          SetAddrStringHelper("addr", cur_addr->addr, Address);
          SetAddrStringHelper("netmask", cur_addr->netmask, Address);
          SetAddrStringHelper("broadaddr", cur_addr->broadaddr, Address);
          SetAddrStringHelper("dstaddr", cur_addr->dstaddr, Address);
          AddrArray->Set(Integer::New(j++), Address);
        }
      }
    }
      
    Dev->Set(String::New("addresses"), AddrArray);

    if (cur_dev->flags & PCAP_IF_LOOPBACK)
      Dev->Set(String::New("flags"), String::New("PCAP_IF_LOOPBACK"));

    DevsArray->Set(Integer::New(i), Dev);
  }

  if (alldevs)
    pcap_freealldevs(alldevs);

  return scope.Close(DevsArray);
}

static Handle<Value> FindDevice(const Arguments& args) {
  HandleScope scope;

  Local<Value> ret;
  char errbuf[PCAP_ERRBUF_SIZE];
  char name4[INET_ADDRSTRLEN];
  char name6[INET6_ADDRSTRLEN];
  char *ip = NULL;
  pcap_if_t *alldevs = NULL, *dev;
  pcap_addr_t *addr;
  bool found = false;

  if (args.Length() > 0) { 
    if (!args[0]->IsString()) {
      return ThrowException(
        Exception::Error(String::New("Expected string for IP"))
      );
    }
    String::AsciiValue ipstr(args[0]->ToString());
    ip = (char*)malloc(sizeof(*ipstr));
    strcpy(ip, *ipstr);
  }

  if (pcap_findalldevs(&alldevs, errbuf) == -1)
    return ThrowException(Exception::Error(String::New(errbuf)));

  for (dev = alldevs; dev != NULL; dev = dev->next) {
    if (dev->addresses != NULL && !(dev->flags & PCAP_IF_LOOPBACK)) {
      for (addr = dev->addresses; addr != NULL; addr = addr->next) {
        if (addr->addr->sa_family == AF_INET
            || addr->addr->sa_family == AF_INET6) {
          if (ip) {
            if (addr->addr->sa_family == AF_INET) {
              inet_ntop(AF_INET,
                        (char*)&(((struct sockaddr_in*)(addr->addr))->sin_addr),
                        name4, INET_ADDRSTRLEN);
              if (strcmp(ip, name4) != 0)
                continue;
            } else if (addr->addr->sa_family == AF_INET6) {
              inet_ntop(AF_INET6,
                        (char*)&(((struct sockaddr_in6*)(addr->addr))->sin6_addr),
                        name6, INET6_ADDRSTRLEN);
              if (strcmp(ip, name6) != 0)
                continue;
            }
          }
          ret = String::New(dev->name);
          found = true;
          break;
        }
      }
      if (found)
        break;
    }
  }

  if (alldevs)
    pcap_freealldevs(alldevs);
  if (ip)
    free(ip);
  return scope.Close(ret);
}

extern "C" {
  void init(Handle<Object> target) {
    HandleScope scope;
    Pcap::Initialize(target);
    target->Set(String::NewSymbol("findDevice"),
                FunctionTemplate::New(FindDevice)->GetFunction());
    target->Set(String::NewSymbol("deviceList"),
                FunctionTemplate::New(ListDevices)->GetFunction());
  }

  NODE_MODULE(cap, init);
}
