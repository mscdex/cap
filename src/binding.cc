#include <node.h>
#include <node_buffer.h>
#include <nan.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
# define snprintf _snprintf
  const char* inet_ntop(int af, const void* src, char* dst, int cnt) {
    struct sockaddr_storage sa;
    struct sockaddr_in *srcaddr = (struct sockaddr_in*)&sa;
    struct sockaddr_in6 *srcaddr6 = (struct sockaddr_in6*)&sa;
    int addr_len;
    memset(&sa, 0, sizeof(sa));
    if (af == AF_INET) {
      srcaddr->sin_family = af;
      addr_len = sizeof(struct sockaddr_in);
      memcpy(&srcaddr->sin_addr, src, sizeof(struct in_addr));
    } else if (af == AF_INET6) {
      srcaddr6->sin6_family = af;
      addr_len = sizeof(struct sockaddr_in6);
      memcpy(&srcaddr6->sin6_addr, src, sizeof(struct in6_addr));
    } else
      return NULL;
    if (WSAAddressToString((LPSOCKADDR)&sa,
                           addr_len,
                           0,
                           dst,
                           (LPDWORD)&cnt) != 0) {
      return NULL;
    }
    return dst;
  }
#else
# include <arpa/inet.h>
# include <sys/ioctl.h>
#endif
#if __linux__
# include <dlfcn.h>
  // Without immediate mode some architectures (e.g. Linux with TPACKET_V3)
  // will buffer replies and potentially cause a *long* delay in packet
  // reception

  // pcap_set_immediate_mode is new as of libpcap 1.5.1, so we check for
  // this new method dynamically ...
  typedef void* (*set_immediate_fn)(pcap_t *p, int immediate);
  void *_pcap_lib_handle = dlopen("libpcap.so", RTLD_LAZY);
  set_immediate_fn set_immediate_mode =
    (set_immediate_fn)(dlsym(_pcap_lib_handle, "pcap_set_immediate_mode"));
#else
# define set_immediate_mode NULL
#endif

using namespace node;
using namespace v8;

static Persistent<FunctionTemplate> constructor;
static Persistent<String> emit_symbol;
static Persistent<String> packet_symbol;

void SetAddrStringHelper(const char* key,
                         sockaddr *addr,
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
    if (address == NULL)
      Address->Set(NanNew<String>(key), NanUndefined());
    else
      Address->Set(NanNew<String>(key), NanNew<String>(address));
  }
}

class Pcap : public ObjectWrap {
  public:
    Persistent<Function> Emit;

#ifdef _WIN32
    HANDLE wait;
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
      NanDisposePersistent(Emit);
    }

    bool close() {
      if (pcap_handle) {
#ifdef _WIN32
        if (wait) {
          UnregisterWait(wait);
          wait = NULL;
        }
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

    static void EmitPacket(u_char* user,
                           const struct pcap_pkthdr* pkt_hdr,
                           const u_char* pkt_data) {
      NanScope();
      Pcap *obj = (Pcap*) user;

      size_t copy_len = pkt_hdr->caplen;
      bool truncated = false;
      if (copy_len > obj->buffer_length) {
        copy_len = obj->buffer_length;
        truncated = true;
      }
      memcpy(obj->buffer_data, pkt_data, copy_len);

      Handle<Value> emit_argv[3] = {
        NanNew<String>(packet_symbol),
        NanNew<Number>(copy_len),
        NanNew<Boolean>(truncated)
      };
      NanMakeCallback(
#if NODE_MAJOR_VERSION == 0 && NODE_MINOR_VERSION <= 10
        obj->handle_,
#else
        NanNew<Object>(obj->persistent()),
#endif
        NanNew<Function>(obj->Emit),
        3,
        emit_argv
      );
    }

#ifdef _WIN32
    static void cb_packets(uv_async_t* handle, int status) {
      assert(status == 0);
      Pcap *obj = (Pcap*) handle->data;
      int packet_count;

      do {
        packet_count = pcap_dispatch(obj->pcap_handle, 1, Pcap::EmitPacket,
                                     (u_char*)obj);
      } while (packet_count > 0);
    }
    static void CALLBACK OnPacket(void* data, BOOLEAN didTimeout) {
      assert(!didTimeout);
      uv_async_t* async = (uv_async_t*) data;
      int r = uv_async_send(async);
      assert(r == 0);
    }
    static void cb_close(uv_handle_t* handle) {
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

    static NAN_METHOD(New) {
      NanScope();

      if (!args.IsConstructCall())
        return NanThrowError("Use `new` to create instances of this object");

      Pcap *obj = new Pcap();
      obj->Wrap(args.This());

      NanAssignPersistent<Function>(
        obj->Emit,
        Local<Function>::Cast(
#if NODE_MAJOR_VERSION == 0 && NODE_MINOR_VERSION <= 10
          obj->handle_->Get(emit_symbol)
#else
          NanNew<Object>(obj->persistent())->Get(NanNew<String>(emit_symbol))
#endif
        )
      );

      NanReturnValue(args.This());
    }

    static NAN_METHOD(Send) {
      NanScope();
      Pcap *obj = ObjectWrap::Unwrap<Pcap>(args.This());
      unsigned int buffer_size = 0;

      if (args.Length() == 0)
        return NanThrowTypeError("the first parameter must be a buffer");

      if (!Buffer::HasInstance(args[0]))
        return NanThrowTypeError("first parameter must be a buffer");

      if (args.Length() >= 2) {
        if (!args[1]->IsUint32())
          return NanThrowTypeError("length must be a positive integer");

        buffer_size = args[1]->Uint32Value();
      }

#if NODE_MAJOR_VERSION == 0 && NODE_MINOR_VERSION < 10
      Local<Object> buffer_obj = args[0]->ToObject();
#else
      Local<Value> buffer_obj = args[0];
#endif
      if (args.Length() == 1)
        buffer_size = Buffer::Length(buffer_obj);
      else {
        if (buffer_size > Buffer::Length(buffer_obj)) {
          return NanThrowTypeError(
            "size must be smaller or equal to buffer length"
          );
        }
      }

      if (pcap_sendpacket(obj->pcap_handle,
                          (const u_char*)Buffer::Data(buffer_obj),
                          buffer_size) == -1) {
        return NanThrowError(pcap_geterr(obj->pcap_handle));
      }

      NanReturnUndefined();
    }

    static NAN_METHOD(Open) {
      NanScope();
      Pcap *obj = ObjectWrap::Unwrap<Pcap>(args.This());

      if (obj->pcap_handle)
        obj->close();

      if (args.Length() < 4)
        return NanThrowTypeError("Expecting 4 arguments");

      if (!args[0]->IsString())
        return NanThrowTypeError("device must be a string");

      if (!args[1]->IsString())
        return NanThrowTypeError("filter must be a string");

      if (!args[2]->IsUint32())
        return NanThrowTypeError("bufSize must be a positive integer");

      if (!Buffer::HasInstance(args[3]))
        return NanThrowTypeError("buffer must be a Buffer");
        

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
        return NanThrowError(errbuf);

      // 64KB is the max IPv4 packet size
      if (pcap_set_snaplen(obj->pcap_handle, 65535) != 0)
        return NanThrowError("Unable to set snaplen");

      // Always use promiscuous mode
      if (pcap_set_promisc(obj->pcap_handle, 1) != 0)
        return NanThrowError("Unable to set promiscuous mode");

      // Try to set buffer size. Sometimes the OS has a lower limit that it will
      // silently enforce.
      if (pcap_set_buffer_size(obj->pcap_handle, buffer_size) != 0)
        return NanThrowError("Unable to set buffer size");

      // Set "timeout" on read, even though we are also setting nonblock below.
      // On Linux this is required.
      if (pcap_set_timeout(obj->pcap_handle, 1000) != 0)
        return NanThrowError("Unable to set read timeout");

      if (set_immediate_mode)
        set_immediate_mode(obj->pcap_handle, 1);

      if (pcap_activate(obj->pcap_handle) != 0)
        return NanThrowError(pcap_geterr(obj->pcap_handle));

      if (pcap_setnonblock(obj->pcap_handle, 1, errbuf) == -1)
        return NanThrowError(errbuf);

      if (filter.length() != 0) {
        if (pcap_compile(obj->pcap_handle, &fp, (char*)*filter, 1, net) == -1)
          return NanThrowError(pcap_geterr(obj->pcap_handle));

        if (pcap_setfilter(obj->pcap_handle, &fp) == -1)
          return NanThrowError(pcap_geterr(obj->pcap_handle));

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
          ret = NanNew<String>("NULL");
          break;
        case DLT_EN10MB: // most wifi interfaces pretend to be "ethernet"
          ret =  NanNew<String>("ETHERNET");
          break;
        case DLT_IEEE802_11_RADIO: // 802.11 "monitor mode"
          ret = NanNew<String>("IEEE802_11_RADIO");
          break;
        case DLT_LINUX_SLL: // "Linux cooked-mode capture"
          ret = NanNew<String>("LINKTYPE_LINUX_SLL");
          break;
        case DLT_RAW: // "raw IP"
          ret = NanNew<String>("RAW");
          break;
        default:
          snprintf(errbuf, PCAP_ERRBUF_SIZE, "Unknown linktype %d", link_type);
          ret = NanNew<String>(errbuf);
          break;
      }

      int r;
#ifdef _WIN32
      r = uv_async_init(uv_default_loop(), &obj->async, cb_packets);
      assert(r == 0);
      obj->async.data = obj;
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
        return NanThrowError(errmsg);
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
      NanReturnValue(ret);
    }

#ifdef _WIN32
    static NAN_METHOD(WIN_SetMin) {
      NanScope();
      Pcap *obj = ObjectWrap::Unwrap<Pcap>(args.This());

      if (args.Length() < 1)
        return NanThrowTypeError("missing min bytes value");

      if (!args[0]->IsUint32())
        return NanThrowTypeError("min bytes must be a positive number");

      if (obj->pcap_handle == NULL)
        return NanThrowError("Not currently capturing/open");

      if (pcap_setmintocopy(obj->pcap_handle, args[0]->Uint32Value()) != 0)
        return NanThrowError("Unable to set min bytes");

      NanReturnUndefined();
    }
#endif

    static NAN_METHOD(Close) {
      NanScope();
      Pcap *obj = ObjectWrap::Unwrap<Pcap>(args.This());

      NanReturnValue(NanNew<Boolean>(obj->close()));
    }

    static void Initialize(Handle<Object> target) {
      NanScope();

      Local<FunctionTemplate> tpl = NanNew<FunctionTemplate>(New);

      NanAssignPersistent(constructor, tpl);
      tpl->InstanceTemplate()->SetInternalFieldCount(1);
      tpl->SetClassName(NanNew<String>("Cap"));

      NODE_SET_PROTOTYPE_METHOD(tpl, "send", Send);
      NODE_SET_PROTOTYPE_METHOD(tpl, "open", Open);
      NODE_SET_PROTOTYPE_METHOD(tpl, "close", Close);
#ifdef _WIN32
      NODE_SET_PROTOTYPE_METHOD(tpl, "setMinBytes", WIN_SetMin);
#endif

      NanAssignPersistent(emit_symbol, NanNew<String>("emit"));
      NanAssignPersistent(packet_symbol, NanNew<String>("packet"));

      target->Set(NanNew<String>("Cap"), tpl->GetFunction());
    }
};

static NAN_METHOD(ListDevices) {
  NanScope();

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs = NULL, *cur_dev;
  pcap_addr_t *cur_addr;
  int i, j, af;

  Local<Object> Dev;
  Local<Object> Address;
  Local<Array> DevsArray;
  Local<Array> AddrArray;

  if (pcap_findalldevs(&alldevs, errbuf) == -1)
    return NanThrowError(errbuf);

  DevsArray = NanNew<Array>();

  for (i = 0, cur_dev = alldevs;
       cur_dev != NULL;
       cur_dev = cur_dev->next, ++i) {
    Dev = NanNew<Object>();
    AddrArray = NanNew<Array>();

    Dev->Set(NanNew<String>("name"), NanNew<String>(cur_dev->name));
    if (cur_dev->description != NULL) {
      Dev->Set(NanNew<String>("description"),
               NanNew<String>(cur_dev->description));
    }

    for (j = 0, cur_addr = cur_dev->addresses;
         cur_addr != NULL;
         cur_addr = cur_addr->next) {
      if (cur_addr->addr) {
        af = cur_addr->addr->sa_family;
        if (af == AF_INET || af == AF_INET6) {
          Address = NanNew<Object>();
          SetAddrStringHelper("addr", cur_addr->addr, Address);
          SetAddrStringHelper("netmask", cur_addr->netmask, Address);
          SetAddrStringHelper("broadaddr", cur_addr->broadaddr, Address);
          SetAddrStringHelper("dstaddr", cur_addr->dstaddr, Address);
          AddrArray->Set(NanNew<Integer>(j++), Address);
        }
      }
    }
      
    Dev->Set(NanNew<String>("addresses"), AddrArray);

    if (cur_dev->flags & PCAP_IF_LOOPBACK)
      Dev->Set(NanNew<String>("flags"), NanNew<String>("PCAP_IF_LOOPBACK"));

    DevsArray->Set(NanNew<Integer>(i), Dev);
  }

  if (alldevs)
    pcap_freealldevs(alldevs);

  NanReturnValue(DevsArray);
}

static NAN_METHOD(FindDevice) {
  NanScope();

  Local<Value> ret;
  char errbuf[PCAP_ERRBUF_SIZE];
  char name4[INET_ADDRSTRLEN];
  char name6[INET6_ADDRSTRLEN];
  char *ip = NULL;
  pcap_if_t *alldevs = NULL, *dev;
  pcap_addr_t *addr;
  bool found = false;

  if (pcap_findalldevs(&alldevs, errbuf) == -1)
    return NanThrowError(errbuf);

  if (args.Length() > 0) { 
    if (!args[0]->IsString())
      return NanThrowTypeError("Expected string for IP");
    NanUtf8String ipstr(args[0]->ToString());
    ip = (char*)malloc(ipstr.length());
    strcpy(ip, *ipstr);
  }

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
          ret = NanNew<String>(dev->name);
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

  NanReturnValue(ret);
}

extern "C" {
  void init(Handle<Object> target) {
    NanScope();
    Pcap::Initialize(target);
    target->Set(NanNew<String>("findDevice"),
                NanNew<FunctionTemplate>(FindDevice)->GetFunction());
    target->Set(NanNew<String>("deviceList"),
                NanNew<FunctionTemplate>(ListDevices)->GetFunction());
  }

  NODE_MODULE(cap, init);
}
