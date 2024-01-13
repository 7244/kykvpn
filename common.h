#if defined(set_ExtremeVerbose)
  #define evprint(p, ...) { \
    print("[ev] %llf ", T_nowf()); \
    print(p, ## __VA_ARGS__); \
  }
#else
  #define evprint(...)
#endif

#if defined(set_Verbose) || defined(set_ExtremeVerbose)
  #define vprint(p, ...) { \
    print("[v] %llf ", T_nowf()); \
    print(p, ## __VA_ARGS__); \
  }
#else
  #define vprint(...)
#endif


#include <WITCH/WITCH.h>

#include <WITCH/PR/PR.h>

#include <WITCH/IO/IO.h>
#include <WITCH/IO/print.h>

#include <WITCH/VEC/VEC.h>
#include <WITCH/VEC/print.h>

void print(const char *format, ...){
  IO_fd_t fd_stdout;
  IO_fd_set(&fd_stdout, FD_OUT);
  va_list argv;
  va_start(argv, format);
  IO_vprint(&fd_stdout, format, argv);
  va_end(argv);
}

#include <WITCH/NET/TCP/TCP.h>

#include <WITCH/STR/psu.h>
#include <WITCH/STR/pss.h>
#include <WITCH/STR/psh.h>

#include <WITCH/RAND/RAND.h>

#define ETC_HTTP_set_prefix HTTP
#include <WITCH/ETC/HTTP/HTTP.h>

#include "httpp.h"

#define common_BuildRecvData \
  uint8_t *Data; \
  uintptr_t DataSize; \
  uint8_t _EventReadBuffer[0x1000]; \
  switch(*type){ \
    case NET_TCP_QueueType_DynamicPointer:{ \
      Data = (uint8_t *)Queue->DynamicPointer.ptr; \
      DataSize = Queue->DynamicPointer.size; \
      break; \
    } \
    case NET_TCP_QueueType_PeerEvent:{ \
      IO_fd_t peer_fd; \
      EV_event_get_fd(&peer->event, &peer_fd); \
      IO_ssize_t len = IO_read(&peer_fd, _EventReadBuffer, sizeof(_EventReadBuffer)); \
      if(len < 0){ \
        NET_TCP_CloseHard(peer); \
        return NET_TCP_EXT_PeerIsClosed_e; \
      } \
      Data = _EventReadBuffer; \
      DataSize = len; \
      break; \
    } \
    case NET_TCP_QueueType_CloseHard: \
    case NET_TCP_QueueType_CloseIfGodFather: \
    { \
      return 0; \
    } \
    default:{ \
      print("cb_read *type %lx\r\n", *type); \
      PR_abort(); \
      __unreachable(); \
    } \
  }

void common_LowerSocketBuffer(NET_socket_t s){
  sint32_t BufferSize;
  sint32_t r = NET_getsockopt(&s, SOL_SOCKET, SO_SNDBUF, &BufferSize);
  if(r){
    vprint("common socket BufferSize NET_getsockopt failed %ld\n", r);
    return;
  }

  if(BufferSize < 0){
    vprint("common socket BufferSize is negative\n");
    return;
  }
  else if(BufferSize == 0){
    BufferSize = 0x800;
  }

  /* we set first setsockopt same as first to cancel kernel's autotune */
  BufferSize /= 2;
  r = NET_setsockopt(&s, SOL_SOCKET, SO_SNDBUF, BufferSize);
  if(r){
    vprint("common socket canceling autotune buffer failed %ld\n", r);
    return;
  }

  if(((uint32_t)0x80000000 >> __clz32(BufferSize)) == BufferSize){
    BufferSize /= 2;
  }
  else{
    BufferSize = (uint32_t)0x80000000 >> __clz32(BufferSize);
  }

  while(BufferSize >= 0x400){
    r = NET_setsockopt(&s, SOL_SOCKET, SO_SNDBUF, BufferSize);
    if(r){
      break;
    }
    BufferSize /= 2;
  }

  evprint("common socket BufferSize is %lx\n", BufferSize * 2);
}

typedef struct{
  NET_TCP_t *tcp;
  NET_TCP_extid_t extid;
  NET_TCP_layerid_t LayerStateID;
  NET_TCP_layerid_t LayerReadID;
}tcppile_t;

void
tcppile_Open(
  EV_t *listener,
  tcppile_t *tcppile,
  uintptr_t pd_size,
  void *cb_connstate,
  void *cb_read
){
  tcppile->tcp = NET_TCP_alloc(listener);

  tcppile->extid = NET_TCP_EXT_new(tcppile->tcp, 0, pd_size);
  tcppile->LayerStateID = NET_TCP_layer_state_open(
    tcppile->tcp,
    tcppile->extid,
    (NET_TCP_cb_state_t)cb_connstate);
  tcppile->LayerReadID = NET_TCP_layer_read_open(
    tcppile->tcp,
    tcppile->extid,
    (NET_TCP_cb_read_t)cb_read,
    NULL,
    NULL,
    NULL
  );

  NET_TCP_open(tcppile->tcp);
}
#define tcppile_Open(...) \
  tcppile_Open(&pile.listener, __VA_ARGS__)

NET_TCP_peer_t *tcp_connect(NET_TCP_t *tcp, NET_addr_t *addr){
  NET_TCP_sockopt_t sockopt;
  sockopt.level = IPPROTO_TCP;
  sockopt.optname = TCP_NODELAY;
  sockopt.value = 1;

  NET_TCP_peer_t *FillerPeer;
  if(NET_TCP_connect(tcp, &FillerPeer, addr, &sockopt, 1)){
    return NULL;
  }
  return FillerPeer;
}

void tcp_write_loop(NET_TCP_peer_t *peer, NET_TCP_Queue_t *Queue, uint32_t QueueType){
  NET_TCP_layerflag_t Flag = NET_TCP_write_loop(
    peer,
    NET_TCP_GetWriteQueuerReferenceFirst(peer),
    QueueType,
    Queue
  );
  if(Flag != 0){
    PR_abort();
  }
}

/* write dynamic pointer */
void tcp_write_dp(NET_TCP_peer_t *peer, const void *Data, uintptr_t Size){
  NET_TCP_Queue_t Queue;
  Queue.DynamicPointer.ptr = (uint8_t *)Data;
  Queue.DynamicPointer.size = Size;
  tcp_write_loop(peer, &Queue, NET_TCP_QueueType_DynamicPointer);
}
/* write stack to special pointer */
void tcp_write_s2sp(NET_TCP_peer_t *peer, const void *Data, uintptr_t Size, NET_TCP_SpecialPointer_cb cb){
  A_resize_t resize = NET_TCP_write_GetResize_SpecialPointer(
    peer->parent,
    peer,
    NET_TCP_IterateWriteQueuerReference(
      peer,
      NET_TCP_GetWriteQueuerReferenceFirst(peer)
    )
  );
  uint8_t *sp = resize(0, Size);
  MEM_copy(Data, sp, Size);

  NET_TCP_Queue_t Queue;
  Queue.SpecialPointer.ptr = sp;
  Queue.SpecialPointer.Size = Size;
  Queue.SpecialPointer.DataIndex = 0;
  Queue.SpecialPointer.cb = cb;
  tcp_write_loop(peer, &Queue, NET_TCP_QueueType_SpecialPointer);
}

#define COPY(to, size) \
  ({ \
    uintptr_t ls = DataSize - DataIndex; \
    if(ls > ((size) - pd->CopyIndex)){ \
      ls = ((size) - pd->CopyIndex); \
    } \
    MEM_copy(&Data[DataIndex], &((uint8_t *)(to))[pd->CopyIndex], ls); \
    DataIndex += ls; \
    pd->CopyIndex += ls; \
    bool r = pd->CopyIndex == size; \
    if(r){ \
      pd->CopyIndex = 0; \
    } \
    r; \
  })

typedef struct{
  uintptr_t a;
  uintptr_t index;
}balance_w4_tmp_t;
void balance_w4_swap(uintptr_t *x, uintptr_t *y){
  uintptr_t t = *x;
  *x = *y;
  *y = t;
}
void common_uintptr_Balance(uintptr_t *a, uintptr_t s, uintptr_t d) {
  balance_w4_tmp_t *tmp = (balance_w4_tmp_t *)A_resize(NULL, s * sizeof(balance_w4_tmp_t));
  for(uintptr_t i = 0; i < s; i++){
    tmp[i].a = 0;
    tmp[i].index = i;
  }

  uintptr_t Increaseable = s;
  while(d){
    if(Increaseable == 0){
      break;
    }

    uintptr_t Inc = d / Increaseable;
    Inc += !!(d % Increaseable) * !Inc;

    for(uintptr_t i = 0; i < Increaseable;){
      uintptr_t diff = a[i] - tmp[i].a;
      uintptr_t used = diff;
      if(used > Inc){
        used = Inc;
      }
      if(EXPECT(d <= 1, 0)) do{
        if(used == 0){
          break;
        }
        tmp[i].a++;
        goto gt_d0;
      }while(0);
      else{
        tmp[i].a += used;
        d -= used;
      }

      if(used == diff){
        Increaseable--;
        balance_w4_swap(&a[i], &a[Increaseable]);
        balance_w4_swap(&tmp[i].a, &tmp[Increaseable].a);
        balance_w4_swap(&tmp[i].index, &tmp[Increaseable].index);
        continue;
      }
      i++;
    }
  }
  gt_d0:;

  for(uintptr_t i = 0; i < s; i++){
    uintptr_t ai = tmp[i].index;
    a[ai] = tmp[i].a;
  }

  A_resize(tmp, 0);
}
