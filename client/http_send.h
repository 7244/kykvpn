typedef enum{
  http_send_state_Wait,
  http_send_state_PostSent
}http_send_state_t;

typedef struct{
  uint8_t State;
  EV_timer_t Timer;

  HTTP_decode_t hd;
  uint8_t hd_combo;
}tcp_http_send_pd_t;

void tcp_http_send_Timer(EV_t *l, EV_timer_t *t){
  tcp_http_send_pd_t *pd = (tcp_http_send_pd_t *)NET_TCP_GetPeerData(pile.http_send_peer, pile.http_send.extid);

  ic_Packet_t *icp;
  ic_Packet_t _icp;
  icack_t icack;
  if(pile.ic.srcack_at != pile.ic.srcack_to){
    icack = pile.ic.srcack_at;
    icp = ic_ackPacketMap_GetOutputPointer(&pile.ic.srcPacketMap, &icack);
  }
  else{
    #include "LoadBalance.h"

    icack = pile.ic.srcack_to++;

    uint8_t *Data = A_resize(NULL, Size);
    __builtin_memcpy(Data, pile.SendBuffer.ptr, Size);
    pile.SendBuffer.Current = 0;

    icp = &_icp;
    icp->Size = Size;
    icp->Data = Data;
    ic_ackPacketMap_InNew(&pile.ic.srcPacketMap, &icack, icp);
  }

  VEC_t vec;
  VEC_init(&vec, 1, A_resize);
  VEC_print(&vec,
    "POST /uploadpfp HTTP/1.1\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
    "Accept-Encoding: gzip, deflate, br\r\n"
    "Accept-Language: en-US,en;q=0.9\r\n"
    "Cache-Control: max-age=0\r\n"
    "Connection: Keep-Alive\r\n"
    "Content-Length: %u\r\n"
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundarygbI3oA7gW8BaAfjl\r\n"
    "Host: 84.248.74.200\r\n"
    "Origin: http://84.248.74.200\r\n"
    "Referer: http://84.248.74.200/\r\n"
    "Upgrade-Insecure-Requests: 1\r\n"
    "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36\r\n\r\n",
    sizeof(icack_t) + icp->Size
  );

  VEC_print(&vec, "%.*s", sizeof(icack_t), &icack);
  VEC_print(&vec, "%.*s", icp->Size, icp->Data);

  tcp_write_dp(pile.http_send_peer, vec.ptr, vec.Current);

  VEC_free(&vec);

  EV_timer_stop(l, t);
  HTTP_decode_init(&pd->hd);
  pd->hd_combo = 0;
  pd->State = http_send_state_PostSent;
}

void tcp_http_send_PeerOpen(NET_TCP_peer_t *p){

  print("[+] http_send\n");

  tcp_http_send_pd_t *pd = (tcp_http_send_pd_t *)NET_TCP_GetPeerData(p, pile.http_send.extid);

  NET_TCP_StartReadLayer(p, pile.http_send.LayerReadID);

  pile.http_send_peer = p;

  pd->State = http_send_state_Wait;
  EV_timer_init(&pd->Timer, 0.05, tcp_http_send_Timer);
  EV_timer_start(&pile.listener, &pd->Timer);
}
void tcp_http_send_PeerClose(NET_TCP_peer_t *p){
  print("[-] http_send\n");

  tcp_http_send_pd_t *pd = (tcp_http_send_pd_t *)NET_TCP_GetPeerData(p, pile.http_send.extid);

  pile.http_send_peer = NULL;

  if(pd->State == http_send_state_Wait){
    EV_timer_stop(&pile.listener, &pd->Timer);
  }
}

uint32_t
cb_tcp_http_send_connstate(
  NET_TCP_peer_t *peer,
  uint8_t *sd,
  tcp_http_send_pd_t *pd,
  uint32_t flag
){
  if(flag & NET_TCP_state_succ_e){
    tcp_http_send_PeerOpen(peer);
  }
  else{
    if(flag & NET_TCP_state_init_e){
      tcp_http_send_PeerClose(peer);
    }

    EV_timer_init(&pile.timer_http_send, 0, timer_http_send_connect_cb);
    EV_timer_start(&pile.listener, &pile.timer_http_send);
  }

  return 0;
}

NET_TCP_layerflag_t
cb_tcp_http_send_read(
  NET_TCP_peer_t *peer,
  uint8_t *sd,
  tcp_http_send_pd_t *pd,
  NET_TCP_QueuerReference_t QueuerReference,
  uint32_t *type,
  NET_TCP_Queue_t *Queue
){
  common_BuildRecvData

  uintptr_t DataIndex = 0;

  while(DataIndex != DataSize){
    if(pd->State != http_send_state_PostSent){
      PR_abort();
    }

    HTTP_result_t result;
    sint32_t ret = HTTP_decode(&pd->hd, Data, DataSize, &DataIndex, &result);
    if(ret < 0){
      if(ret == ~HTTP_DecodeError_Done_e){
        if(pd->hd_combo != 4){
          evprint("[http_send close] http done with hd_combo %lx\n", pd->hd_combo);
          evprint("here is part of content:\n");
          uintptr_t left = DataIndex - DataSize;
          evprint("%.*s\n", left, &Data[DataIndex]);
          NET_TCP_CloseHard(peer);
          return NET_TCP_EXT_PeerIsClosed_e;
        }
        evprint("cb_tcp_http_send_read http done\n");
        {
          icack_t icack = pile.ic.srcack_at++;
          ic_Packet_t *icp = ic_ackPacketMap_GetOutputPointer(&pile.ic.srcPacketMap, &icack);
          A_resize(icp->Data, 0);
          ic_ackPacketMap_Remove(&pile.ic.srcPacketMap, &icack);
        }
        EV_timer_init(&pd->Timer, 0.05, tcp_http_send_Timer);
        EV_timer_start(&pile.listener, &pd->Timer);
        pd->State = http_send_state_Wait;
      }
      else{
        evprint("http_send HTTP_decode error %ld\n", ret);
        NET_TCP_CloseHard(peer);
        return NET_TCP_EXT_PeerIsClosed_e;
      }
    }
    else{
      if(ret == HTTP_ResultType_head_e){
        const char *r1 = "200";
        const char *r2 = "OK";
        if(MEM_cstreu(r1) == result.head.s[1] && STR_ncmp(r1, result.head.v[1], result.head.s[1]) == 0){
          pd->hd_combo++;
        }
        if(MEM_cstreu(r2) == result.head.s[2] && STR_ncmp(r2, result.head.v[2], result.head.s[2]) == 0){
          pd->hd_combo++;
        }
      }
      else if(ret == HTTP_ResultType_header_e){
        const char *r00 = "Content-Length";
        const char *r01 = "0";
        const char *r10 = "Connection";
        const char *r11 = "Keep-Alive";
        if(MEM_cstreu(r00) == result.header.s[0] && STR_ncmp(r00, result.header.v[0], result.header.s[0]) == 0){
          if(MEM_cstreu(r01) == result.header.s[1] && STR_ncmp(r01, result.header.v[1], result.header.s[1]) == 0){
            pd->hd_combo++;
          }
        }
        else if(MEM_cstreu(r10) == result.header.s[0] && STR_ncmp(r10, result.header.v[0], result.header.s[0]) == 0){
          if(MEM_cstreu(r11) == result.header.s[1] && STR_ncasecmp(r11, result.header.v[1], result.header.s[1]) == 0){
            pd->hd_combo++;
          }
        }
      }
    }
  }

  return 0;
}
