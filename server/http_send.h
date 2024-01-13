typedef struct{
  EV_timer_t Timer;
}tcp_http_send_pd_t;

void tcp_http_send_PeerClose(tcp_http_send_pd_t *);

void PackSendBuffer(){
  uintptr_t Size = pile.SendBuffer.Current;
  icack_t icack = pile.ic.srcack_to++;

  uint8_t *Data = A_resize(NULL, Size);
  MEM_copy(pile.SendBuffer.ptr, Data, Size);
  pile.SendBuffer.Current = 0;

  ic_Packet_t icp;
  icp.Size = Size;
  icp.Data = Data;
  ic_ackPacketMap_InNew(&pile.ic.srcPacketMap, &icack, &icp);
}

void tcp_http_send_SendACK(tcp_http_send_pd_t *pd, bool Force){
  ic_Packet_t *icp;
  ic_Packet_t _icp;
  icack_t icack;
  if(pile.ic.srcack_at != pile.ic.srcack_to){
    icack = pile.ic.srcack_at;
    icp = ic_ackPacketMap_GetOutputPointer(&pile.ic.srcPacketMap, &icack);
  }
  else{
    #include "LoadBalance.h"
    /*
    uintptr_t Size = pile.SendBuffer.Current;
    if(pile.SendBuffer.Current == 0 && Force == false){
      return;
    }
    */

    icack = pile.ic.srcack_to++;

    uint8_t *Data = A_resize(NULL, Size);
    MEM_copy(pile.SendBuffer.ptr, Data, Size);
    pile.SendBuffer.Current = 0;

    icp = &_icp;
    icp->Size = Size;
    icp->Data = Data;
    ic_ackPacketMap_InNew(&pile.ic.srcPacketMap, &icack, icp);
  }

  VEC_t vec;
  VEC_init(&vec, 1, A_resize);
  VEC_print(&vec,
    "HTTP/1.1 200 OK\r\n"
    "Server: Apache\r\n"
    "Content-Length: %u\r\n"
    "Connection: Keep-Alive\r\n\r\n",
    sizeof(icack_t) + icp->Size
  );

  VEC_print(&vec, "%.*s", sizeof(icack_t), &icack);
  VEC_print(&vec, "%.*s", icp->Size, icp->Data);

  evprint("tcp_http_send_SendACK %lx %x\n", icack, icp->Size);

  tcp_write_dp(pile.http_send_peer, vec.ptr, vec.Current);

  VEC_free(&vec);

  NET_TCP_peer_t *peer = pile.http_send_peer;
  tcp_http_send_PeerClose(pd);
  tcp_http_PeerReinit(peer);
}

void tcp_http_send_Timer(EV_t *l, EV_timer_t *t){
  tcp_http_send_pd_t *pd = OFFSETLESS(t, tcp_http_send_pd_t, Timer);

  tcp_http_send_SendACK(pd, false);
}

void tcp_http_send_PeerOpen(tcp_http_send_pd_t *pd, icack_t icack, uint64_t HTTPCombo){
  if(icack == pile.ic.srcack_at){
    /* soulless */
  }
  else if(icack == pile.ic.srcack_at + 1){
    ic_Packet_t *icp = ic_ackPacketMap_GetOutputPointer(&pile.ic.srcPacketMap, &pile.ic.srcack_at);
    A_resize(icp->Data, 0);
    ic_ackPacketMap_Remove(&pile.ic.srcPacketMap, &pile.ic.srcack_at);
    pile.ic.srcack_at = icack;
  }

  print("[+] http_send\n");

  EV_timer_init(&pd->Timer, 0.05, tcp_http_send_Timer);
  EV_timer_start(&pile.listener, &pd->Timer);

  if(HTTPCombo == 1){
    tcp_http_send_SendACK(pd, true);
  }
}
void tcp_http_send_PeerClose(tcp_http_send_pd_t *pd){
  print("[-] http_send\n");

  pile.http_send_peer = NULL;

  EV_timer_stop(&pile.listener, &pd->Timer);
}
