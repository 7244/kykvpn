/*
#ifndef set_ExtremeVerbose
  #define set_ExtremeVerbose
#endif
*/

#ifndef set_ServerIP
  #define set_ServerIP 0x7f000001
#endif
#ifndef set_ServerPort
  #define set_ServerPort 80
#endif

#ifndef set_DNS_Timeout
  #define set_DNS_Timeout 20000000000
#endif

#ifndef set_http_send_MaxSize
  #define set_http_send_MaxSize 0x7fff
#endif

#include "../common.h"

#define BLL_set_prefix tcp_socks5_PacketList
#define BLL_set_NodeData \
  uint8_t Data[0x200];
#define BLL_set_Usage 1
#define BLL_set_Language 0
#include <BLL/BLL.h>

typedef struct{
  NET_TCP_peer_t *peer;

  tcp_socks5_PacketList_t PacketList;
  uintptr_t TotalSize;
  uintptr_t FirstIndex;
}SessionMap_Output_t;
#define MAP_set_Prefix SessionMap
#define MAP_set_InputType SessionID_t
#define MAP_set_OutputType SessionMap_Output_t
#define MAP_set_MaxInput 0xffffffff
#include <WITCH/MAP/MAP.h>

typedef struct{
  uintptr_t Size;
  void *Data;
}ic_Packet_t;

#define MAP_set_Prefix ic_ackPacketMap
#define MAP_set_InputType icack_t
#define MAP_set_OutputType ic_Packet_t
#define MAP_set_MaxInput 0xffffffff
#include <WITCH/MAP/MAP.h>

typedef struct{
  httpp_DNSID_t DNSID;
  uint16_t TransactionID;
  NET_addr_t RecvAddress;
  EV_timer_t Timer;
}DNSMap_Output_t;

#define MAP_set_Prefix DNSMap
#define MAP_set_InputType httpp_DNSID_t
#define MAP_set_OutputType DNSMap_Output_t *
#define MAP_set_MaxInput 0xffffffff
#include <WITCH/MAP/MAP.h>

typedef struct{
  EV_t listener;

  struct{
    icack_t srcack_to;
    icack_t srcack_at;
    icack_t dstack_to;
    icack_t dstack_at;

    ic_ackPacketMap_t srcPacketMap;
    ic_ackPacketMap_t dstPacketMap;
  }ic;

  SessionMap_t SessionMap;

  VEC_t SendBuffer; /* 1 */

  tcppile_t socks5;
  SessionID_t SessionID;

  tcppile_t http_send;
  NET_TCP_peer_t *http_send_peer;

  tcppile_t http_recv;

  EV_timer_t timer_http_send;
  EV_timer_t timer_http_recv;

  httpp_DNSID_t DNSID;
  NET_socket_t DNSSocket;
  EV_event_t DNSEvent;
  DNSMap_t DNSMap;
}pile_t;
pile_t pile;

uint8_t *SessionGetWriteData(SessionMap_Output_t *smo, uintptr_t *WantedSize){
  gt_Begin:;

  if(tcp_socks5_PacketList_Usage(&smo->PacketList) == 0){
    return NULL;
  }

  tcp_socks5_PacketList_NodeReference_t nr = tcp_socks5_PacketList_GetNodeFirst(&smo->PacketList);
  tcp_socks5_PacketList_Node_t *n = tcp_socks5_PacketList_GetNodeByReference(&smo->PacketList, nr);

  if(smo->FirstIndex == 0x200){
    smo->FirstIndex = 0;
    tcp_socks5_PacketList_unlrec(&smo->PacketList, nr);
    goto gt_Begin;
  }

  uintptr_t BlockSize = 0x200 - smo->FirstIndex;
  if(BlockSize > smo->TotalSize){
    BlockSize = smo->TotalSize;
  }
  if(*WantedSize > BlockSize){
    *WantedSize = BlockSize;
  }

  if(*WantedSize == 0){
    return NULL;
  }

  uint8_t *r = &n->data.Data[smo->FirstIndex];

  smo->FirstIndex += *WantedSize;
  smo->TotalSize -= *WantedSize;

  return r;
}

void timer_http_send_connect_cb(EV_t *l, EV_timer_t *t){
  NET_addr_t addr;
  addr.ip = set_ServerIP;
  addr.port = set_ServerPort;
  if(tcp_connect(pile.http_send.tcp, &addr) == NULL){
    EV_timer_stop(l, t);
    EV_timer_init(t, 1, timer_http_send_connect_cb);
    EV_timer_start(l, t);
    return;
  }
  EV_timer_stop(l, t);
}
void timer_http_recv_connect_cb(EV_t *l, EV_timer_t *t){
  NET_addr_t addr;
  addr.ip = set_ServerIP;
  addr.port = set_ServerPort;
  if(tcp_connect(pile.http_recv.tcp, &addr) == NULL){
    EV_timer_stop(l, t);
    EV_timer_init(t, 1, timer_http_recv_connect_cb);
    EV_timer_start(l, t);
    return;
  }
  EV_timer_stop(l, t);
}

void RemoveSession(SessionID_t);

void net_httpp_Connect_ipv4(NET_TCP_peer_t *);
void net_httpp_DropConnection_SessionID(SessionID_t);
void net_httpp_DropConnect(NET_TCP_peer_t *);
void net_httpp_Write(SessionID_t, const void *, uintptr_t);
void net_httpp_FillerWrite(void);

void RemoveDNSQuery(httpp_DNSID_t);

#include "socks5.h"
#include "http_send.h"
#include "http_recv.h"

void RemoveSession(SessionID_t SessionID){
  SessionMap_Output_t *smo = SessionMap_GetOutputPointer(&pile.SessionMap, &SessionID);
  if(smo->peer != NULL){
    tcp_socks5_pd_t *pd = (tcp_socks5_pd_t *)NET_TCP_GetPeerData(smo->peer, pile.http_send.extid);
    if(pd->state == socks5_state_Connected){
      tcp_socks5_PacketList_Close(&smo->PacketList);
      NET_TCP_CloseSoft(smo->peer);
    }
    else{
      NET_TCP_CloseHard(smo->peer);
    }
  }
  else{
    tcp_socks5_PacketList_Close(&smo->PacketList);
  }
  
  SessionMap_Remove(&pile.SessionMap, &SessionID);
}

void net_httpp_Connect_ipv4(NET_TCP_peer_t *p){
  tcp_socks5_pd_t *pd = (tcp_socks5_pd_t *)NET_TCP_GetPeerData(p, pile.socks5.extid);

  pd->SessionID = pile.SessionID++;

  evprint("net_httpp_Connect_ipv4 %lx\n", pd->SessionID);

  SessionMap_Output_t smo;
  smo.peer = p;
  SessionMap_InNew(&pile.SessionMap, &pd->SessionID, &smo);
  pd->state = socks5_state_WaitingConnect;

  uint8_t Payload[1 + sizeof(httpp_cc_ConnectHead_t) + sizeof(uint32_t)];

  Payload[0] = httpp_cc_Connect;

  httpp_cc_ConnectHead_t *ConnectHead = (httpp_cc_ConnectHead_t *)&Payload[1];
  ConnectHead->SessionID = pd->SessionID;
  if(pd->CMD == 0x01){
    ConnectHead->Mode = httpp_ConnectMode_TCP;
  }
  else{
    PR_abort();
  }
  ConnectHead->AddressType = httpp_ConnectAddressType_IPV4;
  ConnectHead->Port = pd->dstAddress.port;

  *(uint32_t *)&ConnectHead[1] = pd->dstAddress.ip;

  VEC_print(&pile.SendBuffer, "%.*s", sizeof(Payload), Payload);
}
void net_httpp_DropConnection_SessionID(SessionID_t SessionID){
  evprint("net_httpp_DropConnection_SessionID %lx\n", SessionID);

  uint8_t Payload[1 + sizeof(httpp_cc_DropConnection_t)];

  Payload[0] = httpp_cc_DropConnection;

  httpp_cc_DropConnection_t *rest = (httpp_cc_DropConnection_t *)&Payload[1];
  rest->SessionID = SessionID;

  VEC_print(&pile.SendBuffer, "%.*s", sizeof(Payload), Payload);
}
void net_httpp_DropConnect(NET_TCP_peer_t *p){
  tcp_socks5_pd_t *pd = (tcp_socks5_pd_t *)NET_TCP_GetPeerData(p, pile.socks5.extid);

  SessionMap_Remove(&pile.SessionMap, &pd->SessionID);

  net_httpp_DropConnection_SessionID(pd->SessionID);
}
void net_httpp_Write(SessionID_t SessionID, const void *Data, uintptr_t DataSize){
  uint8_t Payload[1 + sizeof(httpp_cc_Write_Head_t) + DataSize];

  Payload[0] = httpp_cc_Write;

  httpp_cc_Write_Head_t *Head = (httpp_cc_Write_Head_t *)&Payload[1];
  Head->SessionID = SessionID;
  Head->DataSize = DataSize;

  __builtin_memcpy(&Head[1], Data, DataSize);

  VEC_print(&pile.SendBuffer, "%.*s", sizeof(Payload), Payload);

  evprint("net_httpp_Write %lx %x\n", SessionID, sizeof(Payload));
}
void net_httpp_DNS(httpp_DNSID_t DNSID, const void *Data, uintptr_t DataSize){
  evprint("net_httpp_DNS %lx %x\n", DNSID, DataSize);

  uint8_t Payload[1 + sizeof(httpp_cc_DNS_Head_t) + DataSize];

  Payload[0] = httpp_cc_DNS;

  httpp_cc_DNS_Head_t *h = (httpp_cc_DNS_Head_t *)&Payload[1];
  h->DNSID = DNSID;
  h->Size = DataSize;

  __builtin_memcpy(&h[1], Data, DataSize);

  VEC_print(&pile.SendBuffer, "%.*s", sizeof(Payload), Payload);
}

void RemoveDNSQuery(httpp_DNSID_t DNSID){
  DNSMap_Output_t *dnso = *DNSMap_GetOutputPointer(&pile.DNSMap, &DNSID);
  EV_timer_stop(&pile.listener, &dnso->Timer);
  A_resize(dnso, 0);
  DNSMap_Remove(&pile.DNSMap, &DNSID);
}

void cb_DNSTimer(EV_t *l, EV_timer_t *t){
  DNSMap_Output_t *dnso = OFFSETLESS(t, DNSMap_Output_t, Timer);
  RemoveDNSQuery(dnso->DNSID);
}

void cb_DNSEvent(EV_t *l, EV_event_t *e, uint32_t f){
  NET_addr_t RecvAddress;
  uint8_t Data[0x800];
  IO_ssize_t DataSize = NET_recvfrom(&pile.DNSSocket, Data, sizeof(Data), &RecvAddress);
  if(DataSize < 0){
    PR_abort();
  }
  else if(DataSize <= 2){
    return;
  }

  DNSMap_Output_t *dnso = (DNSMap_Output_t *)A_resize(NULL, sizeof(DNSMap_Output_t));
  dnso->DNSID = pile.DNSID++;
  dnso->TransactionID = *(uint16_t *)Data;
  dnso->RecvAddress = RecvAddress;
  EV_timer_init(&dnso->Timer, (f64_t)set_DNS_Timeout / 1000000000, cb_DNSTimer);
  EV_timer_start(&pile.listener, &dnso->Timer);

  if(DNSMap_GetOutputPointerSafe(&pile.DNSMap, &dnso->DNSID) != NULL){
    RemoveDNSQuery(dnso->DNSID);
  }

  DNSMap_InNew(&pile.DNSMap, &dnso->DNSID, &dnso);

  net_httpp_DNS(dnso->DNSID, &Data[2], DataSize - 2);
}

int main(){
  EV_open(&pile.listener);

  pile.ic.srcack_at = 0;
  pile.ic.srcack_to = 0;
  pile.ic.dstack_to = 0;
  pile.ic.dstack_at = 0;

  ic_ackPacketMap_Open(&pile.ic.srcPacketMap);
  ic_ackPacketMap_Open(&pile.ic.dstPacketMap);

  SessionMap_Open(&pile.SessionMap);

  VEC_init(&pile.SendBuffer, 1, A_resize);

  {
    tcppile_Open(&pile.socks5, sizeof(tcp_socks5_pd_t), cb_tcp_socks5_connstate, cb_tcp_socks5_read);
    pile.socks5.tcp->ssrcaddr.port = 8080;
    if(NET_TCP_listen(pile.socks5.tcp) != 0){
      PR_abort();
    }
    EV_event_start(&pile.listener, &pile.socks5.tcp->ev);
    pile.SessionID = 0;
  }
  {
    tcppile_Open(&pile.http_send, sizeof(tcp_http_send_pd_t), cb_tcp_http_send_connstate, cb_tcp_http_send_read);
    pile.http_send_peer = NULL;
    EV_timer_init(&pile.timer_http_send, 0, timer_http_send_connect_cb);
    EV_timer_start(&pile.listener, &pile.timer_http_send);
  }
  {
    tcppile_Open(&pile.http_recv, sizeof(tcp_http_recv_pd_t), cb_tcp_http_recv_connstate, cb_tcp_http_recv_read);
    EV_timer_init(&pile.timer_http_recv, 0, timer_http_recv_connect_cb);
    EV_timer_start(&pile.listener, &pile.timer_http_recv);
  }

  {
    pile.DNSID = 0;

    sint32_t err = NET_socket2(NET_AF_INET, NET_SOCK_DGRAM | NET_SOCK_NONBLOCK, NET_IPPROTO_UDP, &pile.DNSSocket);
    if(err != 0){
      PR_abort();
    }

    NET_addr_t addr;
    addr.ip = NET_INADDR_ANY;
    addr.port = 10053;
    err = NET_bind(&pile.DNSSocket, &addr);
    if(err != 0){
      PR_abort();
    }

    EV_event_init_socket(&pile.DNSEvent, &pile.DNSSocket, cb_DNSEvent, EV_READ);
    EV_event_start(&pile.listener, &pile.DNSEvent);

    DNSMap_Open(&pile.DNSMap);
  }

  evprint("EV_start\n");
  EV_start(&pile.listener);

  return 0;
}
