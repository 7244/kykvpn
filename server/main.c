/*
#ifndef set_ExtremeVerbose
  #define set_ExtremeVerbose
#endif
*/

#ifndef set_DNS_Timeout
  #define set_DNS_Timeout 20000000000
#endif
#ifndef set_DNS_ServerIP
  #define set_DNS_ServerIP 0x01010101
#endif
#ifndef set_DNS_ServerPort
  #define set_DNS_ServerPort 53
#endif

#ifndef set_http_send_MaxSize
  #define set_http_send_MaxSize 0x7fff
#endif

#include "../common.h"

#define BLL_set_prefix tcp_da_PacketList
#define BLL_set_NodeData \
  uint8_t Data[0x200];
#define BLL_set_Language 0
/* TODO use witch constant */
#define BLL_set_UseUninitialisedValues 0
#include <WITCH/BLL/BLL.h>

typedef struct{
  NET_TCP_peer_t *peer;

  tcp_da_PacketList_t PacketList;
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
  uint16_t TransactionID;
  httpp_DNSID_t DNSID;
  EV_timer_t Timer;
}DNSMap_Output_t;

#define MAP_set_Prefix DNSMap
#define MAP_set_InputType uint16_t
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

  NET_TCP_peer_t *http_send_peer;
  tcppile_t http;

  tcppile_t da; /* direct access */

  uint16_t DNSTransactionID;
  NET_socket_t DNSSocket;
  EV_event_t DNSEvent;
  DNSMap_t DNSMap;
}pile_t;
pile_t pile;

uint8_t *SessionGetWriteData(SessionMap_Output_t *smo, uintptr_t *WantedSize){
  gt_Begin:;

  if(tcp_da_PacketList_Usage(&smo->PacketList) == 0){
    return NULL;
  }

  tcp_da_PacketList_NodeReference_t nr = tcp_da_PacketList_GetNodeFirst(&smo->PacketList);
  tcp_da_PacketList_Node_t *n = tcp_da_PacketList_GetNodeByReference(&smo->PacketList, nr);

  if(smo->FirstIndex == 0x200){
    smo->FirstIndex = 0;
    tcp_da_PacketList_unlrec(&smo->PacketList, nr);
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

void RemoveSession(SessionID_t);

void net_httpp_Write(SessionID_t, const void *, uintptr_t);
void net_httpp_ConnectAnswer(NET_TCP_peer_t *, httpp_sc_ConnectAnswer_Result_t);
void net_httpp_DropConnection(SessionID_t);

void tcp_http_PeerReinit(NET_TCP_peer_t *);

void cb_DNSTimer(EV_t *, EV_timer_t *);

#include "da.h"
#include "http_recv.h"
#include "http_send.h"
#include "http.h"

void RemoveSession(SessionID_t SessionID){
  SessionMap_Output_t *smo = SessionMap_GetOutputPointer(&pile.SessionMap, &SessionID);
  if(smo->peer != NULL){
    tcp_da_PacketList_Close(&smo->PacketList);
    NET_TCP_CloseSoft_MayConnecting(smo->peer);
  }
  else{
    tcp_da_PacketList_Close(&smo->PacketList);
  }
  
  SessionMap_Remove(&pile.SessionMap, &SessionID);
}

void net_httpp_Write(SessionID_t SessionID, const void *Data, uintptr_t DataSize){
  evprint("net_httpp_Write %lx %x\n", SessionID, DataSize);

  uintptr_t pbs = 1 + sizeof(httpp_sc_Write_Head_t); /* payload base size */
  uint8_t Payload[pbs + set_http_send_MaxSize];

  Payload[0] = httpp_sc_Write;

  httpp_sc_Write_Head_t *Head = (httpp_sc_Write_Head_t *)&Payload[1];
  Head->SessionID = SessionID;

  for(uintptr_t DataIndex = 0; DataIndex != DataSize;){
    if((sintptr_t)set_http_send_MaxSize - pile.SendBuffer.Current <= pbs){
      PackSendBuffer();
    }

    uintptr_t left = DataSize - DataIndex;
    if((sintptr_t)pbs + left > (sintptr_t)set_http_send_MaxSize - pile.SendBuffer.Current){
      left = set_http_send_MaxSize - pile.SendBuffer.Current - pbs;
    }
    Head->DataSize = left;
    MEM_copy(&((uint8_t *)Data)[DataIndex], &Head[1], left);
    VEC_print(&pile.SendBuffer, "%.*s", pbs + left, Payload);
    DataIndex += left;
  }
}

void net_httpp_ConnectAnswer(NET_TCP_peer_t *peer, httpp_sc_ConnectAnswer_Result_t Result){
  tcp_da_pd_t *pd = (tcp_da_pd_t *)NET_TCP_GetPeerData(peer, pile.da.extid);

  evprint("net_httpp_ConnectAnswer %lx %lx\n", pd->SessionID, Result);

  uint8_t Payload[1 + sizeof(httpp_sc_ConnectAnswer_Head_t)];

  Payload[0] = httpp_sc_ConnectAnswer;

  httpp_sc_ConnectAnswer_Head_t *Head = (httpp_sc_ConnectAnswer_Head_t *)&Payload[1];
  Head->SessionID = pd->SessionID;
  Head->Result = Result;

  VEC_print(&pile.SendBuffer, "%.*s", sizeof(Payload), Payload);
}

void net_httpp_DropConnection(SessionID_t SessionID){
  evprint("net_httpp_DropConnection %lx\n", SessionID);

  uint8_t Payload[1 + sizeof(httpp_sc_DropConnection_Head_t)];

  Payload[0] = httpp_sc_DropConnection;

  httpp_sc_DropConnection_Head_t *Head = (httpp_sc_DropConnection_Head_t *)&Payload[1];
  Head->SessionID = SessionID;

  VEC_print(&pile.SendBuffer, "%.*s", sizeof(Payload), Payload);
}

void net_httpp_DNS(httpp_DNSID_t DNSID, const void *Data, uintptr_t DataSize){
  evprint("net_httpp_DNS\n");

  uint8_t Payload[1 + sizeof(httpp_sc_DNS_Head_t) + DataSize];

  Payload[0] = httpp_sc_DNS;

  httpp_sc_DNS_Head_t *h = (httpp_sc_DNS_Head_t *)&Payload[1];
  h->DNSID = DNSID;
  h->Size = DataSize;

  MEM_copy(Data, &h[1], DataSize);

  VEC_print(&pile.SendBuffer, "%.*s", sizeof(Payload), Payload);
}

void RemoveDNSQuery(uint16_t TransactionID){
  DNSMap_Output_t *dnso = *DNSMap_GetOutputPointer(&pile.DNSMap, &TransactionID);
  EV_timer_stop(&pile.listener, &dnso->Timer);
  A_resize(dnso, 0);
  DNSMap_Remove(&pile.DNSMap, &TransactionID);
}

void cb_DNSTimer(EV_t *l, EV_timer_t *t){
  DNSMap_Output_t *dnso = OFFSETLESS(t, DNSMap_Output_t, Timer);
  RemoveDNSQuery(dnso->TransactionID);
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

  if(RecvAddress.ip != set_DNS_ServerIP){
    return;
  }
  if(RecvAddress.port != set_DNS_ServerPort){
    return;
  }

  uint16_t TransactionID = *(uint16_t *)Data;

  if(DNSMap_GetOutputPointerSafe(&pile.DNSMap, &TransactionID) == NULL){
    return;
  }

  DNSMap_Output_t *dnso = *DNSMap_GetOutputPointer(&pile.DNSMap, &TransactionID);

  net_httpp_DNS(dnso->DNSID, &Data[2], DataSize - 2);

  RemoveDNSQuery(TransactionID);
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
    tcppile_Open(&pile.da, sizeof(tcp_da_pd_t), cb_tcp_da_connstate, cb_tcp_da_read);
  }
  {
    tcppile_Open(&pile.http, sizeof(tcp_http_pd_t), cb_tcp_http_connstate, cb_tcp_http_read);
    pile.http.tcp->ssrcaddr.port = 80;
    if(NET_TCP_listen(pile.http.tcp) != 0){
      PR_abort();
    }
    EV_event_start(&pile.listener, &pile.http.tcp->ev);
  }

  {
    pile.DNSTransactionID = 0;

    sint32_t err = NET_socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP, &pile.DNSSocket);
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
