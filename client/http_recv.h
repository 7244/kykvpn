typedef enum{
  http_recv_state_Begin,
  http_recv_state_Save
}http_recv_state_t;

typedef enum{
  http_recv_ProcessState_Begin,
  http_recv_ProcessState_ConnectAnswer,
  http_recv_ProcessState_DropConnection,
  http_recv_ProcessState_Write,
  http_recv_ProcessState_Write_Data,
  http_recv_ProcessState_DNS,
  http_recv_ProcessState_DNS_Data
}http_recv_ProcessState_t;

typedef struct{
  http_recv_state_t state;

  union{
    struct{
      HTTP_decode_t hd;
      uint64_t ContentLength;
      uint8_t hd_combo;
    };
  };

  VEC_t vec; /* 1 */
}tcp_http_recv_pd_t;

void tcp_http_recv_PeerReinit(NET_TCP_peer_t *p){
  tcp_http_recv_pd_t *pd = (tcp_http_recv_pd_t *)NET_TCP_GetPeerData(p, pile.http_recv.extid);
  pd->state = http_recv_state_Begin;

  HTTP_decode_init(&pd->hd);
  pd->ContentLength = (uint64_t)-1;
  pd->hd_combo = 0;

  VEC_t vec;
  VEC_init(&vec, 1, A_resize);

  uint8_t FillerContent[64];
  for(uintptr_t i = 0; i < sizeof(FillerContent); i++){
    FillerContent[i] = RAND_bjprng32(i);
  }

  VEC_print(&vec,
    "POST /image%lx HTTP/1.1\r\n"
    "Host: 84.248.74.200\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
    "Accept-Encoding: gzip, deflate, br\r\n"
    "Accept-Language: en-US,en;q=0.9\r\n"
    "Cache-Control: no-cache\r\n"
    "Connection: Keep-Alive\r\n"
    "Content-Length: %u\r\n"
    "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36\r\n\r\n"
    "%.*s",
    pile.ic.dstack_at, sizeof(FillerContent), sizeof(FillerContent), FillerContent
  );
  tcp_write_dp(p, vec.ptr, vec.Current);

  VEC_free(&vec);
}

void tcp_http_recv_PeerOpen(NET_TCP_peer_t *p){
  print("[+] http_recv\n");

  NET_TCP_StartReadLayer(p, pile.http_recv.LayerReadID);

  tcp_http_recv_PeerReinit(p);
}
void tcp_http_recv_PeerClose(NET_TCP_peer_t *p){
  print("[-] http_recv\n");
  tcp_http_recv_pd_t *pd = (tcp_http_recv_pd_t *)NET_TCP_GetPeerData(p, pile.http_recv.extid);

  if(pd->state == http_recv_state_Save){
    VEC_free(&pd->vec);
  }
}

uint32_t
cb_tcp_http_recv_connstate(
  NET_TCP_peer_t *peer,
  uint8_t *sd,
  tcp_http_recv_pd_t *pd,
  uint32_t flag
){
  if(flag & NET_TCP_state_succ_e){
    tcp_http_recv_PeerOpen(peer);
  }
  else{
    if(flag & NET_TCP_state_init_e){
      tcp_http_recv_PeerClose(peer);
    }

    EV_timer_init(&pile.timer_http_recv, 0, timer_http_recv_connect_cb);
    EV_timer_start(&pile.listener, &pile.timer_http_recv);
  }

  return 0;
}

sint32_t ProcessHTTPP(const uint8_t *Data, uintptr_t DataSize){
  struct{
    http_recv_ProcessState_t state;

    uintptr_t CopyIndex;

    union{
      httpp_sc_ConnectAnswer_Head_t ConnectAnswer_Head;
      httpp_sc_DropConnection_Head_t DropConnection_Head;
      httpp_sc_Write_Head_t Write_Head;
      struct{
        httpp_sc_DNS_Head_t DNS_Head;
        uint8_t DNS_Data[0x800];
      };
    }d;
  }_pd;
  typeof(_pd) *pd = &_pd;
  pd->state = http_recv_ProcessState_Begin;
  pd->CopyIndex = 0;

  uintptr_t DataIndex = 0;

  while(DataIndex != DataSize){
    if(pd->state == http_recv_ProcessState_Begin){
      uint8_t t = Data[DataIndex++];
      if(t == httpp_sc_ConnectAnswer){pd->state = http_recv_ProcessState_ConnectAnswer;}
      else if(t == httpp_sc_DropConnection){pd->state = http_recv_ProcessState_DropConnection;}
      else if(t == httpp_sc_Write){pd->state = http_recv_ProcessState_Write;}
      else if(t == httpp_sc_DNS){pd->state = http_recv_ProcessState_DNS;}
      else{
        vprint("http_recv ProcessHTTPP httpp type is unknown %lx\n", t);
        return -1;
      }
    }
    else if(pd->state == http_recv_ProcessState_ConnectAnswer){
      if(COPY(&pd->d.ConnectAnswer_Head, sizeof(pd->d.ConnectAnswer_Head))) do{
        evprint("http_recv ConnectAnswer %lx %lx\n", pd->d.ConnectAnswer_Head.SessionID, pd->d.ConnectAnswer_Head.Result);

        pd->state = http_recv_ProcessState_Begin;

        SessionMap_Output_t *smo = SessionMap_GetOutputPointerSafe(&pile.SessionMap, &pd->d.ConnectAnswer_Head.SessionID);
        if(smo == NULL){
          break;
        }

        tcp_socks5_pd_t *SessionPD = (tcp_socks5_pd_t *)NET_TCP_GetPeerData(smo->peer, pile.socks5.extid);

        VEC_t vec;
        VEC_init(&vec, 1, A_resize);

        VEC_print(&vec, "%c", 0x05);
        VEC_print(&vec, "%c", pd->d.ConnectAnswer_Head.Result != httpp_sc_ConnectAnswer_Result_Success);
        VEC_print(&vec, "%c", 0);
        VEC_print(&vec, "%c", 0x01);
        VEC_print(&vec, "%c%c%c%c", 0, 0, 0, 0);
        VEC_print(&vec, "%c%c", 0, 0);

        tcp_write_dp(smo->peer, vec.ptr, vec.Current);

        VEC_free(&vec);

        if(pd->d.ConnectAnswer_Head.Result != httpp_sc_ConnectAnswer_Result_Success){
          NET_TCP_CloseHard(smo->peer);
        }
        else{
          tcp_socks5_PacketList_Open(&smo->PacketList);
          smo->TotalSize = 0;
          SessionPD->state = socks5_state_Connected;
        }
      }while(0);
    }
    else if(pd->state == http_recv_ProcessState_DropConnection){
      if(COPY(&pd->d.DropConnection_Head, sizeof(pd->d.DropConnection_Head))){
        evprint("http_recv DropConnection %lx\n", pd->d.DropConnection_Head.SessionID);

        pd->state = http_recv_ProcessState_Begin;

        SessionMap_Output_t *smo = SessionMap_GetOutputPointerSafe(&pile.SessionMap, &pd->d.DropConnection_Head.SessionID);
        if(smo != NULL){
          RemoveSession(pd->d.DropConnection_Head.SessionID);
        }
      }
    }
    else if(pd->state == http_recv_ProcessState_Write){
      if(COPY(&pd->d.Write_Head, sizeof(pd->d.Write_Head))){
        evprint("http_recv_ProcessState_Write %llx\n", pd->d.Write_Head.DataSize);
        if(pd->d.Write_Head.DataSize == 0){
          /* retarted */
          pd->state = http_recv_ProcessState_Begin;
        }
        else{
          pd->state = http_recv_ProcessState_Write_Data;
        }
      }
    }
    else if(pd->state == http_recv_ProcessState_Write_Data) do{
      uintptr_t left = DataSize - DataIndex;
      if(left >= pd->d.Write_Head.DataSize){
        left = pd->d.Write_Head.DataSize;
        pd->state = http_recv_ProcessState_Begin;
      }
      else{
        pd->d.Write_Head.DataSize -= left;
      }
      DataIndex += left;

      evprint("http_recv Write_Data %lx %x\n", pd->d.Write_Head.SessionID, left);

      SessionMap_Output_t *smo = SessionMap_GetOutputPointerSafe(&pile.SessionMap, &pd->d.Write_Head.SessionID);
      if(smo == NULL){
        break;
      }
      if(smo->peer == NULL){
        break;
      }

      tcp_write_dp(smo->peer, &Data[DataIndex - left], left);
    }while(0);
    else if(pd->state == http_recv_ProcessState_DNS){
      if(COPY(&pd->d.DNS_Head, sizeof(pd->d.DNS_Head))){
        evprint("http_recv_ProcessState_DNS %lx %lx\n", pd->d.DNS_Head.DNSID, pd->d.DNS_Head.Size);

        if(pd->d.DNS_Head.Size == 0){
          /* retarted */
          pd->state = http_recv_ProcessState_Begin;
        }
        else if(pd->d.DNS_Head.Size > 0x800 - 2){
          vprint("http_recv pd->d.DNS_Head.Size > 0x800 - 2. %lx\n", pd->d.DNS_Head.Size);
          return -1;
        }
        else{
          pd->state = http_recv_ProcessState_DNS_Data;
        }
      }
    }
    else if(pd->state == http_recv_ProcessState_DNS_Data) do{
      if(COPY(pd->d.DNS_Data, pd->d.DNS_Head.Size)){
        evprint("http_recv_ProcessState_DNS_Data %lx %lx\n", pd->d.DNS_Head.DNSID, pd->d.DNS_Head.Size);

        pd->state = http_recv_ProcessState_Begin;

        if(DNSMap_GetOutputPointerSafe(&pile.DNSMap, &pd->d.DNS_Head.DNSID) == NULL){
          vprint("http_recv dns does not exists, id %lx\n", pd->d.DNS_Head.DNSID);
          break;
        }

        DNSMap_Output_t *dnso = *DNSMap_GetOutputPointer(&pile.DNSMap, &pd->d.DNS_Head.DNSID);

        uint8_t UDPData[0x800];
        *(uint16_t *)&UDPData[0] = dnso->TransactionID;
        MEM_copy(pd->d.DNS_Data, &UDPData[2], pd->d.DNS_Head.Size);
        NET_sendto(&pile.DNSSocket, UDPData, pd->d.DNS_Head.Size + 2, &dnso->RecvAddress);

        RemoveDNSQuery(pd->d.DNS_Head.DNSID);
      }
    }while(0);
  }

  return 0;
}

NET_TCP_layerflag_t
cb_tcp_http_recv_read(
  NET_TCP_peer_t *peer,
  uint8_t *sd,
  tcp_http_recv_pd_t *pd,
  NET_TCP_QueuerReference_t QueuerReference,
  uint32_t *type,
  NET_TCP_Queue_t *Queue
){
  common_BuildRecvData

  uintptr_t DataIndex = 0;

  while(DataIndex != DataSize){
    if(pd->state == http_recv_state_Begin){
      HTTP_result_t result;
      sint32_t ret = HTTP_decode(&pd->hd, Data, DataSize, &DataIndex, &result);
      if(ret < 0){
        if(ret == ~HTTP_DecodeError_Done_e){
          if(
            pd->hd_combo != 4 ||
            pd->ContentLength < sizeof(icack_t)
          ){
            evprint("[http_recv close] http done with hd_combo %lx and content length %llx\n", pd->hd_combo, pd->ContentLength);
            evprint("here is part of content:\n");
            uintptr_t left = DataIndex - DataSize;
            if(left > pd->ContentLength){
              left = pd->ContentLength;
            }
            evprint("%.*s\n", left, &Data[DataIndex]);
            NET_TCP_CloseHard(peer);
            return NET_TCP_EXT_PeerIsClosed_e;
          }
          evprint("http_recv state became save, %llx\n", pd->ContentLength);
          pd->state = http_recv_state_Save;
          VEC_init(&pd->vec, 1, A_resize);
        }
        else{
          evprint("http_recv HTTP_decode error %ld\n", ret);
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
          const char *r10 = "Connection";
          const char *r11 = "Keep-Alive";
          if(MEM_cstreu(r00) == result.header.s[0] && STR_ncmp(r00, result.header.v[0], result.header.s[0]) == 0){
            pd->ContentLength = STR_psu64(result.header.v[1], result.header.s[1]);
            pd->hd_combo++;
          }
          else if(MEM_cstreu(r10) == result.header.s[0] && STR_ncmp(r10, result.header.v[0], result.header.s[0]) == 0){
            if(MEM_cstreu(r11) == result.header.s[1] && STR_ncasecmp(r11, result.header.v[1], result.header.s[1]) == 0){
              pd->hd_combo++;
            }
          }
        }
      }
    }
    else if(pd->state == http_recv_state_Save){
      uintptr_t left = DataSize - DataIndex;
      if(left > pd->ContentLength){
        left = pd->ContentLength;
      }
      VEC_print(&pd->vec, "%.*s", left, &Data[DataIndex]);
      DataIndex += left;
      pd->ContentLength -= left;
      if(pd->ContentLength == 0){
        icack_t icack = *(icack_t *)pd->vec.ptr;

        uintptr_t icSize = pd->vec.Current - sizeof(icack_t);
        uint8_t *icData = &pd->vec.ptr[sizeof(icack_t)];

        if(icack >= pile.ic.dstack_to){
          pile.ic.dstack_to = icack + 1;
        }

        if(icack == pile.ic.dstack_at){
          pile.ic.dstack_at++;

          if(ProcessHTTPP(icData,icSize) != 0){
            NET_TCP_CloseHard(peer);
            return NET_TCP_EXT_PeerIsClosed_e;
          }

          while(pile.ic.dstack_at < pile.ic.dstack_to){
            ic_Packet_t *icp = ic_ackPacketMap_GetOutputPointerSafe(&pile.ic.dstPacketMap, &icack);
            if(icp == NULL){
              break;
            }

            if(ProcessHTTPP(icp->Data, icp->Size) != 0){
              NET_TCP_CloseHard(peer);
              return NET_TCP_EXT_PeerIsClosed_e;
            }

            A_resize(icp->Data, 0);
            ic_ackPacketMap_Remove(&pile.ic.dstPacketMap, &icack);
            pile.ic.dstack_at++;
          }
        }
        else if(icack > pile.ic.dstack_at){
          if(ic_ackPacketMap_DoesInputExists(&pile.ic.dstPacketMap, &icack) == false){
            ic_Packet_t icp;
            icp.Size = icSize;
            icp.Data = A_resize(NULL, icp.Size);

            ic_ackPacketMap_InNew(&pile.ic.dstPacketMap, &icack, &icp);
          }

          print("dying, loss %lx %lx\n", icack, pile.ic.dstack_at);

          /* inform loss */
          PR_abort();
        }

        VEC_free(&pd->vec);
        tcp_http_recv_PeerReinit(peer);
      }
    }
  }

  return 0;
}
