typedef enum{
  http_state_Begin,
  http_state_recv_save,
  http_state_send,
  http_state_send_read_content
}http_state_t;

typedef enum{
  http_head_state_Unknown,
  http_head_state_recv,
  http_head_state_send
}http_head_state_t;

typedef struct{
  http_state_t state;

  union{
    struct{
      #ifdef set_ExtremeVerbose
        VEC_t HTTPData;
      #endif

      HTTP_decode_t hd;
      uint8_t HeadState;
      icack_t ack;
      uint64_t ContentLength;
    };
  };

  uint8_t LastHTTPType;
  uint64_t HTTPTypeCombo;

  union{
    struct{
      VEC_t vec;
    }recv;
    tcp_http_send_pd_t send;
  }d;
}tcp_http_pd_t;

void tcp_http_PeerReinit(NET_TCP_peer_t *p){
  tcp_http_pd_t *pd = (tcp_http_pd_t *)NET_TCP_GetPeerData(p, pile.http.extid);

  pd->state = http_state_Begin;
  #ifdef set_ExtremeVerbose
    pd->HTTPData.Current = 0;
  #endif
  HTTP_decode_init(&pd->hd);
  pd->HeadState = http_head_state_Unknown;
  pd->ContentLength = (uint64_t)-1;
}
void tcp_http_PeerOpen(NET_TCP_peer_t *p){
  tcp_http_pd_t *pd = (tcp_http_pd_t *)NET_TCP_GetPeerData(p, pile.http.extid);
  pd->state = http_state_Begin;

  #ifdef set_ExtremeVerbose
    VEC_init(&pd->HTTPData, 1, A_resize);
  #endif

  HTTP_decode_init(&pd->hd);
  pd->HeadState = http_head_state_Unknown;
  pd->ContentLength = (uint64_t)-1;

  pd->LastHTTPType = 0;
  pd->HTTPTypeCombo = 0;

  NET_TCP_StartReadLayer(p, pile.http.LayerReadID);
}
void tcp_http_PeerClose(NET_TCP_peer_t *p){
  tcp_http_pd_t *pd = (tcp_http_pd_t *)NET_TCP_GetPeerData(p, pile.http.extid);

  #ifdef set_ExtremeVerbose
    VEC_free(&pd->HTTPData);
  #endif

  if(pd->state == http_state_recv_save){
    VEC_free(&pd->d.recv.vec);
  }
  else if(pd->state == http_state_send){
    tcp_http_send_PeerClose(&pd->d.send);
  }
}

uint32_t
cb_tcp_http_connstate(
  NET_TCP_peer_t *peer,
  uint8_t *sd,
  tcp_http_pd_t *pd,
  uint32_t flag
){
  if(flag & NET_TCP_state_succ_e){
    tcp_http_PeerOpen(peer);
  }
  else do{
    if(!(flag & NET_TCP_state_init_e)){
      break;
    }

    tcp_http_PeerClose(peer);
  }while(0);

  return 0;
}

NET_TCP_layerflag_t
cb_tcp_http_read(
  NET_TCP_peer_t *peer,
  uint8_t *sd,
  tcp_http_pd_t *pd,
  NET_TCP_QueuerReference_t QueuerReference,
  uint32_t *type,
  NET_TCP_Queue_t *Queue
){
  common_BuildRecvData

  uintptr_t DataIndex = 0;

  while(DataIndex != DataSize){
    if(pd->state == http_state_Begin){
      HTTP_result_t result;
      #ifdef set_ExtremeVerbose
        uintptr_t BeforeDecodeIndex = DataIndex;
      #endif
      sint32_t ret = HTTP_decode(&pd->hd, Data, DataSize, &DataIndex, &result);
      #ifdef set_ExtremeVerbose
        VEC_print(&pd->HTTPData, "%.*s", DataIndex - BeforeDecodeIndex, &Data[BeforeDecodeIndex]);
      #endif
      if(ret < 0){
        if(ret == ~HTTP_DecodeError_Done_e){
          uint8_t LastHTTPType = pd->LastHTTPType;

          if(pd->HeadState == http_head_state_recv && pd->ContentLength != (uint64_t)-1 && pd->ContentLength >= sizeof(icack_t)){
            pd->LastHTTPType = 1;
            pd->state = http_state_recv_save;
            VEC_init(&pd->d.recv.vec, 1, A_resize);
          }
          else if(pd->HeadState == http_head_state_send){
            pd->LastHTTPType = 2;
            pd->state = http_state_send_read_content;
          }

          if(pd->state == http_state_Begin){
            #ifdef set_ExtremeVerbose
              print("http, unknown request\n%.*s\n", pd->HTTPData.Current, pd->HTTPData.ptr);
            #endif

            NET_TCP_CloseHard(peer);
            return NET_TCP_EXT_PeerIsClosed_e;
          }

          if(LastHTTPType != pd->LastHTTPType){
            pd->HTTPTypeCombo = 0;
          }

          pd->HTTPTypeCombo++;
        }
        else{
          NET_TCP_CloseHard(peer);
          return NET_TCP_EXT_PeerIsClosed_e;
        }
      }
      else{
        if(ret == HTTP_ResultType_head_e){
          const char *s0 = "POST";
          const char *s1 = "/image";
          const char *r0 = "POST";
          const char *r1 = "/uploadpfp";
          if(
            (MEM_cstreu(s0) == result.head.s[0] && STR_ncmp(s0, result.head.v[0], result.head.s[0]) == 0) &&
            (result.head.s[1] > MEM_cstreu(s1) && STR_ncmp(s1, result.head.v[1], MEM_cstreu(s1)) == 0)
          ){
            pd->HeadState = http_head_state_send;
            pd->ack = STR_psh32_digit(&result.head.v[1][MEM_cstreu(s1)], result.head.s[1] - MEM_cstreu(s1));
          }
          else if(
            (MEM_cstreu(r0) == result.head.s[0] && STR_ncmp(r0, result.head.v[0], result.head.s[0]) == 0) &&
            (MEM_cstreu(r1) == result.head.s[1] && STR_ncmp(r1, result.head.v[1], result.head.s[1]) == 0)
          ){
            pd->HeadState = http_head_state_recv;
          }
        }
        else if(ret == HTTP_ResultType_header_e){
          const char *cl_str = "Content-Length";
          if(
            MEM_cstreu(cl_str) == result.header.s[0] &&
            STR_ncmp(cl_str, result.header.v[0], result.header.s[0]) == 0
          ){
            pd->ContentLength = STR_psu64(result.header.v[1], result.header.s[1]);
          }
        }
      }
    }
    else if(pd->state == http_state_recv_save){
      uintptr_t left = DataSize - DataIndex;
      if(left > pd->ContentLength){
        left = pd->ContentLength;
      }
      VEC_print(&pd->d.recv.vec, "%.*s", left, &Data[DataIndex]);
      DataIndex += left;
      pd->ContentLength -= left;
      if(pd->ContentLength == 0){
        icack_t icack = *(icack_t *)pd->d.recv.vec.ptr;
        evprint("http http_state_recv_save came %lx\n", icack);

        uintptr_t icSize = pd->d.recv.vec.Current - sizeof(icack_t);
        uint8_t *icData = &pd->d.recv.vec.ptr[sizeof(icack_t)];

        if(icack >= pile.ic.dstack_to){
          pile.ic.dstack_to = icack + 1;
        }

        if(icack == pile.ic.dstack_at){
          pile.ic.dstack_at++;

          tcp_http_recv_pd_t tcp_http_recv_pd;
          tcp_http_recv_PeerOpen(&tcp_http_recv_pd);

          if(ProcessHTTPP(
            &tcp_http_recv_pd,
            icData,
            icSize
          ) != 0){
            NET_TCP_CloseHard(peer);
            return NET_TCP_EXT_PeerIsClosed_e;
          }

          while(pile.ic.dstack_at < pile.ic.dstack_to){
            ic_Packet_t *icp = ic_ackPacketMap_GetOutputPointerSafe(&pile.ic.dstPacketMap, &icack);
            if(icp == NULL){
              break;
            }

            if(ProcessHTTPP(
              &tcp_http_recv_pd,
              icp->Data,
              icp->Size
            ) != 0){
              NET_TCP_CloseHard(peer);
              return NET_TCP_EXT_PeerIsClosed_e;
            }

            A_resize(icp->Data, 0);
            ic_ackPacketMap_Remove(&pile.ic.dstPacketMap, &icack);
            pile.ic.dstack_at++;
          }

          tcp_http_recv_PeerClose(&tcp_http_recv_pd);
        }
        else if(icack > pile.ic.dstack_at){
          if(ic_ackPacketMap_DoesInputExists(&pile.ic.dstPacketMap, &icack) == false){
            ic_Packet_t icp;
            icp.Size = icSize;
            icp.Data = A_resize(NULL, icp.Size);

            ic_ackPacketMap_InNew(&pile.ic.dstPacketMap, &icack, &icp);
          }

          /* inform loss */
          PR_abort();
        }

        const char *StackData =
          "HTTP/1.1 200 OK\r\n"
          "Date: Tue, 10 Oct 2023 09:40:44 GMT\r\n"
          "Server: Apache\r\n"
          "Last-Modified: Tue, 01 Mar 2011 09:44:44 GMT\r\n"
          "ETag: \"26ce2-8c3c-49d68a5671b00\"\r\n"
          "Accept-Ranges: bytes\r\n"
          "Content-Length: 0\r\n"
          "X-Powered-By: PleskLin\r\n"
          "MS-Author-Via: DAV\r\n"
          "Connection: Keep-Alive\r\n\r\n";
        tcp_write_dp(peer, StackData, MEM_cstreu(StackData));

        tcp_http_PeerReinit(peer);
      }
    }
    else if(pd->state == http_state_send_read_content){
      uintptr_t left = DataSize - DataIndex;
      if(left > pd->ContentLength){
        left = pd->ContentLength;
      }
      DataIndex += left;
      pd->ContentLength -= left;
      if(pd->ContentLength == 0){
        pd->state = http_state_send;
        if(pile.http_send_peer != NULL){
          if(pile.http_send_peer == peer){
            NET_TCP_CloseHard(pile.http_send_peer);
            return NET_TCP_EXT_PeerIsClosed_e;
          }
          else{
            NET_TCP_CloseHard(pile.http_send_peer);
          }
        }
        pile.http_send_peer = peer;
        tcp_http_send_PeerOpen(&pd->d.send, pd->ack, pd->HTTPTypeCombo);
      }
    }
    else if(pd->state == http_state_send){
      evprint("http state is http_state_send and got data\n");

      NET_TCP_CloseHard(peer);
      return NET_TCP_EXT_PeerIsClosed_e;
    }
  }

  return 0;
}
