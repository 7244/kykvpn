typedef enum{
  socks5_state_GetVersion,
  socks5_state_GetNAuth,
  socks5_state_GetAuth,
  socks5_state_GetCVersion, /* get connect version */
  socks5_state_GetCMD,
  socks5_state_GetRSV,
  socks5_state_GetAddressType,
  socks5_state_GetAddress,
  socks5_state_GetPort,
  socks5_state_WaitingConnect,
  socks5_state_Connected
}socks5_state_t;

typedef struct{
  socks5_state_t state;
  uint8_t CopyIndex;
  union{
    struct{
      uint8_t NAuth;
      uint8_t Auth[0x100];
    }GetAuth;
    struct{
      uint8_t Type;
      union{
        uint8_t ipv4[0x04];
        uint8_t ipv6[0x10];
        struct{
          uint8_t Size;
          uint8_t Data[0x100];
        }Domain;
      };
    }GetAddress;
  }sod; /* socks data */
  uint8_t CMD;
  NET_addr_t dstAddress;
  SessionID_t SessionID;
}tcp_socks5_pd_t;

void tcp_socks5_PushConnectedData(SessionMap_Output_t *o, void *Data, uintptr_t DataSize){
  uintptr_t DataIndex = 0;
  tcp_socks5_PacketList_NodeReference_t lnr = tcp_socks5_PacketList_GetNodeLast(&o->PacketList);
  tcp_socks5_PacketList_Node_t *ln;
  if(lnr.NRI == o->PacketList.src.NRI){ /* TODO dont access NRI */
    o->FirstIndex = 0;
    goto gt_StartNew;
  }

  uintptr_t m = (o->FirstIndex + o->TotalSize) % sizeof(ln->data.Data);
  if(m == 0){
    goto gt_StartNew;
  }

  ln = tcp_socks5_PacketList_GetNodeByReference(&o->PacketList, lnr);
  {
    uintptr_t LastLeftSize = sizeof(ln->data.Data) - m;

    uintptr_t Left = DataSize - DataIndex;
    if(Left > LastLeftSize){
      Left = LastLeftSize;
      MEM_copy(&((uint8_t *)Data)[DataIndex], &ln->data.Data[m], Left);
      DataIndex += Left;
      o->TotalSize += Left;
    }
    else{
      MEM_copy(&((uint8_t *)Data)[DataIndex], &ln->data.Data[m], Left);
      o->TotalSize += Left;
      return;
    }
  }

  gt_StartNew:;
  while(1){
    lnr = tcp_socks5_PacketList_NewNodeLast(&o->PacketList);
    ln = tcp_socks5_PacketList_GetNodeByReference(&o->PacketList, lnr);

    uintptr_t Left = DataSize - DataIndex;
    if(Left > sizeof(ln->data.Data)){
      Left = sizeof(ln->data.Data);
      MEM_copy(&((uint8_t *)Data)[DataIndex], ln->data.Data, Left);
      DataIndex += Left;
      o->TotalSize += Left;
    }
    else{
      MEM_copy(&((uint8_t *)Data)[DataIndex], ln->data.Data, Left);
      o->TotalSize += Left;
      return;
    }
  }
}

void tcp_socks5_PeerOpen(NET_TCP_peer_t *p){
  tcp_socks5_pd_t *pd = (tcp_socks5_pd_t *)NET_TCP_GetPeerData(p, pile.socks5.extid);
  pd->state = socks5_state_GetVersion;
  pd->CopyIndex = 0;

  NET_TCP_StartReadLayer(p, pile.socks5.LayerReadID);
}
void tcp_socks5_PeerClose(NET_TCP_peer_t *p){
  tcp_socks5_pd_t *pd = (tcp_socks5_pd_t *)NET_TCP_GetPeerData(p, pile.socks5.extid);

  if(pd->state == socks5_state_WaitingConnect){
    net_httpp_DropConnect(p);
  }
  else if(pd->state == socks5_state_Connected) do{
    SessionMap_Output_t *smo = SessionMap_GetOutputPointerSafe(&pile.SessionMap, &pd->SessionID);
    if(smo == NULL){
      break;
    }
    smo->peer = NULL;
  }while(0);
}

uint32_t
cb_tcp_socks5_connstate(
  NET_TCP_peer_t *peer,
  uint8_t *sd,
  tcp_socks5_pd_t *pd,
  uint32_t flag
){
  if(flag & NET_TCP_state_succ_e){
    tcp_socks5_PeerOpen(peer);
  }
  else do{
    if(!(flag & NET_TCP_state_init_e)){
      break;
    }

    tcp_socks5_PeerClose(peer);
  }while(0);

  return 0;
}


NET_TCP_layerflag_t
cb_tcp_socks5_read(
  NET_TCP_peer_t *peer,
  uint8_t *sd,
  tcp_socks5_pd_t *pd,
  NET_TCP_QueuerReference_t QueuerReference,
  uint32_t *type,
  NET_TCP_Queue_t *Queue
){
  common_BuildRecvData

  SessionMap_Output_t *smo;
  if(pd->state >= socks5_state_WaitingConnect){
    smo = SessionMap_GetOutputPointerSafe(&pile.SessionMap, &pd->SessionID);
    if(smo == NULL){ /* we are in closesoft */
      return NET_TCP_EXT_dontgo_e;
    }
  }

  uintptr_t DataIndex = 0;

  while(DataIndex != DataSize){
    if(pd->state == socks5_state_GetVersion){
      if(Data[DataIndex++] != 0x05){
        /* we only support socks5 */
        NET_TCP_CloseHard(peer);
        return NET_TCP_EXT_PeerIsClosed_e;
      }
      pd->state = socks5_state_GetNAuth;
    }
    else if(pd->state == socks5_state_GetNAuth){
      pd->sod.GetAuth.NAuth = Data[DataIndex++];
      if(pd->sod.GetAuth.NAuth == 0){
        NET_TCP_CloseHard(peer);
        return NET_TCP_EXT_PeerIsClosed_e;
      }
      pd->state = socks5_state_GetAuth;
    }
    else if(pd->state == socks5_state_GetAuth){
      if(COPY(pd->sod.GetAuth.Auth, pd->sod.GetAuth.NAuth)){
        bool NoAuth = 0;
        for(uint32_t i = 0; i < pd->sod.GetAuth.NAuth; i++){
          if(pd->sod.GetAuth.Auth[i] == 0){
            NoAuth = true;
          }
        }
        if(NoAuth == 0){
          NET_TCP_CloseHard(peer);
          return NET_TCP_EXT_PeerIsClosed_e;
        }
        uint8_t d[2] = {0x05, 0};
        tcp_write_dp(peer, d, 2);
        pd->state = socks5_state_GetCVersion;
      }
    }
    else if(pd->state == socks5_state_GetCVersion){
      if(Data[DataIndex++] != 0x05){
        NET_TCP_CloseHard(peer);
        return NET_TCP_EXT_PeerIsClosed_e;
      }
      pd->state = socks5_state_GetCMD;
    }
    else if(pd->state == socks5_state_GetCMD){
      pd->CMD = Data[DataIndex++];
      pd->state = socks5_state_GetRSV;
    }
    else if(pd->state == socks5_state_GetRSV){
      if(Data[DataIndex++] != 0){
        NET_TCP_CloseHard(peer);
        return NET_TCP_EXT_PeerIsClosed_e;
      }
      pd->state = socks5_state_GetAddressType;
    }
    else if(pd->state == socks5_state_GetAddressType){
      pd->sod.GetAddress.Type = Data[DataIndex++];
      pd->sod.GetAddress.Domain.Size = 0;
      pd->state = socks5_state_GetAddress;
    }
    else if(pd->state == socks5_state_GetAddress){
      if(pd->sod.GetAddress.Type == 0x03){
        if(pd->sod.GetAddress.Domain.Size == 0){
          pd->sod.GetAddress.Domain.Size = Data[DataIndex++];
          if(pd->sod.GetAddress.Domain.Size == 0){
            NET_TCP_CloseHard(peer);
            return NET_TCP_EXT_PeerIsClosed_e;
          }
        }
        else{
          if(COPY(pd->sod.GetAddress.Domain.Data, pd->sod.GetAddress.Domain.Size)){
            print("domain request %.*s\n", (uintptr_t)pd->sod.GetAddress.Domain.Size, pd->sod.GetAddress.Domain.Data);
            NET_TCP_CloseHard(peer);
            return NET_TCP_EXT_PeerIsClosed_e;
          }
        }
      }
      else if(pd->sod.GetAddress.Type == 0x01){
        if(COPY(pd->sod.GetAddress.ipv4, 4)){
          pd->dstAddress.ip = byteswap32(*(uint32_t *)pd->sod.GetAddress.ipv4);
          pd->state = socks5_state_GetPort;
        }
      }
      else if(pd->sod.GetAddress.Type == 0x04){
        if(COPY(pd->sod.GetAddress.ipv6, 0x10)){
          print("ipv6 is not supported\n");
          NET_TCP_CloseHard(peer);
          return NET_TCP_EXT_PeerIsClosed_e;
        }
      }
      else{
        NET_TCP_CloseHard(peer);
        return NET_TCP_EXT_PeerIsClosed_e;
      }
    }
    else if(pd->state == socks5_state_GetPort){
      if(COPY(&pd->dstAddress.port, 2)){
        pd->dstAddress.port = byteswap16(pd->dstAddress.port);
        if(pd->CMD == 0x01){
          net_httpp_Connect_ipv4(peer);
        }
        else if(pd->CMD == 0x03){
          print("udp not supported yet\n");
          PR_exit(0);
          uint8_t d[4 + sizeof(NET_addr_t)] = {0x05, 0, 0, 1};
          (*(NET_addr_t *)&d[4]).ip = byteswap32(pd->dstAddress.ip);
          (*(NET_addr_t *)&d[4]).port = byteswap16(pd->dstAddress.port);
          tcp_write_dp(peer, d, sizeof(d));
          pd->state = socks5_state_Connected;
        }
        else{
          print("unknown cmd %lx\n", pd->CMD);
          PR_abort();
        }
      }
    }
    else if(pd->state == socks5_state_WaitingConnect){
      NET_TCP_CloseHard(peer);
      return NET_TCP_EXT_PeerIsClosed_e;
    }
    else if(pd->state == socks5_state_Connected){
      tcp_socks5_PushConnectedData(smo, Data, DataSize);
      DataIndex = DataSize;
    }
  }

  return 0;
}
