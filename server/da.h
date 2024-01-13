typedef struct{
  SessionID_t SessionID;
}tcp_da_pd_t;

void tcp_da_PeerOpen(NET_TCP_peer_t *p){
  tcp_da_pd_t *pd = (tcp_da_pd_t *)NET_TCP_GetPeerData(p, pile.da.extid);

  NET_TCP_StartReadLayer(p, pile.da.LayerReadID);

  net_httpp_ConnectAnswer(p, 0);
}

void tcp_da_PushConnectedData(SessionMap_Output_t *o, void *Data, uintptr_t DataSize){
  uintptr_t DataIndex = 0;
  tcp_da_PacketList_NodeReference_t lnr = tcp_da_PacketList_GetNodeLast(&o->PacketList);
  tcp_da_PacketList_Node_t *ln;
  if(lnr.NRI == o->PacketList.src.NRI){ /* TODO dont access NRI */
    o->FirstIndex = 0;
    goto gt_StartNew;
  }

  uintptr_t m = (o->FirstIndex + o->TotalSize) % sizeof(ln->data.Data);
  if(m == 0){
    goto gt_StartNew;
  }

  ln = tcp_da_PacketList_GetNodeByReference(&o->PacketList, lnr);
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
    lnr = tcp_da_PacketList_NewNodeLast(&o->PacketList);
    ln = tcp_da_PacketList_GetNodeByReference(&o->PacketList, lnr);

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

uint32_t
cb_tcp_da_connstate(
  NET_TCP_peer_t *peer,
  uint8_t *sd,
  tcp_da_pd_t *pd,
  uint32_t flag
){
  if(flag & NET_TCP_state_succ_e){
    tcp_da_PeerOpen(peer);
  }
  else do{
    SessionMap_Output_t *smo = SessionMap_GetOutputPointerSafe(&pile.SessionMap, &pd->SessionID);
    if(flag & NET_TCP_state_init_e){
      if(smo == NULL){
        break;
      }
      smo->peer = NULL;
    }
    else{
      net_httpp_ConnectAnswer(peer, 1);
      if(smo == NULL){
        break;
      }
      smo->peer = NULL;
      RemoveSession(pd->SessionID);
    }
  }while(0);

  return 0;
}

NET_TCP_layerflag_t
cb_tcp_da_read(
  NET_TCP_peer_t *peer,
  uint8_t *sd,
  tcp_da_pd_t *pd,
  NET_TCP_QueuerReference_t QueuerReference,
  uint32_t *type,
  NET_TCP_Queue_t *Queue
){
  common_BuildRecvData

  SessionMap_Output_t *smo;
  smo = SessionMap_GetOutputPointerSafe(&pile.SessionMap, &pd->SessionID);
  if(smo == NULL){ /* we are in closesoft and RemoveSession came */
    return NET_TCP_EXT_dontgo_e;
  }
  if(smo->peer == NULL){ /* we are in closesoft */
    return NET_TCP_EXT_dontgo_e;
  }

  tcp_da_PushConnectedData(smo, Data, DataSize);

  return 0;
}
