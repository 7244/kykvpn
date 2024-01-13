uintptr_t BaseWriteSize = 1 + sizeof(httpp_cc_Write_Head_t);

uintptr_t WriteCount = 0;

SessionMap_Iterate_t smit;
SessionMap_Iterate_Open(&pile.SessionMap, &smit);
while(1){
  SessionMap_Output_t *smo;
  SessionID_t SessionID;
  if((smo = SessionMap_Iterate(&pile.SessionMap, &smit, &SessionID)) == NULL){
    break;
  }
  if(smo->peer == NULL){
    if(!smo->TotalSize){
      RemoveSession(SessionID);
      net_httpp_DropConnection_SessionID(SessionID);
    }
    else{
      WriteCount++;
    }
  }
  else{
    tcp_socks5_pd_t *pd = (tcp_socks5_pd_t *)NET_TCP_GetPeerData(smo->peer, pile.http_send.extid);
    if(pd->state != socks5_state_Connected){
      continue;
    }
    if(smo->TotalSize != 0){
      WriteCount++;
    }
  }
}
SessionMap_Iterate_Close(&pile.SessionMap, &smit);

uintptr_t Size;

if(WriteCount == 0){
  goto gt_NoWrite;
}

{
  SessionID_t SessionArrayID[WriteCount];
  uintptr_t SessionArraySize[WriteCount];
  WriteCount = 0;

  SessionMap_Iterate_Open(&pile.SessionMap, &smit);
  while(1){
    SessionMap_Output_t *smo;
    SessionID_t SessionID;
    if((smo = SessionMap_Iterate(&pile.SessionMap, &smit, &SessionID)) == NULL){
      break;
    }
    if(smo->peer == NULL){
      if(smo->TotalSize){
        SessionArrayID[WriteCount] = SessionID;
        SessionArraySize[WriteCount] = smo->TotalSize;
        WriteCount++;
      }
    }
    else{
      tcp_socks5_pd_t *pd = (tcp_socks5_pd_t *)NET_TCP_GetPeerData(smo->peer, pile.http_send.extid);
      if(pd->state != socks5_state_Connected){
        continue;
      }
      if(smo->TotalSize != 0){
        SessionArrayID[WriteCount] = SessionID;
        SessionArraySize[WriteCount] = smo->TotalSize;
        WriteCount++;
      }
    }
  }
  SessionMap_Iterate_Close(&pile.SessionMap, &smit);

  Size = pile.SendBuffer.Current;

  uintptr_t SizeGuess = Size + BaseWriteSize * WriteCount;
  if(SizeGuess > set_http_send_MaxSize){
    print("LoadBalance starvation type0\n");
    PR_abort();
  }
  uintptr_t PerWriteSize = (set_http_send_MaxSize - SizeGuess) / WriteCount;
  if(PerWriteSize < 32){
    print("LoadBalance starvation type1\n");
    PR_abort();
  }

  common_uintptr_Balance(SessionArraySize, sizeof(SessionArrayID) / sizeof(SessionArrayID[0]), set_http_send_MaxSize - SizeGuess);

  for(uintptr_t i = 0; i < sizeof(SessionArrayID) / sizeof(SessionArrayID[0]); i++){
    SessionMap_Output_t *smo = SessionMap_GetOutputPointer(&pile.SessionMap, &SessionArrayID[i]);

    uint8_t Data[set_http_send_MaxSize];
    uintptr_t DataIndex = 0;
    uintptr_t WantedSize = SessionArraySize[i];

    while(1){
      if(DataIndex == WantedSize){
        break;
      }

      uintptr_t GotSize = WantedSize - DataIndex;
      uint8_t *tp = SessionGetWriteData(smo, &GotSize);
      if(tp == NULL){
        break;
      }

      if(DataIndex + GotSize > sizeof(Data)){
        PR_abort();
      }

      MEM_copy(tp, &Data[DataIndex], GotSize);
      DataIndex += GotSize;
    }

    if(DataIndex == 0){
      break;
    }

    net_httpp_Write(SessionArrayID[i], Data, DataIndex);
  }
}
gt_NoWrite:;

Size = pile.SendBuffer.Current;

if(Size == 0){
  return;
}
