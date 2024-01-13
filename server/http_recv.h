typedef enum{
  http_recv_state_httpp_begin,
  http_recv_state_Connect,
  http_recv_state_Connect_Address,
  http_recv_state_DropConnection,
  http_recv_state_Write,
  http_recv_state_Write_Data,
  http_recv_state_FillerWrite,
  http_recv_state_DNS,
  http_recv_state_DNS_Data
}http_recv_state_t;

typedef struct{
  http_recv_state_t state;
  uintptr_t CopyIndex;

  union{
    struct{
      httpp_cc_ConnectHead_t Head;
      union{
        uint8_t ipv4[0x04];
        uint8_t ipv6[0x10];
        struct{
          uint8_t Size;
          uint8_t Data[0x100];
        }Domain;
      }Address;
    }Connect;
    httpp_cc_DropConnection_t DropConnection;
    struct{
      httpp_cc_Write_Head_t Head;
    }Write;
    struct{
      httpp_cc_DNS_Head_t DNS_Head;
      uint8_t DNS_Data[0x800];
    };
  }d; /* data */

  NET_addr_t dstaddr;
}tcp_http_recv_pd_t;

void tcp_http_recv_PeerOpen(tcp_http_recv_pd_t *pd){
  print("[+] http_recv\n");

  pd->state = http_recv_state_httpp_begin;
  pd->CopyIndex = 0;
}
void tcp_http_recv_PeerClose(tcp_http_recv_pd_t *pd){
  print("[-] http_recv\n");
}

void http_recv_Connect(tcp_http_recv_pd_t *pd){
  if(pd->d.Connect.Head.AddressType == httpp_ConnectAddressType_IPV4){
    NET_addr_t addr;
    addr.port = pd->d.Connect.Head.Port;
    addr.ip = *(uint32_t *)pd->d.Connect.Address.ipv4;

    evprint("http_recv_Connect %lx\n", pd->d.Connect.Head.SessionID);

    if(SessionMap_DoesInputExists(&pile.SessionMap, &pd->d.Connect.Head.SessionID)){
      PR_abort();
    }

    NET_TCP_peer_t *da_peer = tcp_connect(pile.da.tcp, &addr);
    if(da_peer == NULL){
      PR_abort();
    }
    tcp_da_pd_t *da_pd = (tcp_da_pd_t *)NET_TCP_GetPeerData(da_peer, pile.da.extid);
    da_pd->SessionID = pd->d.Connect.Head.SessionID;

    SessionMap_Output_t smo;
    smo.peer = da_peer;
    tcp_da_PacketList_Open(&smo.PacketList);
    smo.TotalSize = 0;
    SessionMap_InNew(&pile.SessionMap, &da_pd->SessionID, &smo);
  }
  else{
    PR_abort();
  }
}

sint32_t ProcessHTTPP(tcp_http_recv_pd_t *pd, const uint8_t *Data, uintptr_t DataSize){
  uintptr_t DataIndex = 0;

  while(DataIndex != DataSize){
    if(pd->state == http_recv_state_httpp_begin){
      uint8_t t = Data[DataIndex++];
      if(t == httpp_cc_NOP){}
      else if(t == httpp_cc_Connect){pd->state = http_recv_state_Connect;}
      else if(t == httpp_cc_DropConnection){pd->state = http_recv_state_DropConnection;}
      else if(t == httpp_cc_Write){pd->state = http_recv_state_Write;}
      else if(t == httpp_cc_DNS){pd->state = http_recv_state_DNS;}
      else{
        vprint("ProcessHTTPP t doesnt exists %lx\n", t);
        return -1;
      }
    }
    else if(pd->state == http_recv_state_Connect){
      if(COPY(&pd->d.Connect.Head, sizeof(pd->d.Connect.Head))){
        if(pd->d.Connect.Head.AddressType == httpp_ConnectAddressType_Domain){
          pd->d.Connect.Address.Domain.Size = 0;
        }
        pd->state = http_recv_state_Connect_Address;
      }
    }
    else if(pd->state == http_recv_state_Connect_Address){
      uint8_t at = pd->d.Connect.Head.AddressType;
      if(at == httpp_ConnectAddressType_Domain){
        if(pd->d.Connect.Address.Domain.Size == 0){
          pd->d.Connect.Address.Domain.Size = Data[DataIndex++];
          if(pd->d.Connect.Address.Domain.Size == 0){
            return -1;
          }
        }
        else{
          if(COPY(pd->d.Connect.Address.Domain.Data, pd->d.Connect.Address.Domain.Size)){
            /* good luck */
            PR_abort();
          }
        }
      }
      else if(at == httpp_ConnectAddressType_IPV4){
        if(COPY(pd->d.Connect.Address.ipv4, 4)){
          http_recv_Connect(pd);
          pd->state = http_recv_state_httpp_begin;
        }
      }
      else if(at == httpp_ConnectAddressType_IPV6){
        /* not supported yet */
        return -1;
      }
      else{
        print("unknown address type %lx\n", at);
        return -1;
      }
    }
    else if(pd->state == http_recv_state_DropConnection){
      if(COPY(&pd->d.DropConnection, sizeof(pd->d.DropConnection))){
        SessionMap_Output_t *smo = SessionMap_GetOutputPointerSafe(&pile.SessionMap, &pd->d.DropConnection.SessionID);
        if(smo != NULL){
          RemoveSession(pd->d.DropConnection.SessionID);
        }

        evprint("http_recv_state_DropConnection %lx\n", pd->d.DropConnection.SessionID);

        pd->state = http_recv_state_httpp_begin;
      }
    }
    else if(pd->state == http_recv_state_Write){
      if(COPY(&pd->d.Write.Head, sizeof(pd->d.Write.Head))){
        if(pd->d.Write.Head.DataSize == 0){
          vprint("http_recv_state_Write retarted %lx\n", pd->d.Write.Head.SessionID);
          pd->state = http_recv_state_httpp_begin;
        }
        else{
          evprint("http_recv_state_Write %lx\n", pd->d.Write.Head.SessionID);
          pd->state = http_recv_state_Write_Data;
        }
      }
    }
    else if(pd->state == http_recv_state_Write_Data) do{
      uintptr_t left = DataSize - DataIndex;
      if(left >= pd->d.Write.Head.DataSize){
        left = pd->d.Write.Head.DataSize;
        pd->state = http_recv_state_httpp_begin;
      }
      else{
        pd->d.Write.Head.DataSize -= left;
      }
      DataIndex += left;

      SessionMap_Output_t *smo = SessionMap_GetOutputPointerSafe(&pile.SessionMap, &pd->d.Write.Head.SessionID);
      if(smo == NULL){
        evprint("http_recv_state_Write_Data unknown SessionID %lx\n", pd->d.Write.Head.SessionID);
        break;
      }
      if(smo->peer == NULL){
        break;
      }

      evprint("http_recv_state_Write_Data %lx %x\n", pd->d.Write.Head.SessionID, left);
      tcp_write_dp(smo->peer, &Data[DataIndex - left], left);
    }while(0);
    else if(pd->state == http_recv_state_DNS){
      if(COPY(&pd->d.DNS_Head, sizeof(pd->d.DNS_Head))){
        if(pd->d.DNS_Head.Size == 0){
          /* retarted */
          pd->state = http_recv_state_httpp_begin;
        }
        else if(pd->d.DNS_Head.Size > 0x800 - 2){
          vprint("http_recv pd->d.DNS_Head.Size > 0x800 - 2. %lx\n", pd->d.DNS_Head.Size);
          return -1;
        }
        else{
          pd->state = http_recv_state_DNS_Data;
        }
      }
    }
    else if(pd->state == http_recv_state_DNS_Data){
      if(COPY(pd->d.DNS_Data, pd->d.DNS_Head.Size)){
        pd->state = http_recv_state_httpp_begin;

        DNSMap_Output_t *dnso = (DNSMap_Output_t *)A_resize(NULL, sizeof(DNSMap_Output_t));
        dnso->TransactionID = pile.DNSTransactionID++;
        dnso->DNSID = pd->d.DNS_Head.DNSID;
        EV_timer_init(&dnso->Timer, (f64_t)set_DNS_Timeout / 1000000000, cb_DNSTimer);
        EV_timer_start(&pile.listener, &dnso->Timer);

        DNSMap_InNew(&pile.DNSMap, &dnso->TransactionID, &dnso);

        uint8_t UDPData[0x800];
        *(uint16_t *)&UDPData[0] = dnso->TransactionID;
        MEM_copy(pd->d.DNS_Data, &UDPData[2], pd->d.DNS_Head.Size);
        NET_addr_t dstaddr;
        dstaddr.ip = set_DNS_ServerIP;
        dstaddr.port = set_DNS_ServerPort;
        NET_sendto(&pile.DNSSocket, UDPData, pd->d.DNS_Head.Size + 2, &dstaddr);
      }
    }
  }

  return 0;
}
