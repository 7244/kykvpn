/* http protocol */

typedef enum{
  httpp_cc_Bad,
  httpp_cc_NOP,
  httpp_cc_FACK,
  httpp_cc_ACK,
  httpp_cc_Connect,
  httpp_cc_DropConnection,
  httpp_cc_Write,
  httpp_cc_FillerWrite,
  httpp_cc_DNS
}httpp_cc_t; /* client command */

typedef enum{
  httpp_sc_Bad,
  httpp_sc_NOP,
  httpp_sc_FACK,
  httpp_sc_ACK,
  httpp_sc_Connect,
  httpp_sc_ConnectAnswer,
  httpp_sc_DropConnection,
  httpp_sc_Write,
  httpp_sc_FillerWrite,
  httpp_sc_DNS
}httpp_sc_t; /* server command */

#pragma pack(push, 1)

typedef uint32_t SessionID_t;

/* internal connection ack */
typedef uint32_t icack_t;

typedef enum{
  httpp_ConnectMode_TCP,
  httpp_ConnectMode_UDP
}httpp_ConnectMode_t;

typedef enum{
  httpp_ConnectAddressType_IPV4,
  httpp_ConnectAddressType_IPV6,
  httpp_ConnectAddressType_Domain
}httpp_ConnectAddressType_t;

typedef struct{
  SessionID_t SessionID;
  uint8_t Mode; /* httpp_ConnectMode_t */
  uint8_t AddressType; /* httpp_ConnectAddressType_t */
  uint16_t Port;
}httpp_cc_ConnectHead_t;

typedef struct{
  SessionID_t SessionID;
}httpp_cc_DropConnection_t;

typedef enum{
  httpp_sc_ConnectAnswer_Result_Success
}httpp_sc_ConnectAnswer_Result_t;

typedef struct{
  SessionID_t SessionID;
  uint8_t Result; /* httpp_sc_ConnectAnswer_Result_t */
}httpp_sc_ConnectAnswer_Head_t;

typedef struct{
  SessionID_t SessionID;
}httpp_sc_DropConnection_Head_t;

typedef struct{
  SessionID_t SessionID;
  uint64_t DataSize;
}httpp_cc_Write_Head_t;

typedef struct{
  SessionID_t SessionID;
  uint64_t DataSize;
}httpp_sc_Write_Head_t;

typedef struct{
  uint8_t Data[0x200];
}httpp_sc_FillerWrite_Head_t;

typedef struct{
  uint8_t Data[0x200];
}httpp_cc_FillerWrite_Head_t;

typedef uint32_t httpp_DNSID_t;

typedef struct{
  httpp_DNSID_t DNSID;
  uint16_t Size;
}httpp_cc_DNS_Head_t;

typedef struct{
  httpp_DNSID_t DNSID;
  uint16_t Size;
}httpp_sc_DNS_Head_t;

#pragma pack(pop)
