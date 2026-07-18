#ifndef ENIP_COMMON_H
#define ENIP_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ------------------------------------------------------------------------
 * EtherNet/IP well-known UDP/TCP ports (ODVA Vol 2)
 * ---------------------------------------------------------------------- */
#define ENIP_TCP_PORT 44818 /* explicit messaging (encapsulation) */
#define ENIP_UDP_PORT 2222  /* implicit (cyclic I/O) messaging   */

/* ------------------------------------------------------------------------
 * CIP object class codes (ODVA Vol 1, Appendix A / Vol 2)
 * ---------------------------------------------------------------------- */
#define CIP_CLASS_IDENTITY 0x0001u
#define CIP_CLASS_MESSAGE_ROUTER 0x0002u
#define CIP_CLASS_ASSEMBLY 0x0004u
#define CIP_CLASS_CONNECTION_MANAGER 0x0006u
#define CIP_CLASS_TCPIP_INTERFACE 0x00F5u
#define CIP_CLASS_ETHERNET_LINK 0x00F6u

/* ------------------------------------------------------------------------
 * CIP common services (ODVA Vol 1, Table 4A-4.4) - apply to (almost) any class
 * ---------------------------------------------------------------------- */
#define CIP_SVC_GET_ATTRIBUTE_ALL 0x01u
#define CIP_SVC_SET_ATTRIBUTE_ALL 0x02u
#define CIP_SVC_GET_ATTRIBUTE_LIST 0x03u
#define CIP_SVC_SET_ATTRIBUTE_LIST 0x04u
#define CIP_SVC_RESET 0x05u
#define CIP_SVC_GET_ATTRIBUTE_SINGLE 0x0Eu
#define CIP_SVC_SET_ATTRIBUTE_SINGLE 0x10u

/* Connection Manager (class 0x06) specific services */
#define CIP_SVC_FORWARD_CLOSE 0x4Eu
#define CIP_SVC_UNCONNECTED_SEND 0x52u
#define CIP_SVC_FORWARD_OPEN 0x54u
#define CIP_SVC_LARGE_FORWARD_OPEN 0x5Bu

#define CIP_SVC_REPLY_MASK 0x80u

/* ------------------------------------------------------------------------
 * CIP General Status Codes (ODVA Vol 1, Table 4A-4.6) - returned in every
 * CIP response so the requester knows whether/why a service failed.
 * ---------------------------------------------------------------------- */
#define CIP_STATUS_SUCCESS 0x00u
#define CIP_STATUS_CONNECTION_FAILURE 0x01u
#define CIP_STATUS_RESOURCE_UNAVAILABLE 0x02u
#define CIP_STATUS_INVALID_PARAMETER_VALUE 0x03u
#define CIP_STATUS_PATH_SEGMENT_ERROR 0x04u
#define CIP_STATUS_PATH_DEST_UNKNOWN 0x05u
#define CIP_STATUS_PARTIAL_TRANSFER 0x06u
#define CIP_STATUS_CONNECTION_LOST 0x07u
#define CIP_STATUS_SERVICE_NOT_SUPPORTED 0x08u
#define CIP_STATUS_INVALID_ATTRIBUTE_VALUE 0x09u
#define CIP_STATUS_ATTRIBUTE_LIST_ERROR 0x0Au
#define CIP_STATUS_ALREADY_IN_REQUESTED_MODE 0x0Bu
#define CIP_STATUS_OBJECT_STATE_CONFLICT 0x0Cu
#define CIP_STATUS_OBJECT_ALREADY_EXISTS 0x0Du
#define CIP_STATUS_ATTRIBUTE_NOT_SETTABLE 0x0Eu
#define CIP_STATUS_PRIVILEGE_VIOLATION 0x0Fu
#define CIP_STATUS_DEVICE_STATE_CONFLICT 0x10u
#define CIP_STATUS_REPLY_DATA_TOO_LARGE 0x11u
#define CIP_STATUS_FRAGMENT_PRIMITIVE 0x12u
#define CIP_STATUS_NOT_ENOUGH_DATA 0x13u
#define CIP_STATUS_ATTRIBUTE_NOT_SUPPORTED 0x14u
#define CIP_STATUS_TOO_MUCH_DATA 0x15u
#define CIP_STATUS_OBJECT_DOES_NOT_EXIST 0x16u
#define CIP_STATUS_NO_STORED_ATTR_DATA 0x18u
#define CIP_STATUS_STORE_OPERATION_FAILURE 0x19u
#define CIP_STATUS_INVALID_REPLY_RECEIVED 0x1Du

#endif /* ENIP_COMMON_H */
