#ifndef UTIL_H
#define UTIL_H

#include "linux/usb/ch9.h"

#define URB_IS_IN( _urb) (((_urb)->endpoint & USB_DIR_IN) == USB_DIR_IN)

//typedef uint8_t usb_urb_id_t[8];

#define URB_SUBMIT        'S'
#define URB_COMPLETE      'C'
#define URB_ERROR         'E'
typedef uint8_t urb_type_t;

#define URB_ISOCHRONOUS   0x0
#define URB_INTERRUPT     0x1
#define URB_CONTROL       0x2
#define URB_BULK          0x3
//#define URB_TYPE_MASK     0x3
typedef uint8_t urb_transfer_t;

typedef struct {
	uint64_t id;
	urb_type_t type;
	urb_transfer_t transfer_type;
	uint8_t endpoint;
	uint8_t device;
	uint16_t bus_id;
	uint8_t setup_request;
	uint8_t data;
	uint64_t sec;
	uint32_t usec;
	uint32_t status;
	uint32_t length;
	uint32_t data_length;
	//not sure what these are...not labeled in wireshark either
	//uint8_t pad[24];
} __attribute__((packed)) usb_urb_t;

//TODO; figure out what this actually is
typedef struct {
	uint8_t raw[24];
} __attribute__((packed)) control_rx_t;

#endif

