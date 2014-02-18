#include <string>
#include <vector>
#include <map>
#include "util.h"
#include "uv_err.h"
#include <stdarg.h>

static unsigned int uv_get_num_tokens_core(const char *text, char delim, int ret_blanks);

std::string UVDSprintf(const char *format, ...);
//ypedef int uv_err_t;

#define uv_assert_ret(x)
std::vector<std::string> split(const std::string &s, char delim, bool ret_blanks);
std::vector<std::string> UVDSplit(const std::string &s, char delim, bool ret_blanks);
char **uv_split_core(const char *str, char delim, unsigned int *n_ret, int ret_blanks);

uv_err_t parseNumericRangeString(const std::string &s, uint32_t *first, uint32_t *second)
{
	char delim = 0;
	std::vector<std::string> parts;
	
	uv_assert_ret(first);
	uv_assert_ret(second);
	
	if( s.find('-') != std::string::npos )
	{
		delim = '-';
	}
	else if( s.find(',') != std::string::npos )
	{
		delim = ',';
	}
	else if( s.find(':') != std::string::npos )
	{
		delim = ':';
	}
	//Self to self then
	else
	{
		*first = strtol(s.c_str(), NULL, 0);
		*second = *first;
		return UV_ERR_OK;
	}
	
	parts = split(s, delim, true);
	uv_assert_ret(parts.size() == 2);
	*first = strtol(parts[0].c_str(), NULL, 0);
	std::string second_str = parts[1];
	if (second_str == "") {
		*second = UINT_MAX;
	} else {
		*second = strtol(second_str.c_str(), NULL, 0);
	}
	
	return UV_ERR_OK;
}

bool g_util_halt_error = false;

std::string transfer_type_str( unsigned int tt ) {
	switch (tt) {
	case URB_ISOCHRONOUS:
		return "URB_ISOCHRONOUS";
	case URB_INTERRUPT:
		return "URB_INTERRUPT";
	case URB_CONTROL:
		return "URB_CONTROL";
	case URB_BULK:
		return "URB_BULK";
	default:
		printf("WTF? %d\n", __LINE__);
		if (g_util_halt_error) {
			exit(1);
		}
		return "";
	}
}

std::string get_request_str(unsigned int bRequestType, unsigned int bRequest) {
	switch (bRequestType & USB_TYPE_MASK) {
	case USB_TYPE_STANDARD:
		switch (bRequest) {
		case USB_REQ_GET_STATUS:
			return "USB_REQ_GET_STATUS";
		case USB_REQ_CLEAR_FEATURE:
			return "USB_REQ_CLEAR_FEATURE";
		case USB_REQ_SET_FEATURE:
			return "USB_REQ_SET_FEATURE";
		case USB_REQ_SET_ADDRESS:
			return "USB_REQ_SET_ADDRESS";
		case USB_REQ_GET_DESCRIPTOR:
			return "USB_REQ_GET_DESCRIPTOR";
		case USB_REQ_SET_DESCRIPTOR:
			return "USB_REQ_SET_DESCRIPTOR";
		case USB_REQ_GET_CONFIGURATION:
			return "USB_REQ_GET_CONFIGURATION";
		case USB_REQ_SET_CONFIGURATION:
			return "USB_REQ_SET_CONFIGURATION";
		case USB_REQ_GET_INTERFACE:
			return "USB_REQ_GET_INTERFACE";
		case USB_REQ_SET_INTERFACE:
			return "USB_REQ_SET_INTERFACE";
		case USB_REQ_SYNCH_FRAME:
			return "USB_REQ_SYNCH_FRAME";	
		default:
			printf("WTF? %d\n", __LINE__);
			if (g_util_halt_error) {
				exit(1);
			}
			return "";
		};
			
	//TODO: consider decoding class, although really its not as of much interest for replaying
	//since it should be well defined
	case USB_TYPE_CLASS:
	case USB_TYPE_VENDOR:
	case USB_TYPE_RESERVED:
		return UVDSprintf("0x%02X", bRequest);
	
	default:
		printf("WTF? %d\n", __LINE__);
		if (g_util_halt_error) {
			exit(1);
		}
		return "";
	}
}

std::string get_request_type_str(unsigned int bRequestType) {
	std::string ret = "";
	
	if ((bRequestType & USB_DIR_IN) == USB_DIR_IN) {
		ret += "USB_DIR_IN";
	} else {
		ret += "USB_DIR_OUT";
	}
	
	switch (bRequestType & USB_TYPE_MASK) {
	case USB_TYPE_STANDARD:
		ret += " | USB_TYPE_STANDARD"; 
		break;
	case USB_TYPE_CLASS:
		ret += " | USB_TYPE_CLASS"; 
		break;
	case USB_TYPE_VENDOR:
		ret += " | USB_TYPE_VENDOR"; 
		break;
	case USB_TYPE_RESERVED:
		ret += " | USB_TYPE_RESERVED"; 
		break;
	default:
		printf("WTF? %d\n", __LINE__);
		if (g_util_halt_error) {
			exit(1);
		}
		return "";
	}
	
	switch (bRequestType & USB_RECIP_MASK) {
	case USB_RECIP_DEVICE:
		ret += " | USB_RECIP_DEVICE";
		break;
	case USB_RECIP_INTERFACE:
		ret += " | USB_RECIP_INTERFACE";
		break;
	case USB_RECIP_ENDPOINT:
		ret += " | USB_RECIP_ENDPOINT";
		break;
	case USB_RECIP_OTHER:
		ret += " | USB_RECIP_OTHER";
		break;
	case USB_RECIP_PORT:
		ret += " | USB_RECIP_PORT";
		break;
	case USB_RECIP_RPIPE:
		ret += " | USB_RECIP_RPIPE";
		break;
	default:
		printf("WTF? %d\n", __LINE__);
		if (g_util_halt_error) {
			exit(1);
		}
		return "";
	}

	return ret;
}

std::string urb_type_str(unsigned int t) {
	switch (t) {
	case URB_SUBMIT:
		return "URB_SUBMIT";
	case URB_COMPLETE:
		return "URB_COMPLETE";
	case URB_ERROR:
		return "URB_ERROR";
	default:
		printf("WTF? %d\n", __LINE__);
		if (g_util_halt_error) {
			exit(1);
		}
		return "";
	}
}

void print_urb(usb_urb_t *urb) {
	printf("\tid: 0x%016lX\n", urb->id);
	printf("\ttype: %s (%c / 0x%02X)\n", urb_type_str(urb->type).c_str(), urb->type, urb->type);
	printf("\ttransfer_type: %s (0x%02X)\n",
			transfer_type_str(urb->transfer_type).c_str(), urb->transfer_type );
	printf("\tendpoint: 0x%02X\n", urb->endpoint);
	printf("\tdevice: 0x%02X\n", urb->device);
	printf("\tbus_id: 0x%04X\n", urb->bus_id);
	printf("\tsetup_request: 0x%02X\n", urb->setup_request);
	printf("\tdata: 0x%02X\n", urb->data);
	//printf("\tsec: 0x%016llX\n", urb->sec);
	printf("\tusec: 0x%08X\n", urb->usec);
	printf("\tstatus: 0x%08X\n", urb->status);
	printf("\tlength: 0x%08X\n", urb->length);
	printf("\tdata_length: 0x%08X\n", urb->data_length);
}


uint32_t g_bytesPerRow = 16;
uint32_t g_bytesPerHalfRow = 8;

static unsigned int hexdumpHalfRow(const uint8_t *data, size_t size, uint32_t start)
{
	uint32_t col = 0;

	for( ; col < g_bytesPerHalfRow && start + col < size; ++col )
	{
		uint32_t index = start + col;
		uint8_t c = data[index];
		
		printf("%.2X ", (unsigned int)c);
		fflush(stdout);
	}

	//pad remaining
	while( col < g_bytesPerHalfRow )
	{
		printf("   ");
		fflush(stdout);
		++col;
	}

	//End pad
	printf(" ");
	fflush(stdout);

	return start + g_bytesPerHalfRow;
}

void UVDHexdumpCore(const uint8_t *data, size_t size, const std::string &prefix)
{
	/*
	[mcmaster@gespenst icd2prog-0.3.0]$ hexdump -C /bin/ls |head
	00000000  7f 45 4c 46 01 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
	00000010  02 00 03 00 01 00 00 00  f0 99 04 08 34 00 00 00  |............4...|
	00017380  00 00 00 00 01 00 00 00  00 00 00 00              |............|
	*/

	size_t pos = 0;
	while( pos < size )
	{
		uint32_t row_start = pos;
		uint32_t i = 0;

		printf("%s", prefix.c_str());
		fflush(stdout);

		pos = hexdumpHalfRow(data, size, pos);
		pos = hexdumpHalfRow(data, size, pos);

		printf("|");
		fflush(stdout);

		//Char view
		for( i = row_start; i < row_start + g_bytesPerRow && i < size; ++i )
		{
			char c = data[i];
			if( isprint(c) )
			{
				printf("%c", c);
				fflush(stdout);
			}
			else
			{
				printf("%c", '.');
				fflush(stdout);
			}
		} 
		for( ; i < row_start + g_bytesPerRow; ++i )
		{
			printf(" ");
			fflush(stdout);
		}

		printf("|\n");
		fflush(stdout);
	}
	fflush(stdout);
}

void UVDHexdump(const uint8_t *data, size_t size)
{
	UVDHexdumpCore(data, size, "");
}

#define uv_err_str_case(x) case x: return #x;
const char *uv_err_str(uv_err_t err)
{
	switch(err)
	{
	uv_err_str_case(UV_ERR_GENERAL);
	uv_err_str_case(UV_ERR_ACCESS);
	uv_err_str_case(UV_ERR_OUTMEM);
	uv_err_str_case(UV_ERR_NOTFOUND);
	uv_err_str_case(UV_ERR_ABORTED);
	uv_err_str_case(UV_ERR_ARGS);
	uv_err_str_case(UV_ERR_NOTSUPPORTED);
	uv_err_str_case(UV_ERR_BUFFERSIZE);
	uv_err_str_case(UV_ERR_ARBITRARYLIMIT);
	uv_err_str_case(UV_ERR_COMPATIBILITY);
	uv_err_str_case(UV_ERR_NOTIMPLEMENTED);

	uv_err_str_case(UV_ERR_DISASM_COMBO);
	uv_err_str_case(UV_ERR_DISASM_NODAT);
	uv_err_str_case(UV_ERR_DISASM_PREFIX);

	default:
		return "UNKNOWN";
	}
}

uv_err_t uv_err_ret_handler(uv_err_t rc, const char *file, uint32_t line, const char *func)
{
	if( UV_FAILED(rc) )
	{
		printf("ERROR: %s (%s:%d): rc=%s\n", func, file, line, uv_err_str(rc));
	}
	else if( UV_WARNING(rc) )
	{
		printf("WARNING: %s (%s:%d): rc=%s\n", func, file, line, uv_err_str(rc));
	}
	return rc;
}

std::vector<std::string> split(const std::string &s, char delim, bool ret_blanks)
{
	return UVDSplit(s, delim, ret_blanks);
}

std::vector<std::string> UVDSplit(const std::string &s, char delim, bool ret_blanks)
{
	char **coreRet = NULL;
	char **cur = NULL;
	std::vector<std::string> ret;
	
	coreRet = uv_split_core(s.c_str(), delim, NULL, ret_blanks);
	if( !coreRet )
	{
		return ret;
	}

	for( cur = coreRet; *cur; ++cur )
	{
		ret.push_back(*cur);
		free(*cur);
	}
	free(coreRet);

	return ret;
}

/*
XXX: this is really old code that seems to work, but really should be phased out

str: string to split
delim: character to delimit by
	If null, will return the array with a single string
n_ret: if set, will return number of items in the output, otherwise, output is a null terminated array
ret_blanks: return empty strings?
*/
char **uv_split_core(const char *str, char delim, unsigned int *n_ret, int ret_blanks)
{
	unsigned int n = 0;
	char *buff = NULL;
	static char **ret = NULL;
	unsigned int str_index = 0;
	unsigned int i = 0;

	n = uv_get_num_tokens_core(str, delim, ret_blanks);
	if( n_ret )
	{
		*n_ret = n;
	}
	else
	{
		++n;
	}
	ret = (char **)malloc(sizeof(char *) * (n));
	if( !ret || (n_ret && n == 0) )
	{
		return NULL;
	}
	/* The extra bit of n is only needed shortly during allocation */
	if( !n_ret )
	{
		--n;
		ret[n] = NULL;
	}
	buff = strdup(str);
	if( !buff )
	{
		return NULL;
	}

	for( i = 0; i < n; ++i )
	{
		unsigned int j = 0;
		for( j = 0; str[str_index] != delim && str[str_index] != 0; ++j, ++str_index )
		{
			buff[j] = str[str_index];
		}
		buff[j] = 0;
		/* skip over the null */
		++str_index;
		
		ret[i] = strdup(buff);
		if( ret[i] == NULL )
		{
			goto error;
		}
	}
	free(buff);
	return ret;

error:
	for( ;; )
	{
		free(ret[i]);
		if( i == 0 )
		{
			break;
		}
		--i;
	}
	free(ret);
	free(buff);
	return NULL;
}

static unsigned int uv_get_num_tokens_core(const char *text, char delim, int ret_blanks)
{
	int ret = 1;
	unsigned int i = 0;
	for( i = 0; text[i] != 0; ++i )
	{
		if( text[i] == delim && (ret_blanks || (i != 0 && text[i - 1] != delim)) )
		{
			++ret;
		}
	}
	return ret;
}

char *uv_get_line(const char *text, unsigned int lineNumber)
{
	char *line = NULL;
	unsigned int index = 0;
	char cur_char='a';
	unsigned int line_size = 0;
	unsigned int i = 0;

	for(i = 0; i < lineNumber; ++i)
	{
		while( text[index] != '\n' )
		{
			++index;
		}
	}
	//Find line size
	for( line_size = 0; true; ++line_size )
	{
		cur_char = text[index + line_size];
		if( cur_char == '\n' || cur_char == '\r' || cur_char == 0 )
		{
			break;
		}
	}
	line = (char *)malloc(sizeof(char) * (line_size + 1));
	if( !line )
	{
		return NULL;
	}
	//Then copy
	for( i = 0; true; ++i )
	{
		cur_char = text[index + i];
		if( cur_char == '\n' || cur_char == '\r' || cur_char == 0 )
		{
			break;
		}
		line[i] = cur_char;
	}
	line[i] = 0;
	
	return line;
}

char *cap_fixup(char *str)
{
	char *ptr = str;
	
	//UV_ENTER();

	if( !str )
	{
		return str;
	}
	/*
	if( g_config->m_caps )
	{
		while( *ptr )
		{
			*ptr = toupper(*ptr);
			++ptr;
		}
	}
	else
	*/
	{
		while( *ptr )
		{
			*ptr = tolower(*ptr);
			++ptr;
		}
	}
	return str;
}

