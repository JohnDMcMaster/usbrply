/*
UVNet Universal Decompiler (uvudec)
Copyright 2008 John McMaster <JohnDMcMaster@gmail.com>
Licensed under the terms of the LGPL V3 or later, see COPYING for details
*/

#ifndef UV_ERROR_H
#define UV_ERROR_H

typedef int uv_err_t;

#include <stdint.h>

/*
Error classes
*/
//Delcare success
#define UV_ERR_DECL_SUCC(x)				(x)
//Check success
//Note that this includes warnings
#define UV_SUCCEEDED(x) 				((x) >= 0)

//Delcare warning
#define UV_ERR_DECL_WAR(x)				(0x0100 + x)
//Check warning
#define UV_WARNING(x) 					(x >= 0x0100)

//Delcare error
#define UV_ERR_DECL_ERR(x)				(-(x))
//Check error
#define UV_FAILED(x)					((x) < 0)

/*
Full success codes
*/
#define UV_ERR_OK						UV_ERR_DECL_SUCC(0)
//No more data to process
#define UV_ERR_DONE						UV_ERR_DECL_SUCC(1)
//No error occured, but the item did not contain any data to generate output
#define UV_ERR_BLANK					UV_ERR_DECL_SUCC(2)

/*
Warning codes
*/
#define UV_ERR_WARNING					UV_ERR_DECL_WAR(0)

/*
Error codes
*/
//General error
#define UV_ERR_GENERAL					UV_ERR_DECL_ERR(1)
//Access denied	
#define UV_ERR_ACCESS					UV_ERR_DECL_ERR(2)
//Out of memory
#define UV_ERR_OUTMEM					UV_ERR_DECL_ERR(3)
//Not found
#define UV_ERR_NOTFOUND					UV_ERR_DECL_ERR(4)
//Operation unexpected aborted
#define UV_ERR_ABORTED					UV_ERR_DECL_ERR(5)
//Invalid arguments
#define UV_ERR_ARGS						UV_ERR_DECL_ERR(6)
//Not supported.  It is unlikely it will be in any future release either
#define UV_ERR_NOTSUPPORTED				UV_ERR_DECL_ERR(7)
//Passed in buffer too small
#define UV_ERR_BUFFERSIZE				UV_ERR_DECL_ERR(8)
//An arbitrary limit, such as an internal buffer size, has been it
#define UV_ERR_ARBITRARYLIMIT			UV_ERR_DECL_ERR(9)
//Operation could succeed, but would not be compatible as specified
//Created originally for IDASIG vs UVDSIG files which support additional architectures
#define UV_ERR_COMPATIBILITY			UV_ERR_DECL_ERR(10)
//Just not there yet 
#define UV_ERR_NOTIMPLEMENTED			UV_ERR_DECL_ERR(11)
//Item already exists and must be unique
#define UV_ERR_DUPLICATE				UV_ERR_DECL_ERR(12)

/*
Disassembly codes
XXX: are these actually used?
*/
#define UV_ERR_DECL_DIS(x)				(UV_ERR_DECL_ERR(0x0100 + x))
//Invalid instruction combination
#define UV_ERR_DISASM_COMBO				UV_ERR_DECL_DIS(0)
//Instruction required more data than was availible
#define UV_ERR_DISASM_NODAT				UV_ERR_DECL_DIS(1)
//Too many instruction prefixes (x86)
#define UV_ERR_DISASM_PREFIX			UV_ERR_DECL_DIS(2)

//Return a string representation of the define
const char *uv_err_str(uv_err_t err);

/*
Note a type par se...
Need to figure out how to do a pointer to a const char * without typedef
*/
typedef const char * uv_const_char_ptr;

#endif // ifndef UV_ERR_H

