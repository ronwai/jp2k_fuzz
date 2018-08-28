# jp2k

- jp2 header box (jp2h)
- image header box (ihdr) : specifies the size of the image and other related fields.
- component mapping box (cmap) :  specifies the mapping between a palette and codestream components
- palette box (pclr) : specifies the palette which maps a single component in index space to a multiple-component image.

bug (half initialized state due to bailout):
- parses CMAP box but does not clean state
- when PCLR box is encountered, CMAP array counter overwritten then invalid parameter
  causes parser to bail.
- in clean up procedure, the overwritten counter is used for the CMAP array without
  bounds checks, causing out of bounds free.
  
ideas:
- look in other superbox/box handlers for similar bailout bugs
- understand why either branch of patch (if zero, free arrCMAP else assign) is taken

- figure out type of arguments for JP2KImageInitDecoder, build WinAFL harness:
- [x] find how JP2KImageInitDecoder is used by acrobat with API monitor:
 
```
JP2KLibInitEx(MemObj *obj)
MemObj *obj = JP2KGetMemObjEx()
DecOpt *opt = JP2KDecOptCreate()
JP2KDecOptInitToDefaults(opt)
Image *img = JP2KImageCreate()
JP2KImageInitDecoderEx(img, struct_unk_1, JP2KStreamProcsEx*, opt, struct_unk_3)

struct struct_unk_1 {
  DWORD jp2k_size
  DWORD unk_1
  DWORD unk_2
  DWORD unk_3
  DWORD unk_4
  DWORD unk_5
  struct_unk_4 *unk_6
  DWORD unk_7
  JP2KStreamProcsEx *unk_8 
}
```
- JP2KStreamProcsEx (array of functions for working with stream)

## building harness & instrumentation
- [x] build harness invoking JP2KImageInitDecoder	
- [x] emulate & test required functionality (JP2KCodeStm & MemObj) w/ Frida prototype (frida_harness.js)
- [x] reimplement emulation either in DynamoRio or Detours (went with this option)

## prepare for fuzzing
- [x] gather JPEG2000 corpus from old reports
- [x] jp2 files from https://github.com/uclouvain/openjpeg-data & use opj_compress to convert non-jp2 files into jp2
- [x] https://github.com/mdadams/jasper/tree/master/data/test + opj_compress
- [x] corpus minimization
- [ ] write script to pull all jp2 files from github then minimize
    
## optimize fuzzing
- [ ] fuzzer dictionary for JP2K
    - investigate pdf_jpx_fuzzer.cc in libFuzzer
- [ ] test case generation using JP2K grammar/format aware generator
- [ ] look into distributing fuzzer across purpose built fuzz VMs
- [ ] reverse then fuzz individual box handlers


## misc 
```
// called from Acrobat/Reader
+ jp2k_dec_image()
|   + jp2k_lib_init_ex()
|   |   + sub_60026810() ... [20]
|   |   + JP2KLibInitEx()
|   + JP2KGetMemObjEx()
|   + sub_60035860() ... [11]
|   + sub_6020DD00() ... [79]
|   + sub_60026810() ... [21]
|   + memset() ... [2]
|   + JP2KDecOptCreate()
|   + JP2KDecOptInitToDefaults()
|   + JP2KImageCreate()
|   + JP2KImageInitDecoderEx()
|   + sub_60630DF0()
|   + JP2KImageGetGeometryParams()
|   + JP2KImageGeometryGetParams()
|   + sub_606302E0()
|   + sub_60631110()
|   |   + JP2KImageGetColorSpecList()
|   |   + sub_6002D870() ... [6]
|   |   + sub_60043674()
|   |   |   + memcpy() ... [8]
|   |   |   + sub_6003C983()
|   |   |   |   + memset() ... [3]
|   |   + JP2KImageGetGeometryParams() ... [2]
|   |   + JP2KImageGeometryGetParams() ... [2]
|   |   + JP2KImagePalettePresent()
|   |   + JP2KImageGetPalette()
|   |   + memcpy() ... [9]
|   |   + memset() ... [4]
|   |   + sub_60630E60()
|   |   |   + JP2KImageGetGeometryParams() ... [3]
|   |   |   + JP2KImageGeometryGetParams() ... [3]
|   |   |   + JP2KImageGetComponentType()
|   + JP2KImageGlobalTransparencyChannelPresent() ****
|   + JP2KImageGetGlobalTransparencyChannelNum() ****
|   + JP2KImageGetComponentType() ... [2] ****
|   + JP2KDecOptDestroy()
|   + JP2KImageDestroy()
|   + free() ... [21]
```

```
JP2KCodeStm::JP2KCodeStm(void)
JP2KCodeStm::~JP2KCodeStm(void)
JP2KCodeStm::operator=(JP2KCodeStm const &)
JP2KCodeStm::Die(void)
JP2KCodeStm::GetCurPos(void) - returns current pos (+28)
JP2KCodeStm::GetOpenMode(void)
JP2KCodeStm::GetStmBase(void)
JP2KCodeStm::GetStmProcs(void)
JP2KCodeStm::GetTotalLength(void)
JP2KCodeStm::InitJP2KCodeStm(unsigned __int64,int,void *,JP2KStreamProcsEx *,JP2KStmOpenMode,int)
JP2KCodeStm::IsReadable(void)
JP2KCodeStm::IsSeekable(void) - returns 1
JP2KCodeStm::IsWritable(void)
JP2KCodeStm::ReadOnly(void)
JP2KCodeStm::StmLengthUnknown(void)
JP2KCodeStm::TellPos(void)
JP2KCodeStm::WriteOnly(void)
JP2KCodeStm::flushWriteBuffer(void)
JP2KCodeStm::read(uchar *outBuf, int nCount) - read nCount bytes from stream into outBuf, returns num bytes read
JP2KCodeStm::seek(int flag, __int64 pos) - seek to pos, returns current pos
JP2KCodeStm::write(uchar *,int)
```
```
struct struct_MemObjEx {
    int (__cdecl *init_something)(int);
    int (__cdecl *get_something)(int);
    int (__cdecl *not_impl)();
    int (__cdecl *free_2)(int);
    int (__cdecl *malloc_1)(int);
    int (__cdecl *free_1)(int);
    int (__cdecl *memcpy_memset)(int dest, int src, int size);
    int (__cdecl *memset_wrapper)(int dest, int val, int size);
}
```
```
struct __declspec(align(4)) JP2KCodeStm
{
  _DWORD len1;
  _DWORD len2;
  _BYTE gap0[8];
  _DWORD readOnly;
  _DWORD writeOnly;
  _DWORD stmBase;
  _DWORD dword1C;
  _DWORD openMode;
  _DWORD stmFuncs;
  _DWORD curPos;
  _DWORD overflowThing;
  _DWORD dword30;
  _DWORD writeBuffer;
  _DWORD endWriteBuf;
  _DWORD posWriteBuf;
};
```
