# jp2k_fuzz

This repository contains a harness that can be used with WinAFL to fuzz Acrobat's JPEG2000 library. It was used to find CVE-2019-7794.

## Details

JP2KLib.dll is a closed source DLL that is used by Adobe Acrobat to decode JPEG2000 images. Since it's a binary with no source code, its exports have an unknown API. Our goal is to invoke the exported functions properly and get the library to decode our image independently of Acrobat. Before we can invoke the exported functions, we need to observe how they're used by the application and we can do that through API Monitor. Doing so shows us the following sequence of calls:
```cpp
JP2KLibInitEx(MemObj *obj);
MemObj *obj = JP2KGetMemObjEx();
DecOpt *opt = JP2KDecOptCreate();
JP2KDecOptInitToDefaults(opt);
Image *img = JP2KImageCreate();
JP2KImageInitDecoderEx(img, struct_unk_1, JP2KStreamProcsEx*, opt, struct_unk_3);
```
You might be wondering where the JPEG2000 image data is passed in. Perhaps through JP2KImageCreate? Nope, that's where the parsed data is written. What actually happens is that Acrobat reads the data from the PDF and initializes a stream object called `JP2KCodeStm` that `JP2KImageInitDecoderEx` reads during its decoding process. Luckily for us, there exist some symbols for it in the DLL. We then use the [frida_trace.js](frida_trace.js) script to identify which of its methods are called during ordinary image decoding. Once we know what we need to stub, we perform some quick reversing:
```
JP2KCodeStm::InitJP2KCodeStm(unsigned __int64,int,void *,JP2KStreamProcsEx *,JP2KStmOpenMode,int)
JP2KCodeStm::GetCurPos(void) - returns current pos (+28)
JP2KCodeStm::IsSeekable(void) - returns 1
JP2KCodeStm::read(uchar *outBuf, int nCount) - read nCount bytes from stream into outBuf, returns num bytes read
JP2KCodeStm::seek(int flag, __int64 pos) - seek to pos, returns current pos
```
Now that we know how `JP2KImageInitDecoderEx` reads data from the stream we can detour the above functions to read/seek from our buffer containing JPEG2000 data! We use [adobe_jp2k.py](adobe_jp2k.py) to read our JPEG2000 image and insert the bytes as an array in our [frida_harness.js](frida_harness.js) script. This script will attempt to emulate the above functions, e.g. for JP2KCodeStm::read:
```js
var jp2kBytes = [<bytes from JPEG2000 image>];
...
case "?read@JP2KCodeStm@@QAEHPAEH@Z":
    Interceptor.replace(exports[i].address, new NativeCallback(function(outBuf, nCount) {
        console.log('[i] JP2KCodeStm::read() - writing ' + nCount + ' bytes to ' + outBuf + ' curpos=' + curPos);
        var readBytes = jp2kBytes.slice(curPos, curPos + nCount);
        curPos += nCount;
        Memory.writeByteArray(outBuf, readBytes);
        dumpAddr('read()', outBuf, nCount);
        return readBytes.length;
    }, 'int', ['pointer', 'int'], 'stdcall'));
    break;
```
Provided our reversed implementation is correct, this should work right? But it doesn't. We're missing one more thing - the decoding function uses `MemObj` for memory management which in turn uses Acrobat's own memory management primitives. Since we're calling into the DLL directly, we don't have these available so the decoding fails. We have to emulate `MemObj` ourselves and register it through `JP2KLibInitEx`. We start by reversing the MemObjEx struct:
```cpp
struct MemObjEx
{
	int(__cdecl *init_something)(int);
	int(__cdecl *get_something)(int);
	int(__cdecl *not_impl)();
	void(__cdecl *free_2)(void *);
	void *(__cdecl *malloc_1)(int);
	void(__cdecl *free_1)(void *);
	void *(__cdecl *memcpy_memset)(void *dest, void *src, int size);
	void *(__cdecl *memset_wrapper)(void *dest, int val, int size);
};
```
At this point we write our C++ harness where we can (mostly) route the above methods to whatever heap we have available. Our final harness has the following high-level logic:
```c++
// Load our target library
HINSTANCE JP2KLib = LoadLibrary(L"JP2KLib.dll");

// Obtain references to the exported functions we're interested in
libInit = (JP2KLibInitEx)GetProcAddress(JP2KLib, (LPCSTR)185);
imgCreate = (JP2KImageCreate)GetProcAddress(JP2KLib, (LPCSTR)58);
decOptCreate = (JP2KDecOptCreate)GetProcAddress(JP2KLib, (LPCSTR)43);
decOptInit = (JP2KDecOptInitToDefaults)GetProcAddress(JP2KLib, (LPCSTR)45);
decode = (JP2KImageInitDecoderEx)GetProcAddress(JP2KLib, (LPCSTR)157);

// Use Detours to hook the JP2KCodeStm methods above to return data from our file buffer
hook_jp2kstm();

// Init our fake MemObj with JP2KImageInitDecoderEx 
hook_memobj();

// WinAFL will pass the filename of the mutated data through argv
// This function will initialize a JP2KCodeStm from the file and attempt to decode the image 
fuzz_jp2k(argv[1]);
```
Once we compile our corpus and minimize it while maximizing coverage, we achieve decent performance with WinAFL and even manage to find a bug (CVE-2019-7794).

Unfortunately for me, Checkpoint was doing all of this and more at the same time: https://research.checkpoint.com/2018/50-adobe-cves-in-50-days/. That research was published a few months after I had written all of this. ¯\_(ツ)_/¯
