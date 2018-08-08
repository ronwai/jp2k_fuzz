var modules = Process.enumerateModulesSync()
for (var i = 0; i < modules.length; i++) {
  if (modules[i].name == "JP2KLib.dll")
    jp2kBase = modules[i].base;
      
}

jp2k_code_stm_methods = [
    {name: '??4JP2KCodeStm@@QAEAAV0@ABV0@@Z', nargs: 0},
    {name: '?Die@JP2KCodeStm@@QAEXXZ', nargs: 0},
    {name: '?GetCurPos@JP2KCodeStm@@QAE_JXZ', nargs: 0},
    // '?GetOpenMode@JP2KCodeStm@@QAE?AW4JP2KStmOpenMode@@XZ', // doesnt work for some reason lol
    //'?GetStmBase@JP2KCodeStm@@QAEPAXXZ',
    //'?GetStmProcs@JP2KCodeStm@@QAEPAUJP2KStreamProcsEx@@XZ', // cant hook in frida but called in jp2k_dec_image()
    {name: '?GetTotalLength@JP2KCodeStm@@QAE_KXZ', nargs: 0},
    {name: '?InitJP2KCodeStm@JP2KCodeStm@@QAEH_KHPAXPAUJP2KStreamProcsEx@@W4JP2KStmOpenMode@@H@Z', nargs: 7},
    {name: '?IsReadable@JP2KCodeStm@@QAE_NXZ', nargs: 0},
    {name: '?IsSeekable@JP2KCodeStm@@QAE_NXZ', nargs: 0},
    {name: '?IsWritable@JP2KCodeStm@@QAE_NXZ', nargs: 0},
    {name: '?ReadOnly@JP2KCodeStm@@QAE_NXZ', nargs: 0},
    {name: '?StmLengthUnknown@JP2KCodeStm@@QAE_NXZ', nargs: 0},
    {name: '?TellPos@JP2KCodeStm@@QAE_JXZ', nargs: 0},
    {name: '?WriteOnly@JP2KCodeStm@@QAE_NXZ', nargs: 0},
    {name: '?flushWriteBuffer@JP2KCodeStm@@QAEHXZ', nargs: 0},
    {name: '?read@JP2KCodeStm@@QAEHPAEH@Z', nargs: 2},
    {name: '?seek@JP2KCodeStm@@QAE_JH_J@Z', nargs: 2},
    {name: '?write@JP2KCodeStm@@QAEHPAEH@Z', nargs: 2}
];

method_names = jp2k_code_stm_methods.map(function(x) { return x.name });

/* ====================================== */
/* JP2KCodeStm interception and emulation */
/* ====================================== */

var exports = Module.enumerateExportsSync("JP2KLib.dll");
for (var i = 0; i < exports.length; i++) {
    ind = method_names.indexOf(exports[i].name);
    if (ind !== -1) {
        console.log(exports[i].name);
        switch (exports[i].name) {
			case "?InitJP2KCodeStm@JP2KCodeStm@@QAEH_KHPAXPAUJP2KStreamProcsEx@@W4JP2KStmOpenMode@@H@Z":
				Interceptor.attach(exports[i].address, {
                    onLeave: function(ret) { console.log('[i] JP2KCodeStm::Init() - ret=' + ret); }
				});
				break;
            case "?read@JP2KCodeStm@@QAEHPAEH@Z":
                Interceptor.attach(exports[i].address, {
                    onEnter: function(args) { this.arg_0 = args[0]; this.arg_1 = args[1]; },
                    onLeave: function(retval) {
                        console.log('[i] JP2KCodeStm::read() - writing ' + this.arg_1 + ' bytes to ' + this.arg_0 + ' ret=' + retval.toInt32());
                        // console.log('[!] context: ' + JSON.stringify(this.context));
                        dumpAddr('read()', this.arg_0, retval.toInt32());
                    }
                });
                break;
            case '?GetCurPos@JP2KCodeStm@@QAE_JXZ':
                Interceptor.attach(exports[i].address, {
                    onLeave: function(retval) {
                        console.log('[i] JP2KCodeStm::GetCurPos() - ret=' + this.context.eax + ' edx=' + this.context.edx); 
                    }
                });
                break;
            case '?seek@JP2KCodeStm@@QAE_JH_J@Z':
                Interceptor.attach(exports[i].address, {
                    onEnter: function(args) { this.arg_0 = args[0]; this.arg_1 = args[1]; },
                    onLeave: function(retval) {
                        console.log('[i] JP2KCodeStm::seek() - flag=' + this.arg_0 + ' pos=' + this.arg_1 + ' ret=' + retval);
                    }
                });
				break;
			case "?IsSeekable@JP2KCodeStm@@QAE_NXZ":
				Interceptor.attach(exports[i].address, {
                    onLeave: function(retval) { console.log('[i] JP2KCodeStm::IsSeekable(): ret=' + retval); }
				});
				break;
            default:
                Interceptor.attach(exports[i].address, {
                    onEnter: generateOnEnter(jp2k_code_stm_methods[ind]),
                    onLeave: generateOnLeave(jp2k_code_stm_methods[ind])
                });   
        }
    }
}

/* ================================= */
/* MemObj interception and emulation */
/* ================================= */

// MemObj functions to emulate, addresses from JP2KLib.dll - Reader v30096 (July 2018)
var memObjAlloc1 = resolveAddress(jp2kBase, '0x10066F88');
var memObjAlloc2 = resolveAddress(jp2kBase, '0x10067125');
var memObjFree1 = resolveAddress(jp2kBase, '0x10067075');
var memObjFree2 = resolveAddress(jp2kBase, '0x100670AA');
var memObjInitSomething = resolveAddress(jp2kBase, '0x10066ECD');
var memObjGetSomething = resolveAddress(jp2kBase, '0x100670DE');
var memObjMemcpyMemset = resolveAddress(jp2kBase, '0x100671CA');
var memObjMemset = resolveAddress(jp2kBase, '0x10067203');
var memObjNotImpl = resolveAddress(jp2kBase, '0x10067283');

Interceptor.attach(memObjAlloc1, {
	onEnter: function(args) {
		console.log('[i] memObjAlloc1: allocating ' + args[0] + ' * ' + args[1]);
	}
});

Interceptor.attach(memObjAlloc2, {
	onEnter: function(args) {
		console.log('[i] memObjAlloc2: allocating ' + args[0]);
	}
});

Interceptor.attach(memObjFree1, {
	onEnter: function(args) {
		console.log('[i] memObjFree1: freeing ' + args[0]);
	}
});

Interceptor.attach(memObjFree2, {
	onEnter: function(args) {
		console.log('[i] memObjFree2: freeing ' + args[0]);
	}
});

Interceptor.attach(memObjInitSomething, {
	onEnter: function(args) {
		console.log('[i] memObjInitSomething: size ' + args[0]);
	}
});

Interceptor.attach(memObjGetSomething, {
	onEnter: function(args) {
		console.log('[i] memObjGetSomething: size ' + args[0]);
	}
});

Interceptor.attach(memObjMemcpyMemset, {
	onEnter: function(args) {
		console.log('[i] memObjMemcpyMemset: dest: ' + args[0] + ' src: ' + args[1] + ' size: ' + args[2]);
	}
});

Interceptor.attach(memObjMemset, {
	onEnter: function(args) {
		console.log('[i] memObjMemset: dest: ' + args[0] + ' val: ' + args[1] + ' size: ' + args[2]);
	}
});

Interceptor.attach(memObjNotImpl, {
	onEnter: function(args) {
		console.log('[i] memObjNotImpl: a: ' + args[0] + ' b: ' + args[1]);
	}
});


/* ==== */
/* Misc */
/* ==== */

Interceptor.attach(resolveAddress(jp2kBase, '0x10040814'), {
	onEnter: function(args) { console.log('[i] entered big_jp2k'); },
    onLeave: function(ret) { console.log('[i] big_jp2k:: ret=' + ret); }	
});


/* ================ */
/* Helper functions */
/* ================ */

function generateOnEnter(method) {
    var body = "console.log(\"";
    body += "[i] " + method.name + ": ";
    for (var i = 0; i < method.nargs; i++) {
        body += "arg_" + i + " = \" + args[" + i + "] + \" ";
    }
    body += "\")";
    return new Function('args', body);
}

function generateOnLeave(method) {
    var body = "console.log(\"";
    body += "[i] " + method.name + ": ";
    body += "retval: \" + retval );"
    return new Function('retval', body);
}

// non functional
function insertBreakpoint(base, addr) {
    Memory.patchCode(resolveAddress(base, addr), 1, function(code) {
       var writer = new X86Writer(code, {pc: resolveAddress(base, addr)});
       writer.putBreakpoint();
       writer.flush();
    });
}

function dumpAddr(info, addr, size) {
    if (addr.isNull())
        return;
    
    var size = size > 0x100 ? 0x100 : size;
    console.log('Data dump ' + info + ' :');
    var buf = Memory.readByteArray(addr, size);

    // If you want color magic, set ansi to true
    console.log(hexdump(buf, { offset: 0, length: size, header: true, ansi: false }));
    if (size > 100) {
        console.log('[..truncated...]');
    }
}

function resolveAddress(base, addr) {
    var idaBase = ptr('0x10000000'); // Enter the base address of jvm.dll as seen in your favorite disassembler (here IDA)
    var offset = ptr(addr).sub(idaBase); // Calculate offset in memory from base address in IDA database
    var result = base.add(offset); // Add current memory base address to offset of function to monitor
    console.log('[+] New addr=' + result); // Write location of function in memory to console
    return result;
}