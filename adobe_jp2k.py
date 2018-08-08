from __future__ import print_function
import frida
import sys
import os

def on_message(message, data):
    print("[%s] => %s" % (message, data))

def main(target_process, type, jp2k):
    session = frida.attach(target_process)
    
    path = os.path.realpath(__file__)
    dir = os.path.dirname(path)
    with open(jp2k, 'rb') as jp2kfile:
        bytes = ', '.join(hex(ord(x)) for x in jp2kfile.read())
        jp2kBytes = "var jp2kBytes = [{bytes}];\n".format(bytes=bytes)
    frida_script = os.path.join(dir, "frida_trace.js" if type == "reader" else "frida_harness.js")
    print(frida_script)
    with open(frida_script) as frida_script:
        script = session.create_script(jp2kBytes + frida_script.read())
        script.on('message', on_message)
        script.load()

        print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach.\n\n")
        sys.stdin.read()
        session.detach()

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: %s <process name or PID> <'reader'|'harness'> <jp2k file>" % __file__)
        sys.exit(1)

    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]
    main(target_process, sys.argv[2], sys.argv[3])