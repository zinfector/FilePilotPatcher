"""Exercise runtime hook installation and registration in an inert mapped PE.

The File Pilot entrypoint and original code are never executed. Registrar/parser
test doubles let us verify the hook ABI without controlling the desktop app.
"""
import ctypes as C
from pathlib import Path
import struct
import unittest
import lief

HERE=Path(__file__).resolve().parent
BASE=0x140000000
K=C.WinDLL('kernel32',use_last_error=True)
K.VirtualAlloc.argtypes=[C.c_void_p,C.c_size_t,C.c_ulong,C.c_ulong]
K.VirtualAlloc.restype=C.c_void_p
K.VirtualProtect.argtypes=[C.c_void_p,C.c_size_t,C.c_ulong,C.POINTER(C.c_ulong)]


class Hooks(unittest.TestCase):
    def test_install_register_and_preserve_text(self):
        image=lief.PE.parse(str(HERE/'../../ghidra/project/FPilot.exe'))
        address=K.VirtualAlloc(BASE,image.optional_header.sizeof_image,0x3000,0x40)
        self.assertEqual(address,BASE,'Test image base unavailable')
        for s in image.sections:
            data=bytes(s.content)
            C.memmove(BASE+s.virtual_address,data,len(data))
        text_before=C.string_at(BASE+0x8a840,0x116)
        dll=C.WinDLL(str(HERE/'FPilot.Undo.dll'))
        dll.HistoryInitialize.argtypes=[C.c_void_p]
        # Changed instruction must fail without writing any other site.
        C.memmove(BASE+0x111f93,b'\x90',1)
        self.assertFalse(dll.HistoryInitialize(BASE))
        self.assertEqual(C.string_at(BASE+0x27697,1),b'\xe8')
        C.memmove(BASE+0x111f93,b'\xff',1)
        self.assertTrue(dll.HistoryInitialize(BASE))
        self.assertTrue(dll.HistoryInitialize(BASE))
        sites=[0x1131a8,0x108907,0x110a97,0x20b1fd,0x7ea16,0x7ec26,0x113a2b,0x113b1c,0x1f6985]
        def relay(rva):
            code=C.string_at(BASE+rva,5)
            self.assertEqual(code[0],0xe8)
            dest=BASE+rva+5+struct.unpack('<i',code[1:])[0]
            self.assertEqual(C.string_at(dest,2),b'\x48\xb8')
            self.assertEqual(C.string_at(dest+10,2),b'\xff\xe0')
            return struct.unpack('<Q',C.string_at(dest+2,8))[0]
        self.assertEqual(len({relay(rva) for rva in sites}),1)
        self.assertNotEqual(relay(0x111f93),relay(sites[0]))
        self.assertEqual(C.string_at(BASE+0x111f98,1),b'\x90')
        self.assertEqual(C.string_at(BASE+0x8a840,0x116),text_before)

        class Text(C.Structure):
            _fields_=[('p',C.c_void_p),('n',C.c_size_t)]
        Register=C.WINFUNCTYPE(C.c_void_p,C.c_void_p,C.c_void_p,C.POINTER(Text),C.POINTER(Text),C.c_void_p,C.c_uint)
        Parser=C.WINFUNCTYPE(C.c_uint,C.POINTER(Text),C.c_void_p,C.c_int)
        descriptors=[];registrations=[];keys=[]
        @Register
        def register(arena,registry,name,group,callback,flags):
            record=C.create_string_buffer(0x48);descriptors.append(record)
            registrations.append((arena,registry,C.string_at(name.contents.p,name.contents.n),callback,flags))
            return C.addressof(record)
        @Parser
        def parse(key,descriptor,offset):
            keys.append((C.string_at(key.contents.p,key.contents.n),descriptor,offset))
            return 1
        def stub(rva,callback):
            old=C.c_ulong()
            self.assertTrue(K.VirtualProtect(BASE+rva,16,0x40,C.byref(old)))
            C.memmove(BASE+rva,b'\x48\xb8'+struct.pack('<Q',C.cast(callback,C.c_void_p).value)+b'\xff\xe0',12)
        stub(0x260d0,register);stub(0x36880,parse)
        name_buffer=C.create_string_buffer(b'HK_SelectionTrash')
        group_buffer=C.create_string_buffer(b'Files')
        name=Text(C.addressof(name_buffer),17);group=Text(C.addressof(group_buffer),5)
        hook=Register(relay(0x27697))
        result=hook(0x111,0x222,C.byref(name),C.byref(group),0x333,6)
        self.assertEqual(result,C.addressof(descriptors[0]))
        self.assertEqual(len(registrations),4)
        self.assertEqual([x[0] for x in keys],[b'Ctrl+Z',b'Ctrl+Y',b'Ctrl+Shift+Z'])
        self.assertTrue(all(x[4]==6 for x in registrations))
        self.assertTrue(all(x[2]==0 for x in keys))
        Query=C.WINFUNCTYPE(C.c_bool,C.c_void_p,C.c_void_p,C.c_int)
        for entry in registrations[1:]:
            self.assertTrue(Query(entry[3])(None,None,0),'Empty stack must report disabled')
        self.assertEqual(registrations[2][3],registrations[3][3])


if __name__=='__main__':
    unittest.main(verbosity=2)
