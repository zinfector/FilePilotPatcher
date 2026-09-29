"""Real Shell COM tests on disposable files under the project workspace."""
import ctypes as C
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent.parent / 'analysis' / 'undo-0.8.5' / 'runtime-fixtures'
FIXTURES.mkdir(parents=True, exist_ok=True)
dll = C.WinDLL(str(HERE / 'FPilot.Undo.dll'))
dll.HistoryTestOperation.argtypes = [C.c_int, C.c_wchar_p, C.c_wchar_p]
dll.HistoryTestOperation.restype = C.c_long
dll.HistoryTestReplay.argtypes = [C.c_int]
dll.HistoryTestCount.argtypes = [C.c_int]
dll.HistoryTestError.argtypes = [C.c_wchar_p, C.c_uint]
ole = C.OleDLL('ole32')
ole.CoInitializeEx(None, 2)


class HistoryTests(unittest.TestCase):
    def setUp(self):
        dll.HistoryTestReset()
        self.root = Path(tempfile.mkdtemp(prefix=self._testMethodName+'-', dir=FIXTURES))
        self.a, self.b = self.root/'a', self.root/'b'
        self.a.mkdir(); self.b.mkdir()
        self.file = self.a/'document.txt'
        self.file.write_text('original content', encoding='utf-8')

    def message(self):
        p=C.create_unicode_buffer(1024);dll.HistoryTestError(p,1024);return p.value

    def operation(self, kind, file=None, target=None):
        hr=dll.HistoryTestOperation(kind,str(file or self.file),str(target or self.b))
        self.assertGreaterEqual(hr,0,hex(hr & 0xffffffff))

    def replay(self, undo=True):
        self.assertTrue(dll.HistoryTestReplay(undo),self.message())

    def test_move_repeated(self):
        self.operation(1)
        self.assertFalse(self.file.exists())
        self.assertEqual(dll.HistoryTestCount(True),1)
        for _ in range(3):
            self.replay();self.assertEqual(self.file.read_text(),'original content')
            self.replay(False);self.assertTrue((self.b/self.file.name).exists())
        self.replay()

    def test_recycle_repeated(self):
        self.operation(2)
        self.assertFalse(self.file.exists())
        for _ in range(3):
            self.replay();self.assertEqual(self.file.read_text(),'original content')
            self.replay(False);self.assertFalse(self.file.exists())
        self.replay()

    def test_directory_move(self):
        folder=self.a/'folder';folder.mkdir();(folder/'nested.txt').write_text('nested')
        self.operation(1,folder)
        self.replay();self.assertEqual((folder/'nested.txt').read_text(),'nested')
        self.replay(False);self.assertTrue((self.b/'folder'/'nested.txt').exists())

    def test_directory_recycle(self):
        folder=self.a/'folder';folder.mkdir();(folder/'nested.txt').write_text('nested')
        self.operation(2,folder)
        self.replay();self.assertEqual((folder/'nested.txt').read_text(),'nested')

    def test_occupied_original_does_not_overwrite(self):
        self.operation(1)
        self.file.write_text('replacement')
        self.assertFalse(dll.HistoryTestReplay(True))
        self.assertEqual(self.file.read_text(),'replacement')
        self.assertEqual((self.b/self.file.name).read_text(),'original content')

    def test_replaced_result_identity(self):
        self.operation(1)
        result=self.b/self.file.name
        result.rename(self.b/'preserved.txt')
        result.write_text('replacement')
        self.assertFalse(dll.HistoryTestReplay(True))
        self.assertEqual(result.read_text(),'replacement')
        self.assertFalse(self.file.exists())

    def test_redo_branch_cleared(self):
        self.operation(1);self.replay()
        self.assertEqual(dll.HistoryTestCount(False),1)
        self.operation(1)
        self.assertEqual(dll.HistoryTestCount(False),0)

    def test_unicode(self):
        named=self.a/'日本語-é-😀.txt';self.file.rename(named)
        self.operation(1,named);self.replay()
        self.assertEqual(named.read_text(),'original content')

    def test_empty_history(self):
        self.assertFalse(dll.HistoryTestReplay(True))
        self.assertEqual(self.file.read_text(),'original content')


if __name__=='__main__':
    unittest.main(verbosity=2)
