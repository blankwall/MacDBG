import test_base
from libs.const import *
from ctypes import c_byte

def gen_callback(info_struct):
    return 1


class MacDbgTestException(test_base.MacDbgTestBase):
    def test_add_breakpoint(self):
        x = self.dbg.add_breakpoint("abc", PERSISTENT, self.dbg.make_callback(gen_callback))
        self.assertEqual(x, 1)
        x = self.dbg.add_breakpoint(0xe0e, PERSISTENT, self.dbg.make_callback(gen_callback))
        self.assertEqual(x, 1)
        x = self.dbg.add_breakpoint("hello", PERSISTENT, self.dbg.make_callback(gen_callback))
        self.assertEqual(x, 0)

    def test_get_breaks(self):
        x = self.dbg.get_breaks()
        self.assertEqual(len(x), 2)

    def test_add_exception(self):
        x = self.dbg.add_exception_callback(self.dbg.make_callback(gen_callback), NOTE_EXEC)
        self.assertEqual(x, 1)
        x = self.dbg.add_exception_callback(self.dbg.make_callback(gen_callback), NOTE_FORK)
        self.assertEqual(x, 1)

    @classmethod
    def tearDownClass(cls):
        cls.dbg.detach()
        super(MacDbgTestException, cls).tearDownClass()

if __name__ == '__main__':
    unittest.main()
