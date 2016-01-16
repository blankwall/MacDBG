import test_base
from libs.const import *

class MacDbgTestProccessInfo(test_base.MacDbgTestBase):
    def test_pid(self):
        self.pid = self.dbg.find_pid()
        self.assertNotEqual(self.pid, 0)

    def test_base_address(self):
        base_address = self.dbg.get_base_address()
        self.assertGreater(base_address, 0)


if __name__ == '__main__':
    unittest.main()
