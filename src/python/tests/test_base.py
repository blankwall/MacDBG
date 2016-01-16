import unittest
import os, signal
from libs.macdbg import MacDbg
from ctypes import *

class MacDbgTestBase(unittest.TestCase):
    PROGRAM_NAME = "./test_prog.app"

    @classmethod
    def setUpClass(cls):
        cls.dbg = MacDbg()
        arr = (c_char_p * 2)()
        arr[0] = cls.PROGRAM_NAME
        arr[1] = 0

        cls.dbg.run(cls.PROGRAM_NAME, arr)

    def test_task(self):
        self.assertNotEqual(self.dbg.task, 0)

    @classmethod
    def tearDownClass(cls):
        cls.dbg.terminate_()

if __name__ == '__main__':
    unittest.main()
