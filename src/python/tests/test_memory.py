import test_base
from libs.const import *
from ctypes import c_byte

class MacDbgTestProccessInfo(test_base.MacDbgTestBase):

    allocation = 0

    def test_image_size(self):
        self.assertGreater(self.dbg.get_image_size(), 0)

    def test_allocate(self):
        self.__class__.allocation = self.dbg.allocate_space(4096, VM_FLAGS_ANYWHERE)
        self.assertGreater(self.__class__.allocation, self.dbg.base_address)

    def test_change_page(self):
        self.dbg.change_page_protection(self.dbg.base_address, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE)
        prot = self.dbg.get_page_protection(self.dbg.base_address)
        self.assertEqual(prot,'rwx')

    def test_disass(self):
        dis = self.dbg.disass(self.dbg.base_address+0xd90, 3, 1)
        self.assertTrue("push\trbp" in dis[0])

    def test_get_page(self):
        prot = self.dbg.get_page_protection(self.dbg.base_address)
        self.assertEqual(prot,'rwx')   

    def test_hex_dump(self):
        HEX_STRING = 'TEST_HEX_DUMP'
        addr = self.dbg.inject_code(HEX_STRING)
        act = self.dbg.hex_dump(addr,len(HEX_STRING))
        exp = ":".join("{:02x}".format(ord(c)) for c in HEX_STRING)
        self.assertEqual(act, exp)

    def test_inject_code(self):
        INJECT_STRING = 'TEST_INJECT_CODE'
        addr = self.dbg.inject_code(INJECT_STRING)
        self.assertEqual(INJECT_STRING, self.dbg.read_memory_string(addr, len(INJECT_STRING)))

    def test_region(self):
        region_info = self.dbg.get_region_info(self.dbg.base_address)
        prot = self.dbg.protection_to_string(region_info.protection)
        self.assertEqual(prot,'rwx')

    def test_search_mem(self):
        search_string = "blue"
        search_results = self.dbg.search_mem(search_string, self.dbg.base_address, 0x40000)
        self.assertEqual(len(search_results), 3)

    def test_write_bytes(self):
        WRITE_STRING = 'TEST_WRITE_BYTES'
        addr = self.dbg.write_bytes(self.__class__.allocation , WRITE_STRING)
        self.assertEqual(WRITE_STRING, self.dbg.read_memory_string(addr, len(WRITE_STRING)))

    def test_write_memory(self):
        WRITE_DATA = 0x41
        self.dbg.write_memory(self.__class__.allocation , WRITE_DATA, 1)
        str = self.dbg.read_memory(self.__class__.allocation, 1)
        res = format(ord(str), '#04x')
        self.assertEqual(res, hex(WRITE_DATA))

    def test_free_memory(self):
        size = 10
        allocation2 = self.dbg.allocate(self.dbg.base_address, size, VM_FLAGS_ANYWHERE)
        self.assertGreater(allocation2, self.dbg.base_address)
        status = self.dbg.free_memory(allocation2, size)
        self.assertEqual(status, 1)


if __name__ == '__main__':
    unittest.main()
