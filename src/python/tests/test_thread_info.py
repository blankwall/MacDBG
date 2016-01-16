import time
import test_base

class MacDbgTestThreadInfo(test_base.MacDbgTestBase):

    threads = []
    thread_handles = []
    thread_ids = []

    def test_all_threads(self):
        self.__class__.threads = self.dbg.thread_list_info();
        for i in self.__class__.threads:
            self.assertGreater(i,0)

    def test_basic_info(self):
        for i in self.__class__.threads:
            basic_info = self.dbg.get_thread_basic_info(i)
            self.assertGreater(basic_info.user_time.microseconds, 0)
            self.assertGreater(basic_info.system_time.microseconds, 0)

    def test_identifer(self):
        for i in self.__class__.threads:
            thread_ident_info = self.dbg.get_thread_identifier_info(i)
            thread_id = thread_ident_info.thread_id
            self.assertGreater(thread_id, 0)
            self.thread_ids.append(thread_id)
            thread_handle = thread_ident_info.thread_handle
            self.assertGreater(thread_handle, 0)
            self.__class__.thread_handles.append(thread_handle)

    def test_proc_thread_info(self):
        for i in self.__class__.thread_handles:
            proc_t_info = self.dbg.get_proc_threadinfo(i)
            self.assertGreater(proc_t_info.pth_user_time, 0)
            self.assertGreater(proc_t_info.pth_system_time, 0)
            self.assertGreater(proc_t_info.pth_priority, 0)
            self.assertGreater(proc_t_info.pth_maxpriority, 0)

    def test_thread_suspend_resume(self):
        for i in self.__class__.threads:
            status = self.dbg.thread_suspend_(i)
            self.assertEqual(status, 0)
            time.sleep(2)
            status = self.dbg.thread_resume_(i)
            self.assertEqual(status, 0)

    def test_thread_state(self):
        for i in self.__class__.threads:
            x = self.dbg.get_thread_state(i)
            self.assertEqual(len(x), 21)
            x["r13"] = 1
            self.dbg.set_thread_state(i, x)
            x = self.dbg.get_thread_state(i)
            self.assertEqual(x["r13"], 1)

if __name__ == '__main__':
    unittest.main()
