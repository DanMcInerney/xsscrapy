import unittest, tempfile, shutil

class QueuelibTestCase(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="queuelib-tests-")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def mktemp(self):
        return tempfile.mktemp(dir=self.tmpdir)
