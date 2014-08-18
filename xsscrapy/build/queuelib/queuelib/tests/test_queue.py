import os, glob, tempfile

from queuelib.queue import FifoMemoryQueue, LifoMemoryQueue, FifoDiskQueue, LifoDiskQueue
from queuelib.tests import QueuelibTestCase

class FifoMemoryQueueTest(QueuelibTestCase):

    def queue(self):
        return FifoMemoryQueue()

    def test_empty(self):
        """Empty queue test"""
        q = self.queue()
        assert q.pop() is None

    def test_push_pop1(self):
        """Basic push/pop test"""
        q = self.queue()
        q.push(b'a')
        q.push(b'b')
        q.push(b'c')
        self.assertEqual(q.pop(), b'a')
        self.assertEqual(q.pop(), b'b')
        self.assertEqual(q.pop(), b'c')
        self.assertEqual(q.pop(), None)

    def test_push_pop2(self):
        """Test interleaved push and pops"""
        q = self.queue()
        q.push(b'a')
        q.push(b'b')
        q.push(b'c')
        q.push(b'd')
        self.assertEqual(q.pop(), b'a')
        self.assertEqual(q.pop(), b'b')
        q.push(b'e')
        self.assertEqual(q.pop(), b'c')
        self.assertEqual(q.pop(), b'd')
        self.assertEqual(q.pop(), b'e')

    def test_len(self):
        q = self.queue()
        self.assertEqual(len(q), 0)
        q.push(b'a')
        self.assertEqual(len(q), 1)
        q.push(b'b')
        q.push(b'c')
        self.assertEqual(len(q), 3)
        q.pop()
        q.pop()
        q.pop()
        self.assertEqual(len(q), 0)


class LifoMemoryQueueTest(QueuelibTestCase):

    def queue(self):
        return LifoMemoryQueue()

    def test_empty(self):
        """Empty queue test"""
        q = self.queue()
        assert q.pop() is None

    def test_push_pop1(self):
        """Basic push/pop test"""
        q = self.queue()
        q.push(b'a')
        q.push(b'b')
        q.push(b'c')
        self.assertEqual(q.pop(), b'c')
        self.assertEqual(q.pop(), b'b')
        self.assertEqual(q.pop(), b'a')
        self.assertEqual(q.pop(), None)

    def test_push_pop2(self):
        """Test interleaved push and pops"""
        q = self.queue()
        q.push(b'a')
        q.push(b'b')
        q.push(b'c')
        q.push(b'd')
        self.assertEqual(q.pop(), b'd')
        self.assertEqual(q.pop(), b'c')
        q.push(b'e')
        self.assertEqual(q.pop(), b'e')
        self.assertEqual(q.pop(), b'b')
        self.assertEqual(q.pop(), b'a')

    def test_len(self):
        q = self.queue()
        self.assertEqual(len(q), 0)
        q.push(b'a')
        self.assertEqual(len(q), 1)
        q.push(b'b')
        q.push(b'c')
        self.assertEqual(len(q), 3)
        q.pop()
        q.pop()
        q.pop()
        self.assertEqual(len(q), 0)


class FifoDiskQueueTest(FifoMemoryQueueTest):

    chunksize = 100000

    def setUp(self):
        FifoMemoryQueueTest.setUp(self)
        self.qdir = self.mktemp()

    def queue(self):
        return FifoDiskQueue(self.qdir, chunksize=self.chunksize)

    def test_close_open(self):
        """Test closing and re-opening keeps state"""
        q = self.queue()
        q.push(b'a')
        q.push(b'b')
        q.push(b'c')
        q.push(b'd')
        self.assertEqual(q.pop(), b'a')
        self.assertEqual(q.pop(), b'b')
        q.close()
        del q
        q = self.queue()
        self.assertEqual(len(q), 2)
        q.push(b'e')
        self.assertEqual(q.pop(), b'c')
        self.assertEqual(q.pop(), b'd')
        q.close()
        del q
        q = self.queue()
        self.assertEqual(q.pop(), b'e')
        self.assertEqual(len(q), 0)

    def test_chunks(self):
        """Test chunks are created and removed"""
        values = [b'0', b'1', b'2', b'3', b'4']
        q = self.queue()
        for x in values:
            q.push(x)

        chunks = glob.glob(os.path.join(self.qdir, 'q*'))
        self.assertEqual(len(chunks), 5 // self.chunksize + 1)
        for x in values:
            q.pop()

        chunks = glob.glob(os.path.join(self.qdir, 'q*'))
        self.assertEqual(len(chunks), 1)

    def test_cleanup(self):
        """Test queue dir is removed if queue is empty"""
        q = self.queue()
        values = [b'0', b'1', b'2', b'3', b'4']
        assert os.path.exists(self.qdir)
        for x in values:
            q.push(x)

        for x in values:
            q.pop()
        q.close()
        assert not os.path.exists(self.qdir)


class ChunkSize1FifoDiskQueueTest(FifoDiskQueueTest):
    chunksize = 1

class ChunkSize2FifoDiskQueueTest(FifoDiskQueueTest):
    chunksize = 2

class ChunkSize3FifoDiskQueueTest(FifoDiskQueueTest):
    chunksize = 3

class ChunkSize4FifoDiskQueueTest(FifoDiskQueueTest):
    chunksize = 4


class LifoDiskQueueTest(LifoMemoryQueueTest):

    def setUp(self):
        LifoMemoryQueueTest.setUp(self)
        self.path = tempfile.mktemp()

    def queue(self):
        return LifoDiskQueue(self.path)

    def test_close_open(self):
        """Test closing and re-opening keeps state"""
        q = self.queue()
        q.push(b'a')
        q.push(b'b')
        q.push(b'c')
        q.push(b'd')
        self.assertEqual(q.pop(), b'd')
        self.assertEqual(q.pop(), b'c')
        q.close()
        del q
        q = self.queue()
        self.assertEqual(len(q), 2)
        q.push(b'e')
        self.assertEqual(q.pop(), b'e')
        self.assertEqual(q.pop(), b'b')
        q.close()
        del q
        q = self.queue()
        self.assertEqual(q.pop(), b'a')
        self.assertEqual(len(q), 0)

    def test_cleanup(self):
        """Test queue file is removed if queue is empty"""
        q = self.queue()
        values = [b'0', b'1', b'2', b'3', b'4']
        assert os.path.exists(self.path)
        for x in values:
            q.push(x)

        for x in values:
            q.pop()

        q.close()
        assert not os.path.exists(self.path)

    def test_file_size_shrinks(self):
        """Test size of queue file shrinks when popping items"""
        q = self.queue()
        q.push(b'a')
        q.push(b'b')
        q.close()
        size = os.path.getsize(self.path)
        q = self.queue()
        q.pop()
        q.close()
        assert os.path.getsize(self.path), size
