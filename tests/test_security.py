import unittest
from common import generate_salt, hash_password, verify_password, TokenBucket, ReplayWindow

class TestSecurity(unittest.TestCase):
    def test_hash_and_verify(self):
        salt = generate_salt()
        pw = 'S3cure!'
        h = hash_password(pw, salt)
        self.assertTrue(verify_password(pw, salt, h))
        self.assertFalse(verify_password('wrong', salt, h))

    def test_token_bucket(self):
        tb = TokenBucket(capacity=2, fill_rate=1.0)
        self.assertTrue(tb.consume())
        self.assertTrue(tb.consume())
        self.assertFalse(tb.consume())

    def test_replay(self):
        rw = ReplayWindow()
        self.assertTrue(rw.check_and_advance(1))
        self.assertTrue(rw.check_and_advance(2))
        self.assertFalse(rw.check_and_advance(2))  # replay
        self.assertFalse(rw.check_and_advance(1))  # old

if __name__=='__main__':
    unittest.main()
