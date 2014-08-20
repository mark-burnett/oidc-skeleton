from s_user.client_sdk import ClientSDK
import unittest


class TestWebWorkflow(unittest.TestCase):
    def test_client_gets_resource(self):
        c = ClientSDK('alice:k')
        actual_resource = c.get_forwarded_resource('foo')

        expected_resource = {
            'name': 'foo',
            'data': 'HERE IS SOME CRAXZY FOO DATA',
        }

        self.assertEqual(expected_resource, actual_resource)


if __name__ == '__main__':
    unittest.main()
