from s_user.client_sdk import ClientSDK
import unittest


class TestWebWorkflow(unittest.TestCase):
    def test_client_gets_resource(self):
        c = ClientSDK('alice:k')
        actual_resource = c.get_direct_resource('buz')

        expected_resource = {
            'name': 'buz',
            'data': 'some data that lives on the client',
        }

        self.assertEqual(expected_resource, actual_resource)

    def test_client_gets_resource_twice(self):
        c = ClientSDK('alice:k')
        first_resource = c.get_direct_resource('buz')
        second_resource = c.get_direct_resource('buz')

        expected_resource = {
            'name': 'buz',
            'data': 'some data that lives on the client',
        }

        self.assertEqual(expected_resource, second_resource)


if __name__ == '__main__':
    unittest.main()
