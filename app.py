import requests

from bearer_auth import BearerAuth

api_url = 'http://localhost:8080/api/'

auth = BearerAuth('admin', 'admin', api_url + 'auth/login-form')

r = requests.get(api_url + '/api/users', auth=auth)
