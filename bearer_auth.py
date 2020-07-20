import requests


class BearerAuth(requests.auth.AuthBase):
    def __init__(self, username, password, auth_url, retries=3):
        self.username = username
        self.password = password
        self.auth_url = auth_url
        self.token = ''
        self.retries = retries

    def handel_401(self, response, **kwargs):
        """Handel a token/auth error."""
        if response.status_code == 401:  # this may need to be changed to include all 4xx errors
            token_r = requests.post(self.auth_url, params={
                'grant_type': 'password',
                'username': self.username,
                'password': self.password
            }, headers={
                'Content-Type': 'application/x-www-form-urlencoded'
            })
            if token_r.status_code == 200:
                self.token = token_r.json()['access_token']  # update the token

            new_request = response.request.copy()
            new_request.headers['Authorization'] = "Bearer %s" % self.token
            return response.connection.send(new_request, **kwargs)
        return response

    def __call__(self, request):
        request.headers['Authorization'] = "Bearer %s" % self.token
        request.register_hook('response', self.handel_401)
        return request  # return the request
