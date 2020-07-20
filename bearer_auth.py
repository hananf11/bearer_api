import requests


class BearerAuth(requests.auth.AuthBase):
    def __init__(self, username, password, auth_url):
        self.username = username
        self.password = password
        self.auth_url = auth_url
        self._token = ''

    def handel_401(self, response, **kwargs):
        """Handel a token/auth error."""
        if response.status_code == 401:  # this may need to be changed to include all 4xx errors
            # make a post request to get the token
            token_r = requests.post(self.auth_url, params={
                'grant_type': 'password',
                'username': self.username,
                'password': self.password
            }, headers={
                'Content-Type': 'application/x-www-form-urlencoded'
            })
            if token_r.status_code == 200:
                # if the getting the token was successful update it
                self._token = token_r.json()['access_token']  # update the token

            new_request = response.request.copy()  # create a copy of the user request
            new_request.headers['Authorization'] = "Bearer %s" % self._token  # update the Auth header
            # return a new response made from the modified request
            return response.connection.send(new_request, **kwargs)
        return response

    def __call__(self, request):
        # add the Authorization header
        request.headers['Authorization'] = "Bearer %s" % self._token
        # add a hook to check if there was a 401 error and try again
        request.register_hook('response', self.handel_401)
        return request  # return the request
