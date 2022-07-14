from __future__ import annotations

import asyncio
import json
import math
import socket
import datetime
import time
import threading
from typing import Union, Optional

import python_jwt as jwt

from gcloud import storage
from random import uniform
from sseclient import SSEClient
from Crypto.PublicKey import RSA
from collections import OrderedDict
from urllib.parse import urlencode, quote
from oauth2client.service_account import ServiceAccountCredentials
from aiohttp import ClientResponse, ClientSession, ClientResponseError

from firebase.exceptions import HTTPExceptionError

class Firebase: #basicly done
    """ Firebase Interface."""
    def __init__(self, config: dict):
        self.api_key: str = config.get("apiKey")
        self.auth_domain: str = config.get("authDomain")
        self.database_url: str = config.get("databaseURL")
        
        self.storage_bucket: str = config.get("storageBucket")
        self.credentials = None
        self.requests: ClientSession = ClientSession #are you sure? this required a header. hmm maybe idk

        if config.get("serviceAccount"):
            scopes = [
                'https://www.googleapis.com/auth/firebase.database',
                'https://www.googleapis.com/auth/userinfo.email',
                "https://www.googleapis.com/auth/cloud-platform"
            ]

            service_account_type: Union[dict, str] = config.get("serviceAccount")

            if isinstance(service_account_type, str):
                self.credentials = ServiceAccountCredentials.from_json_keyfile_name(config["serviceAccount"], scopes)

            if isinstance(service_account_type, dict):
                self.credentials = ServiceAccountCredentials.from_json_keyfile_dict(config["serviceAccount"], scopes)

    def auth(self) -> Auth:
        return Auth(self.api_key, self.requests, self.credentials)

    def database(self) -> Database:
        return Database(self.credentials, self.api_key, self.database_url, self.requests)

    def storage(self) -> Storage:
        return Storage(self.credentials, self.storage_bucket, self.requests)

class Auth: #ignore this for now
    """ Authentication Service """
    def __init__(self, api_key: str, requests_session: ClientSession, credentials: ServiceAccountCredentials):
        self.api_key = api_key
        self.current_user = None
        self.requests: ClientSession = requests_session
        self.credentials: ServiceAccountCredentials = credentials

    async def sign_in_with_email_and_password(self, email: str, password: str):
        request_object = await self._create_user_with_email_and_password_2(
            'https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key=', email, password
        )

        self.current_user = await request_object.json()
        return self.current_user

    def create_custom_token(self, uid: str, additional_claims = None):
        service_account_email = self.credentials.service_account_email
        private_key = RSA.importKey(self.credentials._private_key_pkcs8_pem)

        payload = {
            "iss": service_account_email,
            "sub": service_account_email,
            "aud": "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
            "uid": uid
        }

        if additional_claims:
            payload["claims"] = additional_claims

        exp = datetime.timedelta(minutes=60)
        return jwt.generate_jwt(payload, private_key, "RS256", exp)

    async def sign_in_with_custom_token(self, token: str):
        request_ref = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key={self.api_key}"

        headers = {"content-type": "application/json; charset=UTF-8"}
        data = json.dumps({"returnSecureToken": True, "token": token})
        request_object = await self.requests.post(request_ref, headers=headers, data=data)
        await raise_detailed_error(request_object)
        return await request_object.json()

    async def refresh(self, refresh_token: str) -> dict:
        request_ref = f"https://securetoken.googleapis.com/v1/token?key={self.api_key}"
        headers = {"content-type": "application/json; charset=UTF-8"}
        data = json.dumps({"grantType": "refresh_token", "refreshToken": refresh_token})
        request_object = await self.requests.post(request_ref, headers=headers, data=data)
        await raise_detailed_error(request_object)
        request_object_json = await request_object.json()
        
        return {
            "userId": request_object_json["user_id"],
            "idToken": request_object_json["id_token"],
            "refreshToken": request_object_json["refresh_token"]
        }

    async def get_account_info(self, id_token):
        request_ref = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo?key={self.api_key}"

        headers = {"content-type": "application/json; charset=UTF-8"}
        data = json.dumps({"idToken": id_token})
        request_object = await self.requests.post(request_ref, headers=headers, data=data)
        await raise_detailed_error(request_object)
        return await request_object.json()

    async def send_email_verification(self, id_token):
        request_ref = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode?key={self.api_key}"

        headers = {"content-type": "application/json; charset=UTF-8"}
        data = json.dumps({"requestType": "VERIFY_EMAIL", "idToken": id_token})
        request_object = await self.requests.post(request_ref, headers=headers, data=data)
        await raise_detailed_error(request_object)
        return await request_object.json()

    async def send_password_reset_email(self, email: str):
        request_ref = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode?key={self.api_key}"

        headers = {"content-type": "application/json; charset=UTF-8"}
        data = json.dumps({"requestType": "PASSWORD_RESET", "email": email})
        request_object = await self.requests.post(request_ref, headers=headers, data=data)
        await raise_detailed_error(request_object)
        return await request_object.json()

    async def verify_password_reset_code(self, reset_code, new_password):
        request_ref = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/resetPassword?key={self.api_key}"

        headers = {"content-type": "application/json; charset=UTF-8"}
        data = json.dumps({"oobCode": reset_code, "newPassword": new_password})
        request_object = await self.requests.post(request_ref, headers=headers, data=data)
        await raise_detailed_error(request_object)
        return await request_object.json()

    async def create_user_with_email_and_password(self, email, password):
        request_object = await self._create_user_with_email_and_password_2(
            'https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser?key=', email, password
        )

        return await request_object.json()

    async def _create_user_with_email_and_password_2(self, arg0, email: str, password: str) -> ClientResponse: #tf
        request_ref = f"{arg0}{self.api_key}"
        headers = {"content-type": "application/json; charset=UTF-8"}
        data = json.dumps({"email": email, "password": password, "returnSecureToken": True})

        result = await self.requests.post(request_ref, headers=headers, data=data)
        await raise_detailed_error(result)
        return result


class Database: #WIP
    """ Database Service """
    def __init__(
        self, 
        credentials: ServiceAccountCredentials, 
        api_key: str, 
        database_url: str, 
        requests_session: ClientSession
    ):
    
        url = database_url if database_url.endswith('/') else ''.join([database_url, '/'])

        self.credentials = credentials
        self.api_key = api_key
        self.database_url = url
        self.requests = requests_session

        self.path = ""
        self.build_query: str = {}
        self.last_push_time = 0
        self.last_rand_chars: list = []

    def order_by_key(self) -> Database:
        self.build_query["orderBy"] = "$key"
        return self

    def order_by_value(self) -> Database:
        self.build_query["orderBy"] = "$value"
        return self

    def order_by_child(self, order) -> Database:
        self.build_query["orderBy"] = order
        return self

    def start_at(self, start) -> Database:
        self.build_query["startAt"] = start
        return self

    def end_at(self, end) -> Database:
        self.build_query["endAt"] = end
        return self

    def equal_to(self, equal) -> Database:
        self.build_query["equalTo"] = equal
        return self

    def limit_to_first(self, limit_first) -> Database:
        self.build_query["limitToFirst"] = limit_first
        return self

    def limit_to_last(self, limit_last) -> Database:
        self.build_query["limitToLast"] = limit_last
        return self

    def shallow(self) -> Database:
        self.build_query["shallow"] = True
        return self

    def child(self, *args) -> Database:
        path = "/".join([str(arg) for arg in args])
        new_path = self.path+path
        db = Database(self.credentials, self.api_key, self.database_url, self.requests)
        db.path = new_path
        db.build_query = self.build_query
        return db
    
    def build_request_url(self, token: str) -> str:
        parameters = {}
        if token:
            parameters['auth'] = token
        
        for param in list(self.build_query):
            
            if isinstance(self.build_query[param], str):
                parameters[param] = quote('"' + self.build_query[param] + '"')
            
            elif isinstance(self.build_query[param], bool):
                parameters[param] = "true" if self.build_query[param] else "false"
            
            else:
                parameters[param] = self.build_query[param]
        
        request_ref = f'{self.database_url}{self.path}.json?{urlencode(parameters)}'
        self.path = ""
        self.build_query = {}
        
        return request_ref

    def build_headers(self, token: str = None) -> dict[str, str]:
        headers = {"content-type": "application/json; charset=UTF-8"}
        if not token and self.credentials:
            access_token = self.credentials.get_access_token().access_token
            headers['Authorization'] = f'Bearer {access_token}'
        
        return headers

    async def get(self, token: str = None, json_kwargs: dict = None) -> FirebaseResponse:
        build_query = self.build_query
        
        query_key = self.path.split("/")[-1]
        request_ref = self.build_request_url(token)
        headers = self.build_headers(token)
        
        request_object = await ClientSession(headers=headers).get(request_ref)
        await raise_detailed_error(request_object)
        request_dict = await request_object.json(**json_kwargs)

        if isinstance(request_dict, list):
            return FirebaseResponse(convert_list_to_firebase(request_dict), query_key)

        if not isinstance(request_dict, dict):
            return FirebaseResponse(request_dict, query_key)

        if not build_query:
            return FirebaseResponse(convert_to_firebase(request_dict.items()), query_key)

        if build_query.get("shallow"):
            return FirebaseResponse(request_dict.keys(), query_key)

        sorted_response = None

        if build_query.get("orderBy"):
            if build_query["orderBy"] == "$key":
                sorted_response = sorted(request_dict.items(), key=lambda item: item[0])
            elif build_query["orderBy"] == "$value":
                sorted_response = sorted(request_dict.items(), key=lambda item: item[1])
            else:
                sorted_response = sorted(request_dict.items(), key=lambda item: item[1][build_query["orderBy"]])
        
        return FirebaseResponse(convert_to_firebase(sorted_response), query_key)

    async def push(self, data, token: str = None, json_kwargs: dict = None) -> FirebaseResponse:
        request_ref = self.check_token(self.database_url, self.path, token)
        self.path = ""
        headers = self.build_headers(token)
        request_object = await self.requests.post(
            request_ref, headers=headers, data=json.dumps(data, **json_kwargs).encode("utf-8")
        )
        await raise_detailed_error(request_object)
        return await request_object.json()

    async def set(self, data, token: str =None, json_kwargs: dict =None) -> FirebaseResponse:
        request_ref = self.check_token(self.database_url, self.path, token)
        self.path = ""
        headers = self.build_headers(token)
        request_object = await self.requests.put(
            request_ref, headers=headers, data=json.dumps(data, **json_kwargs).encode("utf-8")
        )
        await raise_detailed_error(request_object)
        return await request_object.json()

    async def update(self, data, token: str =None, json_kwargs: dict = None) :
        request_ref = self.check_token(self.database_url, self.path, token)
        self.path = ""
        headers = self.build_headers(token)
        request_object = await self.requests.patch(
            request_ref, headers=headers, data=json.dumps(data, **json_kwargs).encode("utf-8")
        )
        await raise_detailed_error(request_object)
        return await request_object.json()

    async def remove(self, token: str = None):
        request_ref = self.check_token(self.database_url, self.path, token)
        self.path = ""
        headers = self.build_headers(token)
        request_object = await self.requests.delete(request_ref, headers=headers)
        await raise_detailed_error(request_object)
        return await request_object.json()

    def stream(self, stream_handler, token: str =None, stream_id=None) -> Stream:
        request_ref = self.build_request_url(token)
        return Stream(request_ref, stream_handler, self.build_headers, stream_id)

    @staticmethod
    def check_token(database_url: str, path: str, token: str) -> str:
        return f'{database_url}{path}.json?auth={token}' if token else f'{database_url}{path}.json'

    def generate_key(self) -> str:
        push_chars = '-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz'
        now = int(time.time() * 1000)
        duplicate_time = now == self.last_push_time
        self.last_push_time = now
        time_stamp_chars = [0] * 8

        for i in reversed(range(8)):
            time_stamp_chars[i] = push_chars[now % 64]
            now = int(math.floor(now / 64))

        new_id = "".join(time_stamp_chars)

        if not duplicate_time:
            for i in range(12):
                self.last_rand_chars.append(int(math.floor(uniform(0, 1) * 64)))
        else:
            for i in range(11):
                if self.last_rand_chars[i] == 63:
                    self.last_rand_chars[i] = 0
                self.last_rand_chars[i] += 1

        for i in range(12):
            new_id += push_chars[self.last_rand_chars[i]]
        return new_id

    @staticmethod
    def sort(origin, by_key) -> FirebaseResponse:
        firebases = origin.each()
        new_list = [firebase.item for firebase in firebases]

        data = sorted(dict(new_list).items(), key=lambda item: item[1][by_key])
        return FirebaseResponse(convert_to_firebase(data), origin.key())


class Storage: #ignore this for now
    """ Storage Service """
    def __init__(self, credentials: ServiceAccountCredentials, storage_bucket, requests: ClientSession):
        self.storage_bucket = f"https://firebasestorage.googleapis.com/v0/b/{storage_bucket}"

        self.credentials = credentials
        self.requests = requests
        self.path = ""

        if credentials:
            client = storage.Client(credentials=credentials, project=storage_bucket)
            self.bucket = client.get_bucket(storage_bucket)

    def child(self, *args) -> Storage:
        new_path = "/".join(args)
        if self.path:
            self.path += f"/{new_path}"
        else:
            new_path = new_path.removeprefix("/")
            self.path = new_path
        return self

    async def put(self, file, token: str =None):
        path = self.path
        self.path = None

        file_object = open(file, 'rb') if isinstance(file, str) else file
        request_ref = self.storage_bucket + "/o?name={0}".format(path)

        if token:
            headers = {"Authorization": f"Firebase {token}"}
            request_object = await self.requests.post(request_ref, headers=headers, data=file_object)
            await raise_detailed_error(request_object)
            return await request_object.json()
        
        elif self.credentials:
            blob = self.bucket.blob(path)
            if isinstance(file, str):
                return blob.upload_from_filename(filename=file)
            else:
                return blob.upload_from_file(file_obj=file)
        
        else:
            request_object = await self.requests.post(request_ref, data=file_object)
            await raise_detailed_error(request_object)
            return await request_object.json()

    def delete(self, name) -> None:
        self.bucket.delete_blob(name)

    async def download(self, filename, token: str =None):
        path = self.path
        url = self.get_url(token)
        self.path = None

        if path.startswith('/'):
            path = path[1:]

        if self.credentials:
            blob = self.bucket.get_blob(path)
            blob.download_to_filename(filename)
        
        else:
            r = await ClientSession().get(url, stream=True)
            if r.status >= 200 and r.status <= 499:
                raise HTTPExceptionError(
                    f'HTTP error encountered while downloading file. Status: {r.status}'
                )
            
            with open(filename, 'wb') as f:
                for chunk in r:
                    f.write(chunk)

    def get_url(self, token: str) -> str:
        path = self.path
        self.path = None

        if path.startswith('/'):
            path = path[1:]

        if token:
            return f"{self.storage_bucket}/o/{quote(path, safe='')}?alt=media&token={token}"

        return f"{self.storage_bucket}/o/{quote(path, safe='')}?alt=media"

    def list_files(self):
        return self.bucket.list_blobs()


async def raise_detailed_error(request_object: ClientResponse):
    try:
        request_object.raise_for_status()
    
    except ClientResponseError as e:
        raise ClientResponseError(e, await request_object.text) from e


def convert_to_firebase(items) -> list[FirebaseKeyValue]:
    return [FirebaseKeyValue(item) for item in items]


def convert_list_to_firebase(items) -> list[FirebaseKeyValue]:
    return [FirebaseKeyValue([items.index(item), item]) for item in items]


class FirebaseResponse:
    def __init__(self, firebases, query_key):
        self.firebases = firebases
        self.query_key = query_key

    def val(self):
        if not isinstance(self.firebases, list):
            return self.firebases
        firebase_list = []

        if isinstance(self.firebases[0].key(), int):
            firebase_list.extend(firebase.val() for firebase in self.firebases)
            return firebase_list

        firebase_list.extend((firebase.key(), firebase.val()) for firebase in self.firebases)

        return OrderedDict(firebase_list)
    
    def key(self) -> str:
        return self.query_key

    def each(self) -> Optional[list]:
        if isinstance(self.firebases, list):
            return self.firebases

class FirebaseKeyValue:
    def __init__(self, item: list):
        self.item = item

    def val(self):
        return self.item[1]

    def key(self):
        return self.item[0]


class KeepAuthSession(ClientSession):
    """
    A session that doesn't drop Authentication on redirects between domains.
    """

    def rebuild_auth(self, prepared_request, response):
        pass


class ClosableSSEClient(SSEClient):
    def __init__(self, *args, **kwargs):
        self.should_connect = True
        super(ClosableSSEClient, self).__init__(*args, **kwargs)

    def _connect(self):
        if self.should_connect:
            super(ClosableSSEClient, self)._connect()
        else:
            raise StopIteration()

    def close(self):
        self.should_connect = False
        self.retry = 0
        self.resp.raw._fp.fp.raw._sock.shutdown(socket.SHUT_RDWR)
        self.resp.raw._fp.fp.raw._sock.close()


class Stream:
    def __init__(self, url, stream_handler, build_headers, stream_id):
        self.build_headers = build_headers
        self.url = url
        self.stream_handler = stream_handler
        self.stream_id = stream_id
        self.sse = None
        self.thread = None
        self.start()

    @staticmethod
    def make_session():
        """
        Return a custom session object to be passed to the ClosableSSEClient.
        """
        return KeepAuthSession()

    def start(self) -> Stream:
        self.thread = threading.Thread(target=self.start_stream)
        self.thread.start()
        return self

    def start_stream(self):
        self.sse = ClosableSSEClient(self.url, session=self.make_session(), build_headers=self.build_headers)
        for msg in self.sse:
            if msg:
                msg_data = json.loads(msg.data)
                msg_data["event"] = msg.event
                if self.stream_id:
                    msg_data["stream_id"] = self.stream_id
                self.stream_handler(msg_data)

    async def close(self) -> Stream:
        while not self.sse and not hasattr(self.sse, 'resp'):
            await asyncio.sleep(0.001)
        self.sse.running = False
        self.sse.close()
        self.thread.join()
        
        return self
