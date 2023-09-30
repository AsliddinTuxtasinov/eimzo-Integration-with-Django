import requests
from rest_framework import views, permissions, exceptions, response, status

from rest_framework.request import Request


class EimzoServiceApi:
    def __init__(self):
        # Define the URLs for authentication, PKCS#7 verification, and joining.
        self.VERIFY_URL = "http://e-imzo-server:8080/backend/pkcs7/verify"

        self.JOIN_URL = "http://e-imzo-server:8080/frontend/pkcs7/join"
        self.TIME_STAMP_URL = "http://e-imzo-server:8080/frontend/timestamp/pkcs7"

        self.CHALLENGE_URL = "http://e-imzo-server:8080/frontend/challenge"

    @staticmethod
    def get_user_ip(request: Request) -> str:
        """
        Get the user's IP address from the request.
        Args:
            request (Request): The Django Rest Framework request object.
        Returns:
            str: The user's IP address.
        """
        x_real_ip = request.META.get("HTTP_X_REAL_IP")
        remote_addr = request.META.get("REMOTE_ADDR")

        # Check if X-Real-IP header is present and not empty
        if x_real_ip:
            return x_real_ip
        elif remote_addr:
            return remote_addr
        else:
            return "Unknown"  # Provide a default value or handle the case as needed

    def get_headers(self, request: Request) -> dict:
        """
        Get headers for HTTP requests, including the Host and X-Real-IP headers.
        Args:
            request (requests): The HTTP request object.
        Returns:
            dict: A dictionary containing headers.
        """
        return {
            "Host": request.environ.get("HTTP_HOST"),
            "X-Real-IP": self.get_user_ip(request),
        }

    def eimzo_challenge(self, request: Request):
        url = self.CHALLENGE_URL
        headers = self.get_headers(request)

        res = requests.get(url, headers=headers)
        return res.status_code, res

    def timestamp_pkcs7(self, pkcs7: str, request: Request) -> tuple:
        """
            Attach a timestamp token to a PKCS#7 document.
            Args:
                pkcs7 (str): The PKCS#7 document as a string.
                request (Request): The HTTP request object used to send the request.
            Returns:
                tuple: A tuple containing the HTTP status code and the response object.
            This method is used to attach a timestamp token to a PKCS#7 document. It sends a POST
            request to the timestamp service with the PKCS#7 data and returns the HTTP status code
            and the response object.

            This method is needed to attach a timestamp token to a PKCS#7 document.
        """
        time_stamp_url = f"{self.TIME_STAMP_URL}"
        headers = self.get_headers(request)

        res = requests.post(time_stamp_url, data=pkcs7, headers=headers)
        return res.status_code, res

    def eimzo_verify(self, pkcs7wtst: str, request: Request) -> tuple:
        """
        Verify a PKCS#7 signature using the EIMZO service.
        Args:
            pkcs7wtst (str): The PKCS#7 data to be verified.
            request (requests): The HTTP request object.
        Returns:
            tuple: A tuple containing a boolean indicating status_code and the verification result.
        """
        verify_url = f"{self.VERIFY_URL}/attached"
        headers = self.get_headers(request)

        res = requests.post(verify_url, data=pkcs7wtst, headers=headers)
        return res.status_code, res

    def pkcs7_join(self, pkcs7_data_1: str, pkcs7_data_2: str, request: Request) -> tuple:
        """
        Join two PKCS#7 data sets using the EIMZO service.
        Args:
            pkcs7_data_1 (str): The first PKCS#7 data set.
            pkcs7_data_2 (str): The second PKCS#7 data set.
            request (requests): The HTTP request object.
        Returns:
            tuple: A tuple containing a boolean indicating status_code and the joining result.
        """
        data = f"{pkcs7_data_1}|{pkcs7_data_2}"
        join_url = f"{self.JOIN_URL}"
        headers = self.get_headers(request)

        res = requests.post(join_url, headers=headers, data=data)
        return res.status_code, res


eimzo_service_api = EimzoServiceApi()


# Define a custom API view class called SavePkcsView
class SavePkcsView(views.APIView):
    # Specify permission classes for this view (requires authentication)
    permission_classes = (permissions.IsAuthenticated,)

    # Method for timestamping a PKCS7 signature
    def timestamp_pkcs7(self, pkcs7):
        # Call the eimzo_service_api.timestamp_pkcs7 function with the given PKCS7 data
        status_code, resp = eimzo_service_api.timestamp_pkcs7(pkcs7=pkcs7, request=self.request)
        # Check if the response status code is not 200 (indicating an error)
        if status_code != 200:
            # Raise a validation error with a JSON error response
            raise exceptions.ValidationError(detail={
                "success": False,
                "err_msg": resp.text
            }, code=status_code)
        # Parse the JSON response and extract the PKCS7 in base64 format
        data_json = resp.json()
        pkcs7b64 = data_json.get("pkcs7b64", False)
        # If PKCS7 is not present in the response, return a 406 Not Acceptable response
        if pkcs7b64 is False:
            return response.Response(data={
                "success": False,
                "err_msg": data_json
            }, status=status.HTTP_406_NOT_ACCEPTABLE)
        # Return the PKCS7 in base64 format
        return pkcs7b64

    # Method for verifying a PKCS7 signature
    def eimzo_verify(self, pkcs7b64):
        # Call the eimzo_service_api.eimzo_verify function with the given PKCS7 data
        status_code, resp = eimzo_service_api.eimzo_verify(pkcs7wtst=pkcs7b64, request=self.request)

        # Check if the response status code is not 200 (indicating an error)
        if status_code != 200:
            # Raise a validation error with a JSON error response
            raise exceptions.ValidationError(detail={
                "success": False,
                "err_msg": resp.text
            }, code=status_code)

    # Method for joining two PKCS7 signatures
    def pkcs7_join(self, pkcs7_data_1, pkcs7_data_2):
        # Call the eimzo_service_api.pkcs7_join function with the given PKCS7 data
        status_code, resp = eimzo_service_api.pkcs7_join(
            pkcs7_data_1=pkcs7_data_1,
            pkcs7_data_2=pkcs7_data_2,
            request=self.request
        )
        # Check if the response status code is not 200 (indicating an error)
        if status_code != 200:
            # Raise a validation error with a JSON error response
            raise exceptions.ValidationError(detail={
                "success": False,
                "err_msg": resp.text
            }, code=status_code)
        # Parse the JSON response and extract the joined PKCS7 in base64 format
        join_resp = resp.json()
        return join_resp.get("pkcs7b64")

    # Method to handle incoming POST requests (This method can be implemented as needed)
    def post(self, request):
        # This method can be implemented with the specific logic needed for your use case
        pass


# Define a custom API view class called PkcsVerify
class PkcsVerify(views.APIView):

    # Define a method for verifying a PKCS7 signature
    def eimzo_verify(self, pkcs7b64):
        # Call the eimzo_service_api.eimzo_verify function with the given PKCS7 data
        status_code, resp = eimzo_service_api.eimzo_verify(pkcs7wtst=pkcs7b64, request=self.request)
        # Check if the response status code is not 200 (indicating an error)
        if status_code != 200:
            # Raise a validation error with a JSON error response
            raise exceptions.ValidationError(detail={
                "success": False,
                "err_msg": resp.text
            }, code=status_code)
        # Return the JSON response if the verification was successful
        return resp.json()

    # Define a POST method to handle incoming requests
    def post(self, request):
        # Get the PKCS7 data from the request's data
        pkcs7b64 = self.request.data.get("pkcs7b64")
        if pkcs7b64 is None:
            raise exceptions.ValidationError(detail={
                "success": False,
                "err_msg": "pkcs7b64 field is required"
            })
        # Call the eimzo_verify method to verify the PKCS7 signature
        json_resp = self.eimzo_verify(pkcs7b64=pkcs7b64)
        # Return a JSON response with the verification result
        return response.Response(data=json_resp)
