import functools
import grpc


def grpc_error(function):
    """
        A decorator that wraps the passed in function and prints grpc error
        exceptions should one occur
        """

    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except grpc.RpcError as e:
            # lets print the gRPC error message
            print(e.details())
            status_code = e.code()
            print(status_code.name)
            print(status_code.value)

    return wrapper
