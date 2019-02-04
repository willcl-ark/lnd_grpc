import functools
import grpc


def handle_error(function):
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
            print("rpcError: %s" % e.details())
            # status_code = e.code()
            # print(status_code.name)
            # print(status_code.value)
        except TypeError as t:
            print('TypeError: %s' % t)
        except KeyError as k:
            print('KeyError: %s' % k)

    return wrapper
