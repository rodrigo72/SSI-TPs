from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

from utils import write_bytes_to_file


def main():
    """to save time, the parameters are generated one time and saved to a file
    (instead of being generated every time a client starts)"""
    params = dh.generate_parameters(generator=2, key_size=2048)
    params_bytes = params.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )
    write_bytes_to_file('params.pem', params_bytes)


if __name__ == '__main__':
    main()
