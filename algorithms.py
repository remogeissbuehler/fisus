import base64
from abc import abstractmethod
from typing import Protocol
import warnings
import yaml 
import hashlib
from parse import parse

TEMPLATE = "config/file_template.txt"

def str_presenter(dumper, data):
  if len(data.splitlines()) > 1:  # check for multiline string
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
  return dumper.represent_scalar('tag:yaml.org,2002:str', data)

yaml.representer.SafeRepresenter.add_representer(str, str_presenter)


class SigningInfrastructure(Protocol):
    algorithm_info: str | dict
    
    @property
    def metadata(self):
        return {
            'infrastructure': {
                'name': self.__class__.__name__,
                'algorithm': self.algorithm_info
            }
        }

    @abstractmethod
    def _sign(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def _verify(self, data: bytes, digest: bytes) -> bool:
        pass

    def sign(self, data: str) -> str:
        data = bytes(data, encoding="utf-8")
        digest = self._sign(data)

        return base64.encodebytes(digest).decode('utf-8')

    def verify(self, data: str, digest: str) -> bool:
        data = bytes(data, encoding='utf-8')
        digest = bytes(digest, encoding='utf-8')
        digest = base64.decodebytes(digest)

        return self._verify(data, digest)

    def sign_file(self, filename: str) -> str:
        with open(filename, "r") as f:
            content = f.read()
            digest = self.sign(content)

        with open(TEMPLATE) as f:
            template = f.read()

        with open(filename + ".sgn", "w") as f:
            header = {
                'metadata': self.metadata,
                'digest': digest.strip()
            }
            # header = yaml.dump(header)
            # signed_content = template.format(header=header, content=content)
            signed_content = yaml.safe_dump_all([header, content])
            f.write(signed_content)
            # print(header)
            # print(yaml.dump({'body': content}, default_style='|'))

    def verify_file(self, filename: str) -> bool:
        # with open(TEMPLATE) as t:
        #     template = t.read()

        with open(filename) as f:
            content = f.read()

        header, content = yaml.safe_load_all(content)

        digest = header.get("digest", None)
        if digest is None:
            return False

        return self.verify(content, digest)


class TestingInfrastructure(SigningInfrastructure):
    def __init__(self) -> None:
        warnings.warn("this class is only for testing!!")
        self.algorithm_info = 'sha256'
        super().__init__()

    def _sign(self, data: bytes) -> bytes:
        hash = hashlib.sha256()
        hash.update(data)

        return hash.digest()

    def _verify(self, data: bytes, digest: bytes) -> bool:
        hash = hashlib.sha256()
        hash.update(data)

        return hash.digest() == digest


if __name__ == "__main__":
    infra = TestingInfrastructure()
    infra.sign_file("examples/helloworld.py")

    print(infra.verify_file("examples/helloworld.py.sgn"))
    print(infra.verify_file("examples/tampered.py.sgn"))
