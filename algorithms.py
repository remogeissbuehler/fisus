import base64
from abc import abstractmethod
from typing import Protocol
import warnings
import yaml 
import hashlib
import shutil

gpg_err = None
try:
    import gpg
except ImportError as e:
    gpg_err = e

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

    def verify_file(self, filename: str, exception_on_invalid=True) -> bool:
        # with open(TEMPLATE) as t:
        #     template = t.read()

        with open(filename) as f:
            content = f.read()
        try:
            header, content = yaml.safe_load_all(content)
        except ValueError :
            if not exception_on_invalid:
                return False
            raise ValueError("signature file is invalid")
        except yaml.scanner.ScannerError:
            if not exception_on_invalid:
                return False
            raise ValueError("signature file is invalid")

        digest = header.get("digest", None)
        if digest is None:
            return False

        return self.verify(content, digest)


class GPGInfrastructure(SigningInfrastructure):

    @staticmethod
    def _ensure_gpg():
        if gpg_err is not None:
            msg =  "You need the gpg bindings for python to use this Infrastructure."
            msg += "Try `sudo apt install python3-gpg` or check the README for more info."

            raise ImportError(msg) from gpg_err

    def __new__(cls) -> 'Self':
        cls._ensure_gpg()
        return super().__new__(cls)

    def __init__(self) -> None:
        self.algorithm_info = "gpg"
        self.ctx = gpg.Context()

        super().__init__()

    def _ensure_signing_key(self):
        keys = self.ctx.keylist(secret=True)

        def _valid(key):
            is_valid = key.can_sign
            is_valid = is_valid and not key.disabled
            is_valid = is_valid and not key.expired
            is_valid = is_valid and not key.invalid
            is_valid = is_valid and not key.revoked

            return is_valid

        keys = (k for k in keys if _valid(k))

        try:
            next(keys)
        except StopIteration:
            raise ValueError("need at least one valid private signing key")

    def _sign(self, data: bytes) -> bytes:
        self._ensure_signing_key()
        digest, result = self.ctx.sign(data, mode=gpg.constants.SIG_MODE_DETACH)
        
        if len(result.invalid_signers) > 0:
            raise ValueError()

        return digest

    def _verify(self, data: bytes, digest: bytes) -> bool:
        try:
            result = self.ctx.verify(data, signature=digest)
            return True
        except gpg.errors.VerificationError:
            return False
    


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
    infra = GPGInfrastructure()
    infra.sign_file("examples/helloworld.py")
    shutil.copyfile("examples/helloworld.py.sgn", "examples/tampered.py.sgn")

    with open("examples/tampered.py.sgn") as f:
        c = f.read()
    with open("examples/tampered.py.sgn", 'w') as f:
        f.write(c.replace("hello", "ciao"))
    with open("examples/tampered2.py.sgn", 'w') as f:
        f.write(c.split("--- ")[-1])
    with open("examples/tampered3.py.sgn", 'w') as f:
        f.write(c)
        f.write("--- \n")
        f.write("malish: true")
    with open("examples/invalid.sgn", 'w') as f:
        f.write(">> This is not a yaml file <<<\n")
        f.write(">>> really not              <<")
    

    print(infra.verify_file("examples/helloworld.py.sgn"))
    for f in ["tampered.py", "tampered2.py", "tampered3.py", "invalid"]:
        try:
            print(infra.verify_file(f"examples/{f}.sgn", exception_on_invalid=False))
        except ValueError:
            print("False: ValueError")
