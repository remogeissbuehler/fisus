# fisus
New Python side-project that allows for codesigning in python. It will provide both utils to sign code, as well as to verify it and to restrict imports to signed modules.


## Dependencies
If you want to use it with gpg, this project requires gpg as well as GPGME to provide bindings to python. It appears that on CentOS, they are installed by default.
To make sure that you have it, run:

```
python3 -c "import gpg; print(gpg.version)
```

## Ubuntu / Debian
```bash
sudo apt install gpg python3-pgp
```

## macOS
```zsh
brew install gpg gpgme
```

## venv
If you use a virtual environment, you need to create it with
```bash
python3 -m venv --system-site-packages
```
to include the python bindings for GPG in the venv.