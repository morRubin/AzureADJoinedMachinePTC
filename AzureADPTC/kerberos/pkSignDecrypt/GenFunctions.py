import functools
import windows.generated_def as gdef
import ctypes
from windows.winproxy.apiproxy import ExportNotFound
from windows.winproxy.error import WinproxyError
from windows.generated_def.winstructs import *

class NeededParameterType(object):
    _inst = None

    def __new__(cls):
        if cls._inst is None:
            cls._inst = super(NeededParameterType, cls).__new__(cls)
        return cls._inst

    def __repr__(self):
        return "NeededParameter"


no_error_check = None
NeededParameter = NeededParameterType()
sentinel = object()


def fail_on_zero(func_name, result, func, args):
    """raise WinproxyError if result is 0"""
    if not result:
        raise WinproxyError(func_name)
    return args


class ApiProxy(object):
    APIDLL = None
    """Create a python wrapper around a kernel32 function"""

    def __init__(self, func_name=None, error_check=sentinel, deffunc_module=None):
        self.deffunc_module = deffunc_module if deffunc_module is not None else gdef.winfuncs
        self.func_name = func_name
        if error_check is sentinel:
            error_check = self.default_error_check

        self.error_check = error_check
        self._cprototyped = None

    def __call__(self, python_proxy):
        # Use the name of the sub-function if None was given
        if self.func_name is None:
            self.func_name = python_proxy.__name__

        errchk = None
        if self.error_check is not None:
            errchk = functools.wraps(self.error_check)(functools.partial(self.error_check, self.func_name))

        prototype = ctypes.WINFUNCTYPE(BOOL, DWORD, PCERT_PUBLIC_KEY_INFO, DWORD, PVOID, POINTER(PVOID))  # getattr(self.deffunc_module, self.func_name + "Prototype")
        params = ((1, 'dwCertEncodingType'), (1, 'pInfo'), (1, 'dwFlags'), (1, 'pvAuxInfo'), (1, 'phKey'))  # getattr(self.deffunc_module, self.func_name + "Params")
        python_proxy.prototype = prototype
        python_proxy.params = params
        python_proxy.errcheck = errchk
        python_proxy.target_dll = self.APIDLL
        python_proxy.target_func = self.func_name
        # Give access to the 'ApiProxy' object from the function
        python_proxy.proxy = self
        params_name = [param[1] for param in params]
        if (self.error_check.__doc__):
            doc = python_proxy.__doc__
            doc = doc if doc else ""
            python_proxy.__doc__ = doc + "\nErrcheck:\n   " + self.error_check.__doc__

        def generate_ctypes_function():
            try:
                api_dll = ctypes.windll[self.APIDLL]
            except WindowsError as e:
                if e.winerror == gdef.ERROR_BAD_EXE_FORMAT:
                    e.strerror = e.strerror.replace("%1", "<{0}>".format(self.APIDLL))
                raise
            try:
                c_prototyped = prototype((self.func_name, api_dll), params)
            except (AttributeError, WindowsError):
                raise ExportNotFound(self.func_name, self.APIDLL)
            if errchk is not None:
                c_prototyped.errcheck = errchk
            self._cprototyped = c_prototyped

        def perform_call(*args):
            if self._cprototyped is None:
                generate_ctypes_function()
            try:
                return self._cprototyped(*args)
            except ctypes.ArgumentError as e:
                # We just add a conversion ctypes argument fail
                # We can do some heavy computation if needed
                # Not a case that normally happen

                # "argument 2: <type 'exceptions.TypeError'>: wrong type"
                # Thx ctypes..
                argnbstr, ecx, reason = e.message.split(":")
                if not argnbstr.startswith("argument "):
                    raise  # Don't knnow if it can happen
                argnb = int(argnbstr[len("argument "):])
                badarg = args[argnb - 1]
                if badarg is NeededParameter:
                    badargname = params_name[argnb - 1]
                    raise TypeError("{0}: Missing Mandatory parameter <{1}>".format(self.func_name, badargname))
                # Not NeededParameter: the caller need to fix the used param :)
                # raise the real ctypes error
                raise

        setattr(python_proxy, "ctypes_function", perform_call)
        setattr(python_proxy, "force_resolution", generate_ctypes_function)
        return python_proxy


class Crypt32Proxy(ApiProxy):
    APIDLL = "crypt32"
    default_error_check = staticmethod(fail_on_zero)


@Crypt32Proxy()
def CryptImportPublicKeyInfo(hCryptProv, dwCertEncodingType, pInfo, phKey):
    return CryptImportPublicKeyInfo.ctypes_function(hCryptProv, dwCertEncodingType, pInfo, phKey)


@Crypt32Proxy()
def CryptImportPublicKeyInfoEx2(dwCertEncodingType, pInfo, dwFlags, pvAuxInfo, phKey):
    return CryptImportPublicKeyInfoEx2.ctypes_function(dwCertEncodingType, pInfo, dwFlags, pvAuxInfo, phKey)
