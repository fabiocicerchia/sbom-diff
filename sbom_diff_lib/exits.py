"""The exit-code table, and the error that carries one of its codes."""

# Exit codes, following sysexits(3). 0 and 1 are the documented gate contract
# and keep their meanings; the rest separate "this input is unusable" from
# "a gate tripped", which both used to surface as an uncaught traceback.
EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_DATAERR = 65  # EX_DATAERR: not JSON, or JSON that is not an SBOM
EXIT_NOINPUT = 66  # EX_NOINPUT: the file is not there
EXIT_IOERR = 74  # EX_IOERR: it is there but cannot be read
EXIT_NOPERM = 77  # EX_NOPERM: permission denied


class SbomError(Exception):
    """An input the tool cannot use, carrying the exit code that reports it."""

    def __init__(self, message, code):
        super().__init__(message)
        self.code = code
