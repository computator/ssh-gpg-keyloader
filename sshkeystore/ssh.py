import subprocess


class AgentError(Exception):
    pass


class Agent:
    @staticmethod
    def addkey(key):
        try:
            output = subprocess.run(
                ['ssh-add', '-k', '-q', '-'],
                check=True,
                input=key,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            ).stdout
            if output != b'Identity added: (stdin) ((stdin))\n':
                raise AgentError(f"Unexpected output: {output.decode().rstrip()}")
        except subprocess.CalledProcessError as e:
            raise AgentError(f"Add error: {e.stdout.decode().rstrip()}") from e
