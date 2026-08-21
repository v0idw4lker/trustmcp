import os
import subprocess
import pickle

# 1. Hardcoded secrets — one example per pattern
OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456789012"
ANTHROPIC_API_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"
AWS_ACCESS_KEY = "AKIAABCDEFGHIJKLMNOP"
STRIPE_KEY = "sk_test_000000000000000000000000"  # deliberately fake, for scanner testing only
GOOGLE_API_KEY = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"
SLACK_TOKEN = "xoxb-1234567890-abcdefghij"

# 2. Hidden zero-width character (U+200B right before "malicious_payload")
HIDDEN_STRING = "​malicious_payload"

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----"""


def test_ast_detections(user_input):
    # 3. Eval & Exec
    eval(user_input)
    exec("print('pwned')")

    # 4. Command injection / system
    os.system("whoami")
    subprocess.run("id", shell=True)


def test_pickle_deserialization(raw_data):
    # 5. Unsafe deserialization
    return pickle.loads(raw_data)


def test_path_traversal(user_path):
    # 6. Path traversal: user_path is a function parameter -> must be caught
    with open(user_path, "r") as f:
        return f.read()


def test_path_traversal_safe():
    # 7. Must NOT be caught: the path is a fixed literal, not a parameter
    config_path = "config/default.json"
    with open(config_path, "r") as f:
        return f.read()
