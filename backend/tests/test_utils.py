from core.utils import sanitize_filename, hash_content

def test_filename_sanitization():
    unsafe = "../../../etc/passwd"
    safe = sanitize_filename(unsafe)
    assert ".." not in safe
    assert "/" not in safe
    assert safe == "passwd"

def test_hashing():
    content = "test_data"
    h1 = hash_content(content)
    h2 = hash_content(content)
    assert h1 == h2
    assert len(h1) == 64 # SHA256 length
