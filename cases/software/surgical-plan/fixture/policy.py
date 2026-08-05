MAX_RETRIES = 3


def may_retry(attempt):
    return 0 <= attempt < MAX_RETRIES
