import requests
import hashlib


def request_api_data(query_char):
    query_char_s = str(query_char)
    url = 'http://api.pwnedpasswords.com/range/' + query_char_s
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}')
    return res


def get_pass_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_checker(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    print(response)
    return get_pass_leaks_count(response, tail)


def main(password):
    with open('password_to_check.txt', 'a') as result:
        count = pwned_api_checker(password)
        if count:
            result.write(f' was found {count} times... you should change it')
        else:
            result.write(' was NOT found. Carry on!')
        return 'done'


with open('password_to_check.txt') as password_text:
    password = password_text.read()

main(password)