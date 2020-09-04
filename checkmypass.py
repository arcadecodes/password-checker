import requests
import hashlib
import sys


def request_api_data(query_char):
    """ requests data from an api and outputs a response"""
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {response.status_code}, check the API and try again')
    return response


def get_password_leaks_count(hashes, hash_to_check):
    """ Read the response and because it's from an api
    can read the text and loop through the hashes """
    # line comprensions to split the hashes by the colon
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    """check password if it exists in api response
    Have to run our password through the sha1 algorithm
    """
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    # print(first5_char, tail)  # make sure everything is working.
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f'{password} was found {count} times... you should probably change your password')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))  # makkes sure the system call exists.
