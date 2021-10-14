import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + str(query_char)
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}', 'check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = [line.split(':') for line in hashes.splitlines()]
    for h, count in hashes:
        if hash_to_check in h:
            return count
    return 0


def pwned_api_check(password):
    # check password if it exists in API response
    password = str(password)
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response.text, tail)


# def main(args):
#     for password in args:
#         count = pwned_api_check(password)
#         if count:
#             print(f'{password} was found {count} times... you should change your password!')
#         else:
#             print(f'{password} was NOT found! carry on.')
#     return 'done'

def main():
    password = input("Please enter your password: ")
    count = pwned_api_check(password)
    if count:
        print(f'{password} was found {count} times... you should change your password!')
    else:
       print(f'{password} was NOT found! carry on.')

    return 'done'


# def keep_going():
#     flag = input("Enter x to exit: ")
#
#     if flag == "x" or flag == "X":
#         return
#
#     keep_going()


def exit_func():
    print("Press ctrl + c to exit: ")
    while True:
        pass


if __name__ == '__main__':
    # main(sys.argv[1:])
    main()
    exit_func()
