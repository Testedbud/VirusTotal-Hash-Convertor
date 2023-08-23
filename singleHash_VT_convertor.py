import requests
import time

API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'

# Define the rate limits
REQUESTS_PER_MINUTE = 4
WAIT_TIME = 60 / REQUESTS_PER_MINUTE

def get_hash_info(hash_value):
    url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
    headers = {'x-apikey': API_KEY}

    response = requests.get(url, headers=headers)
    data = response.json()

    return data

def main():
    hash_value = input("Enter the hash value: ")

    try:
        hash_info = get_hash_info(hash_value)

        if 'data' in hash_info:
            print("Hash Information:")
            print(f"MD5: {hash_info['data']['attributes']['md5']}")
            print(f"SHA-1: {hash_info['data']['attributes']['sha1']}")
            print(f"SHA-256: {hash_info['data']['attributes']['sha256']}")
        else:
            print("Hash not found in VirusTotal database.")

    except requests.exceptions.RequestException as e:
        print("An error occurred:", e)
    
    except KeyError:
        print("Hash information not available.")
    
    except Exception as e:
        print("An unexpected error occurred:", e)

if __name__ == '__main__':
    main()
