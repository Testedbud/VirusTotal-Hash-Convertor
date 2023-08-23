import requests
import time

API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'
REQUESTS_PER_MINUTE = 4
WAIT_TIME = 60 / REQUESTS_PER_MINUTE

def get_hash_info(hash_value):
    url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
    headers = {'x-apikey': API_KEY}

    response = requests.get(url, headers=headers)
    data = response.json()

    return data

def main():
    input_file = input("Enter the path to the text file containing hash values: ")
    output_file = input("Enter the path to the output text file: ")

    try:
        with open(input_file, 'r') as file:
            hash_values = file.readlines()

        with open(output_file, 'w') as output:
            for hash_value in hash_values:
                hash_value = hash_value.strip()
                
                try:
                    hash_info = get_hash_info(hash_value)

                    if 'data' in hash_info:
                        output.write(f"Hash Information for {hash_value}:\n")
                        output.write(f"MD5: {hash_info['data']['attributes']['md5']}\n")
                        output.write(f"SHA-1: {hash_info['data']['attributes']['sha1']}\n")
                        output.write(f"SHA-256: {hash_info['data']['attributes']['sha256']}\n\n")
                    else:
                        output.write(f"Hash not found in VirusTotal database for {hash_value}\n\n")

                except requests.exceptions.RequestException as e:
                    output.write(f"An error occurred for {hash_value}: {e}\n\n")
                
                except KeyError:
                    output.write(f"Hash information not available for {hash_value}\n\n")
                
                except Exception as e:
                    output.write(f"An unexpected error occurred for {hash_value}: {e}\n\n")

                time.sleep(WAIT_TIME)

        print(f"Output saved to {output_file}")

    except FileNotFoundError:
        print("File not found.")
    
    except Exception as e:
        print("An unexpected error occurred:", e)

if __name__ == '__main__':
    main()
