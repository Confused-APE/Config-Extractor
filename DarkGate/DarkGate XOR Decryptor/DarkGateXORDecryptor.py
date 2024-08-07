import argparse
import os

def xor_decrypt(data, key):
    decoded_bytes = []
    key_length = len(key)
    index = 0

    for byte in data:
        decoded_byte = (byte ^ ord(key[index])) & 0xFF
        decoded_bytes.append(decoded_byte)
        index = (index + ord(key[index])) % key_length
        if index == 0:
            index = key_length - 1

    return bytes(decoded_bytes)

def generate_xor_key(marker):
    length = len(marker)
    transformed_key = ''

    for char in marker:
        transformed_char = chr(ord(char) ^ length)
        transformed_key += transformed_char
        length -= 1

    return transformed_key

def locate_payload(file_content, marker):
    marker_length = len(marker)
    start_position = file_content.find(marker.encode('utf-8'))

    if start_position == -1:
        raise ValueError("Start marker not found in the file.")

    start_position += marker_length

    return file_content[start_position:]

def main():
    parser = argparse.ArgumentParser(description='Decrypt DarkGate payload from Autoit .a3x loader enclosed by markers in a file.')
    parser.add_argument('-m', '--marker', type=str, required=True, help='Marker to locate the payload in the file')
    parser.add_argument('-i', '--input', type=str, required=True, help='Path to the file containing the payload enclosed by markers')
    parser.add_argument('-o', '--output', type=str, required=True, help='Path to save the decrypted content')

    args = parser.parse_args()
    marker = args.marker
    input_path = args.input
    output_path = args.output

    decryption_key = generate_xor_key(marker)

    if not os.path.isfile(input_path):
        print(f'[!] Error: Input file not found at {input_path}')
        return

    with open(input_path, 'rb') as file:
        file_content = file.read()

    try:
        payload = locate_payload(file_content, marker)
    except ValueError as error:
        print(f'[!] Error: {error}')
        return

    decrypted_content = xor_decrypt(payload, decryption_key)

    with open(output_path, 'wb') as file:
        file.write(decrypted_content)

    print('[+] Decryption successful.')
    print(f'[+] Output written to: {output_path}\n')

if __name__ == "__main__":
    main()