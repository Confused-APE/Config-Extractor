import re
import argparse
import os

decrypt_dict = ''

def load_decrypt_dict(dict_file_path):
    global decrypt_dict
    if not os.path.isfile(dict_file_path):
        raise FileNotFoundError(f"Dict file not found: {dict_file_path}")
    
    with open(dict_file_path, 'r', encoding='utf-8') as file:
        decrypt_dict = file.read().strip()

def decrypt_index(index):
    if index < 0 or index >= len(decrypt_dict):
        raise IndexError(f"Index out of bounds: {index}")
    return decrypt_dict[index]

def decrypt_line(line):
    indices = re.findall(r'\$a\[0x([0-9a-fA-F]+)\]', line)
    decrypted_chars = [decrypt_index(int(index, 16)) for index in indices]
    decrypted_line = re.sub(
        r'\$a\[0x[0-9a-fA-F]+\]', 
        lambda _: decrypted_chars.pop(0), 
        line
    )
    return decrypted_line.replace(' & ', '')

def decrypt_script(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Script file not found: {file_path}")

    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    
    return ''.join(decrypt_line(line) for line in lines)

def main():
    parser = argparse.ArgumentParser(description='Decrypt obfuscated Autoit .au3 script.')
    parser.add_argument('-d', '--dict', type=str, required=True, help='Path to the decryption dictionary')
    parser.add_argument('-i', '--input', type=str, required=True, help='Path to the obfuscated script')
    parser.add_argument('-o', '--output', type=str, required=True, help='Path to save decrypted script')

    args = parser.parse_args()
    dict_file_path = args.dict
    input_file_path = args.input
    output_file_path = args.output

    try:
        load_decrypt_dict(dict_file_path)
        decrypted_script = decrypt_script(input_file_path)

        with open(output_file_path, 'w', encoding='utf-8') as file:
            file.write(decrypted_script)
        
        print('[+] Decryption successful.')
        print(f'[+] Output written to: {output_file_path}\n')

    except Exception as e:
        print(f'[!] Error: {e}')

if __name__ == "__main__":
    main()