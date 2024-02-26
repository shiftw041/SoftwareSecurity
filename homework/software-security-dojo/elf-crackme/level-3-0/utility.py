#!/opt/pwn.college/python

def main():
    file_path = "./elf-crackme-level3.0"
    
    try:
        with open(file_path, "r+b") as file:
            position = int(input("[+] Please enter the position to modify (in hexadecimal, e.g., 0x1000): "), 16)
            new_data = int(input("[+] Please enter the new byte data (in hexadecimal, e.g., 01): "), 16)
            
            file.seek(position)
            file.write(bytes([new_data]))
            
        print("[+] Modification completed!")
    except FileNotFoundError:
        print("[-] Unable to open the file")
    except Exception as e:
        print("[-] An error occurred:", e)

if __name__ == "__main__":
    print("###")
    print("### Welcome to ./elf-crackme-level3.0!")
    print("###")
    print("")
    print("We have provided a binary with a corrupted PLT table.")
    print("Please follow the PLT table jump order, use the script, and execute it to obtain the flag.")
    main()

