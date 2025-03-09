import random
import bitcoin
import os

# Define the range for the private keys
start_int = int("f0fffffffffffffff", 16)  # Starting value in decimal
end_int = int("fffffffffffffffff", 16)    # Ending value in decimal

# Define the output files
output_file = "Addresses 4.txt"
found_file = "foundit.txt"
address_file = "address.txt"
previous_addresses_file = "previous_addresses.txt"

# Load previously generated keys
if os.path.exists(output_file):
    with open(output_file, "r") as f:
        existing_keys = {line.split(",")[0].split(": ")[1] for line in f.readlines()}
else:
    existing_keys = set()

# Load previously generated addresses
if os.path.exists(previous_addresses_file):
    with open(previous_addresses_file, "r") as f:
        previous_addresses = {line.strip() for line in f.readlines()}
else:
    previous_addresses = set()

# Load addresses from address.txt
if os.path.exists(address_file):
    with open(address_file, "r") as f:
        existing_addresses = {line.strip() for line in f.readlines()}
else:
    existing_addresses = set()

# Number of random keys to generate
num_keys_to_generate = 1000000  # Change this to generate more or fewer keys

# Flag to check if any matches were found
matches_found = False

# Set to keep track of generated addresses to avoid duplicates
generated_addresses = set()

# Function to check if a private key has consecutive repeating characters
def has_consecutive_repeating_characters(hex_key):
    for i in range(len(hex_key) - 1):
        if hex_key[i] == hex_key[i + 1]:  # Check for consecutive repeating characters
            return True
    return False

# Generate random keys and save them to the file
with open(output_file, "a") as f:
    for _ in range(num_keys_to_generate):
        # Generate a random integer within the specified range
        random_private_key_int = random.randint(start_int, end_int)
        
        # Convert the integer to a hexadecimal string
        random_private_key_hex = hex(random_private_key_int)[2:].zfill(64)  # Ensure it's 64 characters long
        
        # Check if the key has already been generated or has consecutive repeating characters
        if random_private_key_hex in existing_keys or has_consecutive_repeating_characters(random_private_key_hex):
            continue
        
        # Generate the public key from the private key
        public_key = bitcoin.privkey_to_pubkey(random_private_key_hex)

        # Generate the compressed public key
        if public_key[-1] in ['0', '2', '4', '6', '8', 'A', 'C', 'E']:  # Check if y-coordinate is even
            compressed_public_key = '02' + public_key[2:66]  # Prefix with 0x02 and take the x-coordinate
        else:
            compressed_public_key = '03' + public_key[2:66]  # Prefix with 0x03 and take the x-coordinate

        # Generate the Bitcoin address from the compressed public key
        address = bitcoin.pubkey_to_address(compressed_public_key)

        # Check if the generated address is unique and not in previous_addresses
        if address in previous_addresses or address in generated_addresses:
            continue  # Skip if the address has been generated before

        # Add the address to the set of generated addresses
        generated_addresses.add(address)

        # Write the private key and address to the file
        f.write(f"Private Key (Hex): {random_private_key_hex}, Address: {address}\n")

        # Check if the generated address matches any in address.txt
        if address in existing_addresses:
            matches_found = True  # Set the flag to True if a match is found
            # Write to foundit.txt only if a match is found
            with open(found_file, "a") as found_f:
                found_f.write(f"Matching Address: {address} for Private Key: {random_private_key_hex}\n")

# Update previous_addresses.txt with the newly generated addresses
with open(previous_addresses_file, "a") as prev_f:
    for address in generated_addresses:
        prev_f.write(f"{address}\n")

# Print completion message
if matches_found:
    print(f"Generated {num_keys_to_generate} random private keys and their corresponding addresses, saved to {output_file}. Matches found and saved to {found_file}.")
else:
    print(f"Generated {num_keys_to_generate} random private keys and their corresponding addresses, saved to {output_file}. No matches found.")