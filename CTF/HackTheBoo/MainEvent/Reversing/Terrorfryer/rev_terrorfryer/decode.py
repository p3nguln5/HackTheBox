def decode_to_htb_format(scrambled):
    """
    Decode scrambled message to HTB{} format
    """
    # Initialize result array
    result = ['_'] * len(scrambled)
    
    # Track position mapping
    positions = {}
    
    # Process each character and its number
    for i in range(len(scrambled)-1):
        if scrambled[i].isdigit():
            pos = int(scrambled[i])
            if pos < len(result):
                next_char = scrambled[i+1]
                positions[pos] = next_char
    
    # Fill in known positions
    for pos, char in positions.items():
        if pos < len(result):
            result[pos] = char
    
    # Look for HTB characters
    htb_chars = [c for c in scrambled if c.upper() in 'HTB']
    print("Found HTB characters:", htb_chars)
    
    # Find { and } positions
    brace_positions = [(i, c) for i, c in enumerate(scrambled) if c in '{}']
    print("Found braces at:", brace_positions)
    
    # Reconstruct with HTB{} format
    # First, let's find all valid characters we've decoded
    valid_chars = [c for c in result if c != '_']
    print("Valid decoded characters:", valid_chars)
    
    # Now reconstruct the flag format
    flag = ['H', 'T', 'B', '{']
    content = []
    for char in valid_chars:
        if char not in 'HTB{}':
            content.append(char)
    flag.extend(content)
    flag.append('}')
    
    print("\nDecoded characters in sequence:", ''.join(result))
    print("Reconstructed flag attempt:", ''.join(flag))
    
    return ''.join(flag)

# Test with the scrambled message
scrambled = "1_n3}f3br9Ty{_6_rHnf01fg_14rlbtB60tuarun0c_tr1y3"
decoded = decode_to_htb_format(scrambled)
print("\nFinal decoded flag:", decoded)

# Also let's try to identify any patterns in the numbers
numbers = [c for c in scrambled if c.isdigit()]
print("\nNumbers found in sequence:", numbers)
