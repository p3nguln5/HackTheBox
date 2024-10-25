from sympy import symbols, Eq, solve

# Define the variables
x, y, z = symbols('x y z')

# Read v1, v2, v3, and v4 from the file 'output.txt'
with open('output.txt', 'r') as file:
    # Extract the numeric values by splitting at '=' and stripping whitespace
    v1 = int(file.readline().split('=')[1].strip())
    v2 = int(file.readline().split('=')[1].strip())
    v3 = int(file.readline().split('=')[1].strip())
    v4 = int(file.readline().split('=')[1].strip())

# Define the system of equations
eq1 = Eq(x**3 + z**2 + y, v1)
eq2 = Eq(y**3 + x**2 + z, v2)
eq3 = Eq(z**3 + y**2 + x, v3)
eq4 = Eq(x + y + z, v4)

# Solve the system of equations
solution = solve((eq1, eq2, eq3, eq4), (x, y, z))

# Extract x, y, z from the solution
x_value, y_value, z_value = solution[0]

# Convert x, y, z values into a string of characters by using a modulo operation with 128 to map to ASCII printable characters
x_chr = chr(x_value % 128)  # Ensures it's in the printable ASCII range
y_chr = chr(y_value % 128)
z_chr = chr(z_value % 128)

# Format the result as HTB{...}
result = f"HTB{{{x_chr}{y_chr}{z_chr}}}"

# Print the result
print(result)
