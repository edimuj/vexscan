# Dangerous: executes arbitrary code
user_input = input("Enter code: ")
exec(user_input)

# Also dangerous
eval(user_input)

# compile + exec
code = compile(user_input, '<string>', 'exec')
exec(code)

# __import__ abuse
module = __import__(user_controlled_name)
