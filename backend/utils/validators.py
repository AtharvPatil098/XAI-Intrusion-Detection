def validate_input(data):
    required = ["packets", "bytes", "duration", "port"]

    for key in required:
        if key not in data:
            return False

    return True