import bcrypt

if __name__ == "__main__":
    salt = bcrypt.gensalt()

    print(f"SALT {salt}")

    saltString = b"$2b$12$uUDPHNTgwyqTE/cFJid5LO"

    print(saltString.decode("utf-8"))
    password = b"omgMPC"

    print(f"password!! {password}")

    hashed = bcrypt.hashpw(password, saltString)

    print(hashed.decode("utf-8"))