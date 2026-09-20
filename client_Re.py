import socket
import json
import ssl
import time
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from faker import Faker


def generate_rsa_keys(username):
    private_key_file = f"{username}_private.pem"
    public_key_file = f"{username}_public.pem"

    if os.path.exists(private_key_file) and os.path.exists(public_key_file):
        print(f"[CLIENT] Βρεθηκαν τοπικα τα κλειδαι RSA για τον χρηστη  {username}")

        with open(private_key_file, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password = None
            )

            with open(public_key_file, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read()
                )
            return private_key, public_key

    else:
        print(f"[CLIENT] Δημιουργεια κλειδιων RSA για τον χρηστη  {username}")

        private_key = rsa.generate_private_key(
            public_exponent = 65537,
            key_size = 2048,
        )

        public_key = private_key.public_key()

        with open(private_key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(public_key_file, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        print(f"[CLIENT] Τα κλειδιά αποθηκεύτηκαν επιτυχώς!")
        return private_key, public_key

def setup_and_encrypt_database(public_key):
    fake = Faker()
    encrypted_rows = {"users": [], "accounts": []}

    print("\n==================================================")
    print("ΑΡΧΙΚΑ ΔΕΔΟΜΕΝΑ (ΠΡΙΝ ΤΗΝ ΚΡΥΠΤΟΓΡΑΦΗΣΗ)")
    print("==================================================")

    key = Fernet.generate_key()
    cipher = Fernet(key)

    wrapped_key = public_key.encrypt(key,padding.OAEP(
                                         mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                         algorithm=hashes.SHA256(),
                                         label=None))

    try:
        with open("admin_public.pem", "rb") as f:
            admin_public_key = serialization.load_pem_public_key(f.read())

        admin_wrapped = admin_public_key.encrypt(key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        json_admin_key = base64.b64encode(admin_wrapped).decode('utf-8')
    except FileNotFoundError:
        # Αν δεν υπάρχει το κλειδί του Admin, None για να μη σκάσει
        json_admin_key = "None"

    # γεμισμα των πινακων με πληροφοριες και κρυπτογραφηση
    for i in range(1, 4):
        raw_name = fake.name()
        raw_balance = str(fake.random_int(1000, 9000)) + " EUR"
        print(f"  User {i}: {raw_name} | {raw_balance}")

        balance_value = int(raw_balance.split()[0])
        split_num = balance_value // 1000

        enc_name = cipher.encrypt(raw_name.encode()).decode()
        enc_balance = cipher.encrypt(raw_balance.encode()).decode()

        encrypted_rows["users"].append([enc_name])
        encrypted_rows["accounts"].append([i, enc_balance, split_num])

    json_accepted_key = base64.b64encode(wrapped_key).decode('utf-8')

    # Προσθέτουμε και τα δυο κλειδιά στο πακέτο που φεύγει για τον Server!
    payload_dict = {
        'database_data': encrypted_rows,
        'wrapped_key': json_accepted_key,
        'admin_wrapped_key': json_admin_key
    }
    return payload_dict, cipher, key

def menu_options(client_socket, current_cipher, private_key, public_key, current_username, decrypted_fernet_key):
   while True:
        menu = client_socket.recv(4096).decode()
        print(f"\n{menu}")
        answer = input("Your Choice: ")
        client_socket.send(answer.encode())

        if answer == "3":
            close_msg = client_socket.recv(1024).decode()
            print(close_msg)
            return

        if answer in ("1", "2"):
            while True:
                # Διαβάζουμε το πρώτο κομμάτι
                response = client_socket.recv(4096).decode()

                # Αν ξεκινάει με '{', σημαίνει ότι άρχισε να έρχεται το JSON με τα δεδομένα
                if response.startswith("{"):
                    # Αν το πακέτο είναι τεράστιο διαβάζουμε μέχρι να βρούμε το \n που βάλαμε στον Server
                    while "\n" not in response:
                        response += client_socket.recv(4096).decode()
                    break

                # Αν δεν είναι JSON,είναι ερώτηση του Server
                user_input = input(response.strip())
                if user_input == "":
                    client_socket.send("\n".encode())
                else:
                    client_socket.send(user_input.encode())

            payload = json.loads(response.strip())

            if "error" in payload:
                print(f"\n  ❌ Σφάλμα από Server: {payload['error']}")
                continue

            # παιρνουμε τα κλειδια των users
            keys_dict = payload.get("keys", {})
            ciphers_keys = {}
            # αποκρυπτογραφηση των κλειδιων για τον χρηστη που το ζηταει
            for owner_name, wrapped_key_b64 in keys_dict.items():
                encrypted_fernet_key = base64.b64decode(wrapped_key_b64)
                try:
                    decrypted_user_key = private_key.decrypt(
                        encrypted_fernet_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    # φορτωση των κλειδιων σε λιστα και στο fernet για αποκρυπρογραφηση
                    ciphers_keys[owner_name] = Fernet(decrypted_user_key)
                except Exception as e:
                    print(f"\n  ❌ Αποτυχία ξεκλειδώματος κλειδιού για χρήστη '{owner_name}': {e}")

            results = payload.get("data", []) # διαβασμα των δεδομενων

            print(f"\n[CLIENT] Ελήφθησαν {len(results)} εγγραφές από τον Server.")
            print("=================================================================")
            for row in results:
                user_id = row[0]
                enc_name = row[1]
                enc_balance = row[2]
                row_owner = row[3]

                # Διαλέγουμε το σωστό κλειδί που χρειαζεται
                target_cipher = ciphers_keys.get(row_owner)

                if not target_cipher:
                    print(f"  ❌ Λείπει το κλειδί για τον χρήστη '{row_owner}' (ID: {user_id})")
                    continue

                try:
                    dec_name = target_cipher.decrypt(enc_name.encode()).decode()
                    dec_balance = target_cipher.decrypt(enc_balance.encode()).decode()

                    print(f"  ✅ ID: {user_id} | Ιδιοκτήτης: {row_owner} | Όνομα: {dec_name} | Υπόλοιπο: {dec_balance}")
                except InvalidToken:
                    print(f"  ❌ Αποτυχία αποκρυπτογράφησης για ID: {user_id} (Ιδιοκτήτης: {row_owner})")
                except Exception as e:
                    print(f"  ❌ Άγνωστο σφάλμα (ID {user_id}): {e}")

            print("=================================================================")

        if answer == "4":
            target = input("\nΠοιou χρηστη τα δεδομενα χρειαζεσαι: ")

            # μετατροπη του public_key σε μπορφη string
            public_key_toSend = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            # το αιτημα που λαμβανει ο παραληπτης και θα κληθει να αρνηθει η οχι
            request_payload = {
                "action": "request_access",
                "target_user": target.strip(),
                "requester": current_username,
                "requester_public_key": public_key_toSend,
                "timestamp": int(time.time()),   # timestamp validation για αποφυγη reply attacks
            }

            client_socket.send((json.dumps(request_payload) + "\n").encode())            # επιβεβαιωση οτι ο σερβερ εστειλε το αιτημα
            server_reply = client_socket.recv(4096).decode()
            print(f"\n[CLIENT] Απάντηση Server: {server_reply}")
            print("==================================================")

        if answer == "5":
            response = client_socket.recv(4096).decode().strip()

            try:
                mail_data = json.loads(response)
                # Αν το συρτάρι είναι άδειο
                if mail_data.get("status") == "empty":
                    print("\n[INBOX] Δεν έχεις νέα αιτήματα.")

                elif mail_data.get("status") == "has_mail":
                    msg = mail_data["message"]
                    requester = msg["requester"]

                    print(f"\n[INBOX] 📬 ΝΕΟ ΑΙΤΗΜΑ: Ο χρήστης '{requester}' ζητά πρόσβαση στα δεδομένα σου!")
                    decision = input(f"Επιτρέπεις την πρόσβαση; (y/n): ").strip().lower()

                    if decision == 'y':
                        # 1. Φορτώνουμε το Public Key του αιτούντα από το String
                        requester_pub_key = serialization.load_pem_public_key(
                            msg["requester_public_key"].encode())

                        # 2. Κλειδώνουμε το Fernet κλειδί με το Public Key του αιτουντος
                        encrypted_fernet = requester_pub_key.encrypt(
                            decrypted_fernet_key,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )

                        reply_payload = {
                            "action": "access_reply",
                            "decision": "approved",
                            "to_user": requester,
                            "encrypted_key": base64.b64encode(encrypted_fernet).decode('utf-8')
                        }

                    else:
                        reply_payload = {
                            "action": "access_reply",
                            "decision": "denied",
                            "to_user": requester
                        }

                    client_socket.send((json.dumps(reply_payload) + "\n").encode())
                    server_ack = client_socket.recv(4096).decode()

            except json.JSONDecodeError:
                print("[CLIENT ERROR] Σφάλμα στην ανάγνωση του μηνύματος από τον Server.")

def run_client():
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations("server.public_key")
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False ## Απενεργοποίηση ελέγχου ονόματος επειδή τρέχουμε τοπικά localhost ειναι Self-Signed Πιστοποιητικο
        context.verify_mode = ssl.CERT_REQUIRED
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket = context.wrap_socket(client_socket)
        client_socket.connect(('localhost', 5000))
    except ConnectionRefusedError:
        print("ΣΦΑΛΜΑ: Ο Server δεν απαντά.")
        return

    current_username = "" # μεταβλητη που κραταει το ονομα του χρηστη που συνδεεται εκεινη την στιγμη

    while True:
        server_msg = client_socket.recv(1024).decode()
        if not server_msg:
            break

        if "SUCCESS" in server_msg:
            print("\n" + "=" * 50)
            print("[CLIENT] ✔️ Επιτυχής σύνδεση και αυθεντικοποίηση!")
            print("=" * 50)
            private_key, public_key = generate_rsa_keys(current_username)
            client_socket.send("READY".encode())
            break
        elif "Closing" in server_msg:
            print(f"\n[CLIENT ERROR] ❌ {server_msg}")
            client_socket.close()
            return

        print(f"Server {server_msg}")
        answer = input(" ")

        if "Username" in server_msg:  # κραταει το username που εδωσε ο χρηστης
            current_username = answer.strip()

        client_socket.send(answer.encode())

    # απαντηση απο τον σερβερ αν υπαρχει ηδη στην Βαση
    response = client_socket.recv(4096).decode()
    retrieve_key = json.loads(response)

        # Ελέγχουμε τι μας απάντησε
    if retrieve_key["action"] == "has_key":
        print("[CLIENT] Βρέθηκε παλιό κλειδί στον Server! Προετοιμασία...")

        # Διαβάζουμε το Base64 string και το ξανακάνουμε bytes
        encrypted_fernet_key_b64 = retrieve_key["key"]
        encrypted_fernet_key = base64.b64decode(encrypted_fernet_key_b64)

        # Αποκρυπτογραφούμε το συμμετρικο κλειδί
        decrypted_fernet_key = private_key.decrypt(
            encrypted_fernet_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        current_cipher = Fernet(decrypted_fernet_key)
        print("[CLIENT] ✔️ Το κλειδί ξεκλειδώθηκε επιτυχώς!")

    else:
        print("[CLIENT] Δεν βρέθηκε κλειδί. Εκκίνηση αρχικού Setup...")
        setup_data, current_cipher, decrypted_fernet_key = setup_and_encrypt_database(public_key)
        setup_payload = json.dumps({"action": "setup", "data": setup_data})

        client_socket.sendall((setup_payload + "\n").encode())
        print("\n[CLIENT] 🔄 Αποστολή κρυπτογραφημένου πακέτου δεδομένων...\n")

        setup_response = client_socket.recv(1024).decode()
        if setup_response != "SETUP_OK":
            print(f"[CLIENT ERROR] Αποτυχία setup: {setup_response}")
            client_socket.close()
            return

        print("[CLIENT] ✔️ Ο Server αποθήκευσε τη βάση επιτυχώς!\n")

    menu_options(client_socket, current_cipher, private_key, public_key, current_username,decrypted_fernet_key)

    time.sleep(2)
    print("\n[CLIENT] Κλείσιμο εφαρμογής...")
    client_socket.close()

if __name__ == "__main__":
    run_client()