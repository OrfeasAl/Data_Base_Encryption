import sqlite3
import socket
import json
import bcrypt
import ssl
import threading
import time

MAILBOXES = {}
mailbox_lock = threading.Lock()

def init_auth_database():
    db = sqlite3.connect('secure_server.db')
    cursor = db.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS SystemUsers
                      (
                          username TEXT PRIMARY KEY,
                          password_hash TEXT NOT NULL,
                          role TEXT NOT NULL
                      )''')
    #αν το count(*) ειναι 0 σημαινει οτι πρωτη φορα τρεχει ο σερβερ, χωρις χρηστες
    cursor.execute("SELECT COUNT(*) FROM SystemUsers")
    if cursor.fetchone()[0] == 0:
        print("\n[SERVER] Δημιουργία χρηστών στη Βάση Δεδομένων...")

        # Username: admin | Password: admin123
        admin_pass = "admin123"
        # bcrypt για να προσθεση αλατι πριν το hash για την αποθυκευση των κωδικων.
        admin_hash = bcrypt.hashpw(admin_pass.encode(), bcrypt.gensalt()).decode()
        cursor.execute("INSERT INTO SystemUsers VALUES (?, ?, ?)", ("admin", admin_hash, "admin"))
                                                    # Parameterized Queries για ασφαλεια απο sql injeciton
        for i in range(1, 6):
            username = f"user{i}"
            password = f"user1{i}"
            user_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            cursor.execute("INSERT INTO SystemUsers VALUES (?, ?, ?)", (username, user_hash, "user"))

        db.commit()
        print("[SERVER] ✅ Προστέθηκαν επιτυχώς 5 Χρήστες!\n")

    db.close()

def fetch_key(username):
    db = sqlite3.connect('secure_server.db')
    cursor = db.cursor()
    # αποθυκευση των κρυπτογραφημενων  κλειδιων καθε χρηστη
    cursor.execute('''CREATE TABLE IF NOT EXISTS CLIENT_KEYS(   
                          key_user TEXT PRIMARY KEY,
                          wrapped_key TEXT,
                          admin_wrapped_key TEXT
                      )''')

    query = ''' SELECT wrapped_key 
                FROM CLIENT_KEYS 
                WHERE key_user = ? '''
    cursor.execute(query, (username,)) # περιμενει το ονομα χρηστη ως παραμετρο
    row = cursor.fetchone()
    db.close()

    if row is not None:
        return row[0]
    else:
        return None

def fetch_admin_key(username):
    db = sqlite3.connect('secure_server.db')
    cursor = db.cursor()
    # ο admin παιρνει το κλειδι του user που ζηταει για να το αποκρυπτογραφισει
    query = ''' SELECT admin_wrapped_key                   
                FROM CLIENT_KEYS
                WHERE key_user = ? '''
    cursor.execute(query, (username,))
    row = cursor.fetchone()
    db.close()

    if row is not None and row[0] != "None":  # row[0] != "None" σημαινει οτι ο χρηστης βρηκε το δημοσιο κλειδ του admin
        return row[0]                         # αν δε το ειχε βρει στελνει στην βαση το "None",o περιορισμος αποτρεπει
    else:                                     # τον admin αντι του κλειδιου να παρει την λεξη None και σκασει ο κωδικας
        return None

def fetch_all_admin_keys():
    db = sqlite3.connect('secure_server.db')
    cursor = db.cursor()

    cursor.execute("SELECT key_user, admin_wrapped_key FROM CLIENT_KEYS")
    rows = cursor.fetchall()
    db.close()
    # οταν ο admin ζηταει να δει τα δεδομενα Ολων το χρηστων που εχουν κλειδι
    # Επιστρέφει λεξικό, αποκλείοντας όσους έχουν "None"
    return {row[0]: row[1] for row in rows if row[1] != "None"}

def handle_setup(data, key_username):
    db = sqlite3.connect('secure_server.db') #sqlite βαση
    cursor = db.cursor() #αντικειμενο για να εκτελει sql εντολες

    #πινακας που κραταει τα κρυπτογραφημενα κλειδια οταν συνδεεται την πρωτη καινουργιος χρηστης
    cursor.execute('''CREATE TABLE IF NOT EXISTS CLIENT_KEYS(
                        key_user TEXT PRIMARY KEY,
                        wrapped_key TEXT,
                        admin_wrapped_key TEXT
                   )''')

        # δημιουργια πινακων
    cursor.execute('CREATE TABLE IF NOT EXISTS Users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, owner TEXT)')
    cursor.execute('''CREATE TABLE IF NOT EXISTS Accounts (
                        id      INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        balance TEXT,
                        split   INTEGER,
                        FOREIGN KEY (user_id) REFERENCES Users(id)
        )''')
    # αρχιζει να κραταει τα δεδομενα που εστειλε ο χρηστης
    db_data = data['database_data']
    client_wrapped_key = data['wrapped_key']
    admin_wrapped_key = data.get('admin_wrapped_key', "None")
    cursor.execute("INSERT OR REPLACE INTO CLIENT_KEYS VALUES(?, ?, ?)", (key_username, client_wrapped_key, admin_wrapped_key))

    if "users" not in db_data or "accounts" not in db_data:
        return

    # διαβασμα των πακετων που εστειλε ο client
    users_list = db_data["users"]
    accounts_list = db_data["accounts"]

    if len(users_list) != len(accounts_list):
        return

    # Εισαγωγή Δεδομένων με lastrowid
    for i in range(len(users_list)):
        cursor.execute("INSERT INTO Users (name, owner) VALUES (?,?)", (users_list[i][0], key_username))
        new_user_id = cursor.lastrowid # γνωριζει πιο ηταν το τελευταιο νουμερο ID που εδωσε

        account_row = accounts_list[i]
        cursor.execute("INSERT INTO Accounts (user_id, balance, split) VALUES (?, ?, ?)",
                       (new_user_id, account_row[1], account_row[2]))

    db.commit()

    print("\n=================================================================")
    print(f"[SERVER] Έγινε προσθήκη εγγραφών από τον χρήστη: {key_username}")
    print("[SERVER] Προβολή κρυπτογραφημένων δεδομένων:\n")

    for i in range(len(users_list)):
        enc_name = users_list[i][0]
        enc_balance = accounts_list[i][1]

        print(f" 🔒 Εγγραφή {i + 1}:")
        print(f"    Name    -> {enc_name[:45]}...")
        print(f"    Balance -> {enc_balance[:45]}...")
        print(" - - - - - - - - - - - - - - - - - - - - - - - - -")

    print("=================================================================\n")

    db.close()

def handle_query(sql, params=()):
    db = sqlite3.connect('secure_server.db')
    cursor = db.cursor()
    try:
        cursor.execute(sql, params) # εκτελεση της sql
        results = cursor.fetchall() #  συλλογη των αποτελεσματων που πηρε
        return results # επιστρεψει τα αποτελεσματα στη συναρτηση που τα ζητα
    except Exception as e:
        print(f"[SERVER ERROR] {e}\n")
        return {
            "status": "error",
            "message": str(e)
        }
    finally:
        db.close()

def client_menu(conn, current_user, role):
    while True:
        menu = ("\nChoose an action from the menu:\n"
                "1: Read all information for all the users\n"
                "2: Read information for users with specific split number\n"
                "3: No action - Close connection\n"
                "4: Ask for info from other users\n"
                "5: See Mailbox\n"
                )

        # αποστολη του μενου και αναμονη για την επιλογη
        conn.send(menu.encode())
        choice = conn.recv(1024).decode().strip()

        # Αν ο Client αποσυνδέθηκε ή έκλεισε τη ροή
        if not choice:
            print(f"[SERVER LOG] 👤 Χρήστης: {current_user} | 🚪 Αποσυνδέθηκε.")
            return

        action_names = {
            "1": "Ανάγνωση όλων των επιτρεπτών δεδομένων",
            "2": "Ανάγνωση με βάση το Split Number",
            "3": "Αποσύνδεση",
            "4": "Αίτημα πρόσβασης σε άλλο χρήστη",
            "5": "Έλεγχος Mailbox"
        }

        # Τυπώνει ποιος έκανε τι χρησιμοποιοντας το username από τα ορίσματα της συνάρτησης
        action_desc = action_names.get(choice, f"Άγνωστη εντολή: {choice}")
        print(f"[SERVER LOG] 👤 Χρήστης: {current_user} | 🎯 Ενέργεια: {action_desc}")

        if choice == "1":
            # Ρωτάμε τον χρήστη τίνος τα δεδομένα θέλει
            if role == "admin":
                conn.send("Admin role - Enter username to read from or 'all' for everyone: ".encode())
            else:
                conn.send("Enter username to read from or press Enter for your own: ".encode())

            target_user = conn.recv(1024).decode().strip()

            # Αν πατήσει απλά Enter, φέρνουμε τα δικά του
            if target_user == "":
                target_user = current_user

            keys_dict = {}  # το πακέτο με τα κλειδιά που θα στείλθουν

            if target_user == "all" and role == "admin":
                keys_dict = fetch_all_admin_keys()  # Παίρνει όλα τα κλειδιά για τον Admin
                sql = '''SELECT Users.id, Users.name, Accounts.balance, Users.owner
                         FROM Users JOIN Accounts ON Users.id = Accounts.user_id'''
                results = handle_query(sql)

            else:
                if role == "admin":
                    target_key = fetch_admin_key(target_user)
                    if not target_key:  # αν ο χρηστης δεν υπαρχει τοτε δεν υπαρχει και το κλειδι του
                        conn.send((json.dumps({"error": f"No admin key found from {target_user}"}) + "\n").encode())
                        continue
                    keys_dict[target_user] = target_key

                else:
                    if target_user == current_user:
                        target_key = fetch_key(target_user)
                        if not target_key:
                            conn.send((json.dumps({"error": f"No key found from {target_user}"}) + "\n").encode())
                            continue
                        keys_dict[target_user] = target_key
                    else:
                        granted_key = None
                        if current_user in MAILBOXES:
                            for msg in MAILBOXES[current_user]:
                                if msg.get("action") == "access_granted" and msg.get("from_user") == target_user:
                                    granted_key = msg.get("encrypted_key")
                                    MAILBOXES[current_user].remove(msg)  # κανει το κλειδι να ειναι μιας χρησης
                                    break

                        if granted_key:
                            keys_dict[target_user] = granted_key
                        else:
                            conn.send((json.dumps({"error": f"Access Denied: You do not have permission to read {target_user}'s data."}) + "\n").encode())
                            continue

                # Αν φτάσαμε εδώ, τραβάμε τα δεδομένα του συγκεκριμένου χρήστη
                sql = '''SELECT Users.id, Users.name, Accounts.balance, Users.owner
                         FROM Users JOIN Accounts ON Users.id = Accounts.user_id
                         WHERE Users.owner = ?'''
                results = handle_query(sql, (target_user,))

            # Στέλνουμε το τελικό πακέτο
            payload = {"keys": keys_dict, "data": results}
            conn.send((json.dumps(payload) + "\n").encode())

        elif choice == "2":
            if role == "admin":
                conn.send("Admin role - Enter username to read from or 'all' for everyone: ".encode())
            else:
                conn.send("Enter username to read from or press Enter for your own: ".encode())

            target_user = conn.recv(1024).decode().strip()

            if target_user == "":
                target_user = current_user

            keys_dict = {}
            conn.send("Please give the split number (1-9): ".encode())
            number = conn.recv(1024).decode().strip()

            try:
                number = int(number)
            except ValueError:
                conn.send((json.dumps({"error": "Invalid Number"}) + "\n").encode())
                continue

            if target_user == "all" and role == "admin":
                keys_dict = fetch_all_admin_keys()

                sql = '''SELECT Users.id, Users.name, Accounts.balance, Users.owner
                         FROM Users
                         JOIN Accounts ON Users.id = Accounts.user_id
                         WHERE Accounts.split = ?
                      '''

                results = handle_query(sql, (number,))
            else:
                if role == "admin":
                    target_key = fetch_admin_key(target_user)

                    if not target_key:
                        conn.send((json.dumps({"error": f"No admin key found for {target_user}"}) + "\n").encode())
                        continue
                    keys_dict[target_user] = target_key

                else:
                    if target_user == current_user:
                        target_key = fetch_key(target_user)
                        if not target_key:
                            conn.send((json.dumps({"error": f"No key found for {target_user}"}) + "\n").encode())
                            continue
                        keys_dict[target_user] = target_key

                    else:
                        granted_key = None
                        if current_user in MAILBOXES:
                            for msg in MAILBOXES[current_user]:
                                if msg.get("action") == "access_granted" and msg.get("from_user") == target_user:
                                    granted_key = msg.get("encrypted_key")
                                    MAILBOXES[current_user].remove(msg)  # Μιας χρήσης!
                                    break

                        if granted_key:
                            keys_dict[target_user] = granted_key
                        else:
                            conn.send((json.dumps({"error": f"Access Denied: You do not have permission to read user's {target_user} data."}) + "\n").encode())
                            continue

                sql = '''
                      SELECT Users.id, Users.name, Accounts.balance, Users.owner
                         FROM Users
                         JOIN Accounts ON Users.id = Accounts.user_id
                         WHERE Accounts.split = ? AND Users.owner = ?
                      '''

                results = handle_query(sql, (number, target_user))

            payload = {"keys": keys_dict, "data": results}
            conn.send((json.dumps(payload) + "\n").encode())

        elif choice == "3":
            conn.send("\nClosing connection...".encode())
            return

        elif choice == "4":
            json_data = conn.recv(4096).decode().strip()

            try:
                payload = json.loads(json_data)
                if isinstance(payload, dict) and payload.get("action") == "request_access":
                    # ελεγχος του timestamp για την αποφυγη απο replay attack
                    if "timestamp" not in payload:
                        conn.send("[SECURITY ALERT] Missing timestamp - Replay Attack.\n".encode())
                        continue
                    if abs(time.time() - payload["timestamp"]) > 300:
                        print("Acces denied")
                        conn.send("Error: Access denied from {payload.get('target_user')}.\n".encode())
                        continue

                    target = payload["target_user"]

                    db = sqlite3.connect('secure_server.db')
                    cursor = db.cursor()
                    cursor.execute("SELECT username FROM SystemUsers WHERE username = ?", (target,))
                    target_record = cursor.fetchone()
                    db.close()

                    if target_record:
                        with mailbox_lock:# Ελέγχουμε αν η βάση μας απάντησε ότι υπάρχει ο χρήστης
                            if target not in MAILBOXES:
                                MAILBOXES[target] = []  # Του φτιάχνει το συρτάρι αν λείπει

                            MAILBOXES[target].append(payload)
                            conn.send(f"Success: Request sent to {target}'s mailbox!".encode())
                    else:
                        conn.send(f"Error: User {target} not found in the system.".encode())
            except json.JSONDecodeError:
                conn.send("Error: Invalid request format.".encode())
        elif choice == "5":
            request_msg = None
            with mailbox_lock:
                if current_user in MAILBOXES:
                    for i, msg in enumerate(MAILBOXES[current_user]):
                        if msg.get("action") == "request_access":
                            request_msg = MAILBOXES[current_user].pop(
                                i)  # αν βρεθει ενα μυνημα το διαγραφει στη συνεχεια
                            break

            # Αν βρήκαμε αίτημα, το στέλνουμε και περιμένουμε την απάντηση
            if request_msg:
                response_payload = {
                    "status": "has_mail",
                    "message": request_msg
                }
                conn.send((json.dumps(response_payload) + "\n").encode())

                # Ο Server περιμένει το (y/n)
                client_reply = conn.recv(4096).decode().strip()

                try:
                    reply_payload = json.loads(client_reply)
                    if reply_payload.get("action") == "access_reply":
                        original_requester = reply_payload["to_user"]

                        if reply_payload["decision"] == "approved":
                            approval_message = {
                                "action": "access_granted",
                                "from_user": current_user,
                                "encrypted_key": reply_payload["encrypted_key"]
                            }

                            with mailbox_lock:
                                if original_requester not in MAILBOXES:
                                    MAILBOXES[
                                        original_requester] = []  # φτιαχνει το 'συρατρι' τυο χρηστη αν δεν υπαρχει απο πριν
                                MAILBOXES[original_requester].append(
                                    approval_message)  # προσθετουμε την απαντηση στο συρταρι του

                            conn.send("Approval sent successfully!".encode())
                            time.sleep(0.5)

                        elif reply_payload["decision"] == "denied":
                            conn.send("Request denied. No key was sent.".encode())
                            time.sleep(0.5)

                except json.JSONDecodeError:
                    conn.send("Invalid response format.".encode())
                    time.sleep(0.5)

            else:
                # Αν δεν βρήκαμε κανένα αίτημα (στέλνουμε χωρίς Lock γιατί δεν αλλάζουμε το Mailbox)
                empty_payload = {"status": "empty"}
                conn.send((json.dumps(empty_payload) + "\n").encode())
                time.sleep(0.5)

def handle_client(conn):
    try:
        attempts = 0
        auth = False
        has_existing_key = False

        while attempts < 3:
            conn.send("\nEnter Username: ".encode())
            username = conn.recv(1024).decode().strip()

            conn.send("Enter Password: ".encode())
            password = conn.recv(1024).decode().strip()

            db = sqlite3.connect('secure_server.db')
            cursor = db.cursor()
            cursor.execute("SELECT password_hash, role FROM SystemUsers WHERE username = ?", (username,))
            user_info = cursor.fetchone()
            db.close()

            # Ελέγχουμε αν βρέθηκε ο χρήστης και αν ταιριάζει το password
            if user_info and bcrypt.checkpw(password.encode(), user_info[0].encode()):
                user_role = user_info[1]
                print(f"\n[SERVER] Auth success for: {username} Role: {user_role}\n")
                conn.send("AUTH_SUCCESS".encode())
                client_ack = conn.recv(1024).decode().strip()

                if client_ack != "READY":
                    print(f"[SERVER] Handshake failed for {username}")
                    conn.close()
                    return

                if username not in MAILBOXES:
                    MAILBOXES[username] = []

                user_key = fetch_key(username)
                has_existing_key = False

                if user_key is not None:
                    payload = json.dumps({"action": "has_key", "key": user_key})
                    conn.send(payload.encode())
                    has_existing_key = True
                else:
                    payload = json.dumps({"action": "no_key"})
                    conn.send(payload.encode())

                auth = True
                break
            else:
                attempts += 1
                print(f"\n[SERVER] Failed login ({attempts}/3)")
                if attempts < 3:
                    conn.send("Try again.".encode())
                else:
                    conn.send("\nClosing connection: Too many attempts.".encode())

        if not auth:
            conn.close()
            return

        if not has_existing_key:
            print("[SERVER DEBUG] Περιμένω το  πακέτο Setup...")
            raw = ""
            while True:
                chunk = conn.recv(4096).decode()
                print(f"[SERVER DEBUG] Έλαβα {len(chunk)} χαρακτήρες.")
                if not chunk:  # Αν κοπεί η σύνδεση ξαφνικά
                    break
                raw += chunk
                if "\n" in raw:
                    break

            raw = raw.strip()

            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                conn.send("Invalid setup format.".encode())
                conn.close()
                return

            if not isinstance(payload, dict) or payload.get("action") != "setup":
                conn.send("Invalid setup request.".encode())
                conn.close()
                return

            if "data" not in payload:
                conn.send("Missing setup data.".encode())
                conn.close()
                return

            handle_setup(payload["data"], username)
            conn.send("SETUP_OK".encode())

        client_menu(conn, username, user_role)  # καλει το μενου για να σταλθει στον client

    except (ssl.SSLEOFError, ConnectionResetError, BrokenPipeError):
        print(f"[SERVER] Ο Client αποσυνδέθηκε.")
    except Exception as e:
        print(f"[SERVER ERROR] {e}")

    finally:
        conn.close()

def start_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('server.public_key', 'server.private_key')
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket = context.wrap_socket(server_socket, server_side=True)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 5000))
    server_socket.listen(5)

    print("[SERVER] Αναμονή για σύνδεση στο port 5000...")

    while True:
        try:
            conn, addr = server_socket.accept()
            print(f"[SERVER] Συνδέθηκε ο Client: {addr}\n")
            thread = threading.Thread(target=handle_client, args=(conn,))
            thread.start()
        except (ssl.SSLError, ssl.SSLEOFError):
            print("[SERVER] Αποτυχημένο TLS handshake / απότομη αποσύνδεση πριν την ταυτοποίηση.")
        except Exception as e:
            print(f"[SERVER ERROR στο accept] {e}")


if __name__ == "__main__":
    init_auth_database()
    start_server()