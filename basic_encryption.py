import sqlite3
from cryptography.fernet import Fernet
from faker import Faker

KEY = Fernet.generate_key()
cipher = Fernet(KEY)
fake = Faker()

conn = sqlite3.connect(':memory:')
cursor = conn.cursor()

cursor.execute('''
               CREATE TABLE Customers
               (
                   id             INTEGER PRIMARY KEY,
                   encrypted_name BLOB
               )
               ''')

cursor.execute('''
               CREATE TABLE Orders
               (
                   id               INTEGER PRIMARY KEY,
                   customer_id      INTEGER,
                   encrypted_amount BLOB,
                   FOREIGN KEY (customer_id) REFERENCES Customers (id)
               )
               ''')

print("--- Γέμισμα Βάσης ---")
for i in range(1, 4):
    raw_name = fake.name()
    raw_amount = str(fake.random_int(100, 1000)) + " EUR"

    enc_name = cipher.encrypt(raw_name.encode())
    enc_amount = cipher.encrypt(raw_amount.encode())

    cursor.execute("INSERT INTO Customers (id, encrypted_name) VALUES (?, ?)", (i, enc_name))
    cursor.execute("INSERT INTO Orders (id, customer_id, encrypted_amount) VALUES (?, ?, ?)", (i, i, enc_amount))

    print(f"Αποθηκεύτηκε κρυπτογραφημένα ο πελάτης #{i}")

conn.commit()
print("\n")

print("--- Ανάκτηση και Αποκρυπτογράφηση ---")

query = '''
        SELECT Customers.id, Customers.encrypted_name, Orders.encrypted_amount
        FROM Customers
                 JOIN Orders ON Customers.id = Orders.customer_id \
        '''
cursor.execute(query)
results = cursor.fetchall()

for row in results:
    customer_id = row[0]

    decrypted_name = cipher.decrypt(row[1]).decode()
    decrypted_amount = cipher.decrypt(row[2]).decode()

    print(f"Πελάτης ID: {customer_id} | Όνομα: {decrypted_name} | Παραγγελία: {decrypted_amount}")

conn.close()