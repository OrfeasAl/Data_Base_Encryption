# 1. Παίρνουμε έναν "υπολογιστή" που έχει ήδη εγκατεστημένη την Python 3
FROM python:3.11-slim

# Απενεργοποίηση buffering ώστε τα logs να εμφανίζονται άμεσα
ENV PYTHONUNBUFFERED=1

# 2. Φτιάχνουμε έναν φάκελο /app μέσα στο κουτί και μπαίνουμε εκεί
WORKDIR /app

# 3. Αντιγράφουμε το αρχείο με τα ψώνια (requirements) και τα κάνουμε install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Αντιγράφουμε ΟΛΑ τα αρχεία του φακέλου μας μέσα στο κουτί
COPY . .

# 5. Λέμε στο Docker να αφήσει ανοιχτή την πόρτα 5555 (αν έχεις άλλη, άλλαξέ το)
EXPOSE 5000

# 6. Η εντολή που θα τρέξει όταν πατήσουμε το "On" στο κουτί
CMD ["python", "-u", "server.py"]