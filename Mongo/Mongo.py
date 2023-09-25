import pymongo
from dotenv import load_dotenv
import os

load_dotenv()

connection_string = os.getenv("MONGO_URL")

try:
    client = pymongo.MongoClient(connection_string)

    db = client.get_database('cse-3311-cluster')

    print("Connected to MongoDB Atlas")

    collection = db['Users']
    ## insert = collection.insert_one({"name": "Suhaib Hasan"})
    documents = collection.find_one({"name": "Suhaib Hasan"})

    print(documents)

    client.close()
    print("Disconnected from MongoDB Atlas")

except pymongo.errors.ConnectionFailure as e:
    print("Error connecting to MongoDB Atlas:", e)
