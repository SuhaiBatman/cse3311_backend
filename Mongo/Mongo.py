import pymongo
from dotenv import load_dotenv
import os

load_dotenv()

connection_string = os.getenv("MONGO_URL") ##gets the MongoURL

try:
    client = pymongo.MongoClient(connection_string) ##Connect to the MongoDB

    db = client.get_database('cse-3311-cluster')

    print("Connected to MongoDB Atlas")

    ##test if connection works by adding an object and displaying it
    collection = db['Users'] ##find the collection
    ## insert = collection.insert_one({"name": "Suhaib Hasan"})
    documents = collection.find_one({"name": "Suhaib Hasan"}) ##retrive the document within the collection

    print(documents)

    client.close() ##disconnect from database
    print("Disconnected from MongoDB Atlas")

except pymongo.errors.ConnectionFailure as e: ##exception thrown if no connection was found
    print("Error connecting to MongoDB Atlas:", e)
